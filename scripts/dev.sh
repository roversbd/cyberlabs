#!/usr/bin/env bash
# CyberLabs local dev runner.
#
#   ./scripts/dev.sh start     start backend (:8000) + frontend (:5173)
#   ./scripts/dev.sh stop      stop both
#   ./scripts/dev.sh restart   stop + start
#   ./scripts/dev.sh status    show what is running
#   ./scripts/dev.sh logs      tail both logs
#
# Logs land in .run/backend.log and .run/frontend.log.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT/.run"
PY="$ROOT/backend/.venv/bin/python"
BACKEND_PID="$RUN_DIR/backend.pid"
FRONTEND_PID="$RUN_DIR/frontend.pid"
BACKEND_LOG="$RUN_DIR/backend.log"
FRONTEND_LOG="$RUN_DIR/frontend.log"

mkdir -p "$RUN_DIR"

if [ ! -x "$PY" ]; then
  echo "✗ python venv missing at $PY"
  echo "  create it with:  python3 -m venv backend/.venv"
  echo "  then install:    backend/.venv/bin/pip install -r backend/requirements.txt"
  exit 1
fi

# .env is read from the REPO ROOT by backend/app/config.py, not from backend/.
if [ ! -f "$ROOT/.env" ]; then
  echo "→ no .env found, creating one from backend/.env.example"
  cp "$ROOT/backend/.env.example" "$ROOT/.env"
fi

mkdir -p "$ROOT/data" "$ROOT/labs/generated"

alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }

read_pid() { [ -f "$1" ] && cat "$1" || echo ""; }

# pids listening on a TCP port, if any
port_pids() {
  ss -ltnp 2>/dev/null \
    | grep -E "127\.0\.0\.1:$1 |0\.0\.0\.0:$1 |\[::\]:$1 " \
    | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u
}

free_port() {
  local port="$1" pids
  pids="$(port_pids "$port")"
  [ -z "$pids" ] && return
  echo "→ port $port is held by a stale process (pid: $(echo "$pids" | tr '\n' ' ')) — freeing it"
  # shellcheck disable=SC2086
  kill -9 $pids 2>/dev/null
  sleep 1
}

start_backend() {
  local pid; pid="$(read_pid "$BACKEND_PID")"
  if alive "$pid"; then
    echo "• backend already running (pid $pid)"
    return
  fi
  free_port 8000
  cd "$ROOT/backend" || exit 1
  setsid nohup "$PY" -m uvicorn app.main:app \
    --host 127.0.0.1 --port 8000 --reload \
    > "$BACKEND_LOG" 2>&1 < /dev/null &
  echo $! > "$BACKEND_PID"
  disown 2>/dev/null

  printf '→ backend starting'
  for _ in $(seq 1 40); do
    if grep -q "Uvicorn running on" "$BACKEND_LOG" 2>/dev/null; then
      echo " ✓  http://127.0.0.1:8000"
      return
    fi
    if grep -qE "Error|Traceback" "$BACKEND_LOG" 2>/dev/null; then
      echo " ✗"
      tail -20 "$BACKEND_LOG"
      return 1
    fi
    printf '.'; sleep 0.5
  done
  echo " ✗ (timeout — see $BACKEND_LOG)"
  return 1
}

start_frontend() {
  local pid; pid="$(read_pid "$FRONTEND_PID")"
  if alive "$pid"; then
    echo "• frontend already running (pid $pid)"
    return
  fi
  if [ ! -d "$ROOT/frontend/node_modules" ]; then
    echo "→ installing frontend dependencies (first run, this takes a minute)"
    (cd "$ROOT/frontend" && npm install)
  fi
  free_port 5173
  cd "$ROOT/frontend" || exit 1
  setsid nohup npm run dev > "$FRONTEND_LOG" 2>&1 < /dev/null &
  echo $! > "$FRONTEND_PID"
  disown 2>/dev/null

  printf '→ frontend starting'
  for _ in $(seq 1 60); do
    if grep -q "Local:" "$FRONTEND_LOG" 2>/dev/null; then
      # Report the port Vite actually bound. It silently falls back to 5174+ if
      # 5173 is taken, so never assume 5173 here.
      local bound
      bound="$(grep -oE 'http://127\.0\.0\.1:[0-9]+' "$FRONTEND_LOG" | tail -1 | sed 's#.*:##')"
      FRONTEND_PORT="${bound:-5173}"
      if [ "$FRONTEND_PORT" != "5173" ]; then
        echo " ⚠ bound to :$FRONTEND_PORT, not 5173"
      else
        echo " ✓  http://127.0.0.1:5173"
      fi
      echo "$FRONTEND_PORT" > "$RUN_DIR/frontend.port"
      return
    fi
    printf '.'; sleep 0.5
  done
  echo " ✗ (timeout — see $FRONTEND_LOG)"
  return 1
}

stop_one() {
  local pidfile="$1" name="$2" port="$3"
  local pid; pid="$(read_pid "$pidfile")"
  if alive "$pid"; then
    pkill -TERM -P "$pid" 2>/dev/null
    kill -TERM "$pid" 2>/dev/null
    sleep 1
    kill -KILL "$pid" 2>/dev/null
    echo "• stopped $name (pid $pid)"
  else
    echo "• $name not running"
  fi
  # Catch orphans: a pid that outlived its parent (npm wrapper, vite child)
  # still holds the port and would push the next start onto a fallback port.
  free_port "$port"
  rm -f "$pidfile"
}

frontend_port() {
  local p
  p="$(port_pids 5173 | head -1)"
  if [ -n "$p" ]; then echo 5173; return; fi
  p="$(cat "$RUN_DIR/frontend.port" 2>/dev/null)"
  [ -n "$p" ] && echo "$p" || echo 5173
}

case "${1:-start}" in
  start)
    start_backend && start_frontend
    echo
    echo "  UI  →  http://127.0.0.1:${FRONTEND_PORT:-5173}"
    echo "  API →  http://127.0.0.1:8000/docs"
    echo
    echo "  open in VS Code:  code ."
    ;;
  stop)
    stop_one "$FRONTEND_PID" frontend 5173
    stop_one "$BACKEND_PID" backend 8000
    rm -f "$RUN_DIR/frontend.port"
    ;;
  restart)
    "$0" stop; sleep 1; "$0" start
    ;;
  status)
    bp="$(read_pid "$BACKEND_PID")"; fp="$(read_pid "$FRONTEND_PID")"
    fport="$(frontend_port)"
    alive "$bp" && echo "✓ backend  running (pid $bp)  http://127.0.0.1:8000" || echo "✗ backend  stopped"
    alive "$fp" && echo "✓ frontend running (pid $fp)  http://127.0.0.1:$fport" || echo "✗ frontend stopped"
    echo
    docker ps --filter 'label=cyberlabs.component=lab' --format '  lab: {{.Names}}  {{.Status}}' 2>/dev/null
    ;;
  logs)
    tail -n 40 -F "$BACKEND_LOG" "$FRONTEND_LOG"
    ;;
  *)
    echo "usage: $0 {start|stop|restart|status|logs}"; exit 2
    ;;
esac
