# Running CyberLabs locally

Everything is already set up on this machine. Two processes: a FastAPI backend
and a Vite dev server.

| What | URL |
| --- | --- |
| **Web UI** | <http://127.0.0.1:5173> |
| API docs (Swagger) | <http://127.0.0.1:8000/docs> |
| API health | <http://127.0.0.1:8000/api/stats> |

---

## The short version

```bash
cd ~/cyberlabs
./scripts/dev.sh start     # start both
./scripts/dev.sh status    # what's running
./scripts/dev.sh logs      # tail both logs
./scripts/dev.sh stop      # stop both
```

Then open <http://127.0.0.1:5173>.

## Opening it in VS Code

```bash
cd ~/cyberlabs
code .
```

VS Code is installed **user-local** at `~/opt/vscode` (no root needed, since
`sudo` requires a password here). `code` is on your `PATH` via
`~/.local/bin/code`.

Inside VS Code:

- **Run → Start Debugging (F5)** → pick **"Full stack: backend + frontend (F5)"**.
  It starts the Vite server, starts the backend under the debugger, and opens
  Chrome on the UI. Set breakpoints in `backend/app/` and they will hit.
- **Terminal → Run Task…** runs `Backend: FastAPI (uvicorn)` or
  `Frontend: Vite dev server` on their own (plain start, no debugger).

## Doing it by hand (two terminals)

```bash
# terminal 1 — backend
cd ~/cyberlabs/backend
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# terminal 2 — frontend
cd ~/cyberlabs/frontend
npm run dev
```

---

## First-time setup (already done, for reference)

```bash
# python env
cd ~/cyberlabs/backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# frontend
cd ~/cyberlabs/frontend
npm install

# config  — NOTE: .env belongs at the REPO ROOT, not in backend/
cd ~/cyberlabs
cp backend/.env.example .env
```

`backend/app/config.py` loads `.env` from `BASE_DIR`, which is the repo root.
Putting it in `backend/` silently does nothing.

## AI-generated labs

Leave `AI_API_KEY` empty and everything still works — only the "AI lab" button
is disabled. To enable it, put any OpenAI-compatible key in `~/cyberlabs/.env`:

```
AI_API_KEY=sk-...
AI_BASE_URL=https://api.openai.com/v1   # or DeepSeek / Groq / Ollama
AI_MODEL=gpt-4o-mini
```

---

## How a lab actually runs

1. You click **Launch lab** on a vulnerability.
2. The backend copies `labs/default/<slug>/` into `labs/generated/build/lab-N/`.
3. It injects a random flag, writes a Dockerfile, and `docker build`s it.
4. It runs the image in a container on the `cyberlabs-net` bridge network.
5. You attack it from the URL shown in the UI.

Containers are hard-walled:

- on an **`internal`** network, so **no internet egress** (verified — outbound
  connections fail from inside a lab)
- `cap_drop=ALL`, `no-new-privileges`, `read-only` rootfs, `/tmp` as a small
  tmpfs
- capped at 256 MB RAM / 0.5 CPU / 128 PIDs
- auto-destroyed after `LAB_TTL_MINUTES` (default 60), or via the destroy button

### Why the lab URL is a `172.x.x.x` address

Because the lab network is `internal`, Docker does **not** create
port-publishing NAT rules, so `-p 127.0.0.1:PORT:PORT` silently does nothing.
Labs are therefore reached on the container's bridge IP
(`http://172.18.0.2:8091`). The host can reach it fine and the lab still has
zero internet access — which is the property that matters. If you would rather
have `127.0.0.1` URLs, the network has to stop being `internal`, and you lose
egress isolation.

---

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `code: command not found` | `export PATH="$HOME/.local/bin:$PATH"` |
| Port 5173 or 8000 already in use | `./scripts/dev.sh stop`, then check `ss -ltn \| grep -E '5173\|8000'` |
| Frontend loads, API calls fail | Backend is not running. `./scripts/dev.sh status` |
| Lab stuck on `building` | First build pulls `python:3.11-slim`; can take a few minutes. Watch `./scripts/dev.sh logs` |
| Lab says `error`, read `error` field | Full message is in the lab detail page and `.run/backend.log` |
| Labs disappear when I edit backend code | Expected — `--reload` restarts the process, and startup calls `clean_stale_containers()`. Just launch a new lab |
| Docker errors | Check `docker ps`. The daemon must be running and you must be in the `docker` group |
| Reset all data | Stop the app, `rm -f data/cyberlabs.db`, start again (topics/vulns re-seed) |

Logs: `.run/backend.log` and `.run/frontend.log`. PID files in `.run/`.

## Layout

```
backend/            FastAPI + SQLAlchemy
  app/content/      ALL authored content (add topics + lessons here)
  app/seed.py       upserts content into the DB, keyed on slug
  app/services/     lab_factory, lab_runner, lab_generator
  .venv/            python env
frontend/           React + Vite
  src/pages/        Dashboard, TopicsPage, LessonPage, LabDetailPage, LabsPage
labs/default/       the vulnerable apps, one folder = one lab family
  auth_login/       :8091   enumeration + brute force
  auth_mfa/         :8092   second-factor bypasses
  auth_reset/       :8093   password-reset weaknesses
labs/generated/     build contexts + AI-generated labs
data/cyberlabs.db   SQLite
scripts/dev.sh      start/stop/restart/status/logs
scripts/verify.py   verification suite (see below)
```

## Current state

One topic, **Authentication**: 29 lessons (12 theory, 17 lab-backed), all
lab-backed lessons backed by a working lab family. `CONTINUE.md` has the full
catalogue, the variant table, the API surface and the known defects.

## Adding content

All content lives in `backend/app/content/`. Use `app.content.builder.lesson()`
— it fills in the defaults and fixes the page structure, so a lesson only states
what is different. The docstring at the top of `app/seed.py` documents every
field.

Seeding is an **upsert keyed on slug**, so adding lessons and restarting is
enough; ids stay stable and progress survives:

```bash
./scripts/dev.sh restart
```

If you add a lesson pointing at a new lab variant, register the family in
`lab_runner.DEFAULT_PORTS` and add the variant to the family app's `VARIANT`
dispatch. Then check your work:

```bash
backend/.venv/bin/python scripts/verify.py
```

That command fails if a lesson names a variant the app does not implement, if an
implemented variant has no lesson, if a required field is missing, or if the
`solution` walkthrough has leaked into the normal lesson payload.

## Verifying

```bash
cd ~/cyberlabs

backend/.venv/bin/python scripts/verify.py            # content + API (no Docker)
backend/.venv/bin/python scripts/verify.py --all      # + exploit every variant
```

`--all` builds and runs each lab, asserts the intended vulnerability is actually
exploitable, then destroys the lab. It takes several minutes. Exit code 0 means
everything passed.

| Symptom | Cause / fix |
| --- | --- |
| `code: command not found` | `export PATH="$HOME/.local/bin:$PATH"` |
| Port 5173 or 8000 already in use | `./scripts/dev.sh stop`, then `ss -ltn \| grep -E '5173\|8000'` |
| Frontend loads, API calls fail | Backend is not running. `./scripts/dev.sh status` |
| Lab stuck on `building` | First build pulls `python:3.11-slim`; can take a few minutes. Watch `./scripts/dev.sh logs` |
| Lab says `error`, read `error` field | Full message is in the lab detail page and `.run/backend.log` |
| "Lab limit reached (3 active)" | Stale lab rows. `curl -s http://127.0.0.1:8000/api/labs` and `DELETE /api/labs/<id>` each one |
| Labs disappear when I edit backend code | Expected — `--reload` restarts, and startup calls `clean_stale_containers()`. Launch a new lab |
| `no such column: <table>.<column>` | The DB predates a schema change. `./scripts/dev.sh stop && rm -f data/cyberlabs.db && ./scripts/dev.sh start` |
| Content edits do not appear | Seeding runs at startup. `./scripts/dev.sh restart` |
| Docker errors | Check `docker ps`. The daemon must be running and you must be in the `docker` group |
| Reset all data | Stop, `rm -f data/cyberlabs.db`, start (topics and lessons re-seed) |

Logs: `.run/backend.log` and `.run/frontend.log`. PID files in `.run/`.
