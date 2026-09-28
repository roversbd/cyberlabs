# CyberLabs

A hands-on platform for practising web security. Every lab-backed lesson ships
a **deliberately vulnerable web app** in a throwaway Docker container; you read
the lesson, attack the running app over HTTP, and retrieve a flag to prove it.

The differentiator is that the labs are **verified, not just written**. The test
suite asserts the intended weakness is actually present and exploitable in every
variant, so a lesson cannot drift into describing a bug the app no longer has.

```
1 topic (Authentication) · 29 lessons · 17 hands-on labs · 3 lab apps
FastAPI + SQLite backend · React/Vite frontend · Docker for every lab
```

---

## Quick start

```bash
# private repo — authenticate first, e.g. gh auth login, or use an SSH remote
git clone https://github.com/roversbd/cyberlabs.git
cd cyberlabs

# backend
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && cd ..

# frontend
cd frontend && npm install && cd ..

# config (see "Configuration" below — .env goes in the repo root)
cp backend/.env.example .env

./scripts/dev.sh start
```

`dev.sh start` creates `.env` from the template automatically if it is missing.

Then open **<http://127.0.0.1:5173>**.

| | |
| --- | --- |
| Web UI | <http://127.0.0.1:5173> |
| API docs (Swagger) | <http://127.0.0.1:8000/docs> |
| API health | <http://127.0.0.1:8000/api/stats> |

`dev.sh` also takes `status`, `logs`, `restart` and `stop`.

**Requirements:** Python 3.11+ (developed on 3.14), Node 18+, and Docker. The lab
apps are Python 3.11 images. The isolated Docker network is created automatically
on the first lab launch — nothing to set up by hand.

---

## Configuration

`.env` belongs in the **repository root** — `backend/app/config.py` loads it from
there. Putting it in `backend/` silently does nothing. The template is
[`backend/.env.example`](backend/.env.example) (note the path: the template lives
under `backend/`, the `.env` you create from it goes in the root):

```bash
cp backend/.env.example .env
```

Everything works with the template's defaults, which are also what the lab
sandbox docs describe: `CPU_NANO=500000000` (0.5 CPU), `MEM_LIMIT=256m`,
`PIDS_LIMIT=128`, `LAB_TTL_MINUTES=60`, `MAX_CONCURRENT_LABS=3`. Keep them.

The one value you might want to change is `AI_API_KEY` (any OpenAI-compatible
provider: OpenAI, DeepSeek, Groq, OpenRouter, or local Ollama), which enables the
experimental AI-generated lab button. It is blank in the template and is the one
setting that must never be committed — see [Security](#security).

---

## The labs

All three apps live in [`labs/default/`](labs/default/) and are small enough to
read in one sitting — which is the point, since the lesson and the app must tell
the same story.

| Family | Port | Lessons | Covers |
| --- | --- | --- | --- |
| `auth_login` | 8091 | 7 | username enumeration (4 variants: message, status, timing, lockout), password brute force (3: unthrottled, IP-block bypass, batch endpoint) |
| `auth_mfa` | 8092 | 5 | 2FA not enforced, broken verification, 6-digit code brute force, predictable trusted-device cookie, 4-digit backup-code brute force |
| `auth_reset` | 8093 | 5 | tokens not tied to their account, `X-Forwarded-Host` link poisoning, password-change brute force, predictable sequential tokens |

17 lab lessons are served by 16 unique variants: `reset_poisoning_mw` backs both
`auth-reset-poisoning-complete` and `auth-reset-poisoning-middleware`.

Each lesson is a single, isolated weakness. A variant that fixes one thing and
leaks another would teach the wrong lesson, so the variants are kept deliberately
narrow and the suite checks that they stay that way.

---

## Verifying the labs

```bash
backend/.venv/bin/python scripts/verify.py --all
```

**167 checks, ~2 minutes** (Docker required for the third section). The suite
runs in three independent sections:

| Section | Needs | What it proves |
| --- | --- | --- |
| `content` | nothing | static checks over the content modules, seed data and lab app sources |
| `api` | running backend | endpoint behaviour, and that the walkthrough is **never** in the normal lesson payload |
| `variants` | Docker | launches each lab, asserts the intended vulnerability is **actually present and exploitable**, retrieves the flag, destroys the lab |

Narrower runs: `--no-api` (skip the backend section), `--variant reset_predictable`
(one variant), `--variants` (list them).

The `variants` section is the interesting one. It does not check that a lab
*starts* — it replays the actual exploit. For example, `reset_predictable` must
show that a token which was never issued still resets the account, that a token
below the floor is rejected, that a non-integer token is rejected, and that the
recovered password really does open the flag page.

Three static invariants keep lessons from drifting away from the apps:

- every implemented lab variant must have a registered behavioural check;
- any lesson whose success condition promises the flag must have a check that
  proves the flag is reachable;
- every endpoint a lesson advertises must actually exist in its lab app.

---

## How a lab runs

1. You click **Launch lab** on a lesson.
2. The backend copies `labs/default/<slug>/` to `labs/generated/build/lab-N/`.
3. It injects a fresh flag, writes a Dockerfile, and builds the image.
4. It runs the container on the `cyberlabs-net` bridge network.
5. You attack it from the URL shown in the UI.

Lab containers are hard-walled:

- on an **`internal`** Docker network — **no internet egress**
- `cap_drop=ALL`, `no-new-privileges`, read-only rootfs, small `/tmp` tmpfs
- capped at 256 MB RAM, 0.5 CPU, 128 PIDs
- auto-destroyed after `LAB_TTL_MINUTES`, or with the destroy button

> **Labs are reached at a `172.x.x.x` address** (e.g. `http://172.18.0.2:8091`),
> not `127.0.0.1`. That is a consequence of the network being `internal`: Docker
> creates no port-publishing NAT rules, so `-p 127.0.0.1:PORT:PORT` would
> silently do nothing. The host reaches the lab fine and the lab still has zero
> internet access. Serving labs on `127.0.0.1` would require making the network
> non-internal, which costs the egress isolation.

---

## Layout

```
backend/app/
  content/            lesson content (auth_theory.py, auth_labs_*.py)
  services/
    lab_runner.py     docker lifecycle, DEFAULT_PORTS, sandbox limits
    lab_factory.py    copies a lab app, injects a flag, writes a Dockerfile
    lab_generator.py  experimental AI-generated labs (disabled by default)
  routers/            topics, labs, progress
  seed.py             wires lessons to lab variants
frontend/src/pages/   Dashboard, Topic, Lesson, Labs, LabDetail
labs/default/         the vulnerable apps, one folder per family
scripts/dev.sh        start/stop/restart/status/logs
scripts/verify.py     the 167-check verification suite
```

### Adding a lab

See [`labs/default/README.md`](labs/default/README.md): create the app, register
its port in `DEFAULT_PORTS`, point a lesson at it, then add a `v_<variant>`
check to `verify.py` and register it in `CHECKS`. `verify.py --all` gates the
work.

---

## Security

This repo contains **intentionally vulnerable applications**. They are teaching
material, sandboxed per-lab with no internet egress, resource caps and
`cap_drop=ALL`. Do not deploy any of them, and do not point them at anything
that matters.

Handled carefully:

- **No real secrets are committed.** `.env` is gitignored;
  [`backend/.env.example`](backend/.env.example) ships with an empty
  `AI_API_KEY`. Passwords in the lab apps (`carol-pw-9911` and friends) are
  fixtures, and the Flask `secret_key` is literally
  `northwind-lab-not-a-real-secret`.
- **The SQLite database is not committed.** `data/` holds learner progress and
  is recreated on start.
- **Solutions are withheld by construction.** Walkthrough text lives in the
  content modules but is never included in the normal lesson API payload, and
  `verify.py` asserts that on every run.
- **Not for production.** Single-user, no auth on the platform itself, no
  migrations.

If you fork this for anything beyond a local learning environment, the first
things to add are authentication on the platform and a way to keep real secrets
out of the tree.

---

## Further reading

- **[RUNNING.md](RUNNING.md)** — day-to-day operation: VS Code debugging, manual
  two-terminal startup, first-time setup, troubleshooting, authoring workflow.
- **[CONTINUE.md](CONTINUE.md)** — architecture, the flag-injection mechanism,
  lab lifecycle, content conventions, known defects, and what was fixed most
  recently.

## Status

Authentication is complete and verified: all 17 lab-backed lessons reachable,
solvable, flag retrievable, 167/167 checks passing. Twelve of the twenty-nine
lessons are theory-only. Known limitations (no frontend tests, no git history
before the initial commit, lab images accumulating on disk, labs keeping state
per submitted username rather than per session) are listed in
[CONTINUE.md](CONTINUE.md#10-known-defects-and-remaining-work).
