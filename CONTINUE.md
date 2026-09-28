# CyberLabs — continuation document

Written 2026-09-28 from a verified working state. Everything below was checked
by running it, not inferred. Last full suite run: **87 passed, 0 failed**
(`scripts/verify.py --all`).

---

## 1. What this is

A self-hosted training platform for hands-on web security labs. Content is a
tree of **topics**, each containing **lessons**. A lesson is either conceptual
(theory) or hands-on, in which case it is backed by a **lab**: a small
intentionally vulnerable app, built and run as a throwaway Docker container on
an isolated network, with a per-run random flag.

The learner's whole loop is: read lesson → launch lab → attack it → retrieve the
flag → mark complete.

## 2. Architecture

```
frontend/            React + Vite SPA (port 5173)
  src/api.js         fetch wrapper -> http://127.0.0.1:8000
  src/pages/         Dashboard, TopicsPage, LessonPage, LabDetailPage, LabsPage
backend/             FastAPI + SQLAlchemy (port 8000)
  app/main.py        app factory, CORS, /api/stats, startup seeding
  app/config.py      pydantic-settings; loads .env from the REPO ROOT
  app/models.py      Topic, Vulnerability, Lab, Progress
  app/seed.py        upserts TOPICS into the DB, keyed on slug
  app/content/       all authored content lives here (see §4)
  app/services/
    lab_factory.py   create_default_lab / create_ai_lab, copies build context
    lab_runner.py    docker build/run/teardown, TTL monitor, network
    lab_generator.py AI-generated lab source (unused so far)
labs/default/<family>/app.py    the vulnerable apps, one folder = one app
labs/generated/build/lab-N/     per-lab build context (regenerated each launch)
data/cyberlabs.db               SQLite
scripts/dev.sh                  start | stop | restart | status | logs
scripts/verify.py               the verification suite (see §7)
```

Data flow: content is **authored as Python dicts**, seeded into SQLite on every
startup, and served read-only to the SPA. The SPA never receives the
`solution` field (§3).

### Configuration

`backend/app/config.py` reads `.env` from `BASE_DIR` = **repo root**
(`~/cyberlabs/.env`), *not* from `backend/`. Putting it in `backend/` silently
does nothing. Key settings and defaults:

| Setting | Default | Meaning |
| --- | --- | --- |
| `LAB_TTL_MINUTES` | 60 | auto-destroy a lab after this long |
| `MAX_CONCURRENT_LABS` | 3 | enforced from DB rows with status queued/building/running |
| `MEM_LIMIT` / `CPU_NANO` / `PIDS_LIMIT` | 256m / 0.5 core / 128 | per-container caps |
| `NETWORK_NAME` | `cyberlabs-net` | created `internal=True` |
| `AI_API_KEY` / `AI_BASE_URL` / `AI_MODEL` | empty / OpenAI / gpt-4o-mini | empty disables AI labs |

## 3. Seed model (important)

`seed_topics()` is an **upsert keyed on slug**, not a create-if-empty. Adding or
editing lessons and restarting is enough:

```bash
./scripts/dev.sh restart
```

Lesson ids stay stable, so progress survives content edits. Lessons removed from
the content file are deleted from the catalogue (progress rows cascade).

**Exception — table shape changes.** `Base.metadata.create_all()` never alters
an existing table, so a new column is missing from an existing `data/cyberlabs.db`
and every query fails with `no such column: <table>.<column>`. Fix:

```bash
./scripts/dev.sh stop && rm -f data/cyberlabs.db && ./scripts/dev.sh start
```

This exact failure happened on 2026-09-28 when `topics.learning_map` was added.
`CONTINUE.md` was also found as 3704 bytes of NUL at that point; the previous
notes were unrecoverable.

## 4. Content model

`backend/app/content/`:

| File | Contents |
| --- | --- |
| `builder.py` | `lesson(...)` — supplies defaults and fixes the page structure |
| `authentication.py` | assembles `AUTH_TOPIC` from theory + labs |
| `auth_theory.py` | 12 conceptual lessons + `LEARNING_MAP` |
| `auth_labs_login.py` | enumeration + brute-force lessons, `_theory()` narrative helper |
| `auth_labs_mfa_reset.py` | MFA + password-reset lessons |

Author a lesson with `builder.lesson()`; the docstring in `seed.py` documents
every field. Non-obvious rules:

- **`solution` is server-side only.** It is not in the `/api/vulns` payload. The
  lesson page POSTs to `/api/vulns/{id}/solution` only when the learner asks for
  the walkthrough. Keep it that way.
- **`sort_order` is the catalogue number.** Theory lessons use negative values
  (-120 … -109) to sort ahead of the labs without consuming numbers. Lab lessons
  must form a contiguous `1..N` run — `verify.py` asserts this.
- **One lesson = one weakness.** `lab_family` names the app, `lab_variant`
  selects the single behaviour it exposes via the `LAB_VARIANT` env var.

## 5. Current catalogue — Authentication (the only topic)

1 topic, **29 lessons**: 12 theory + 17 lab-backed. `total_vulns == 29`.

### Theory lessons (no lab)

`auth-foundations`, `auth-credentials`, `auth-factors`, `auth-tokens`,
`arch-stateful`, `arch-stateless`, `arch-spa-api`, `arch-mobile`, `arch-sso`,
`auth-attack-surface`, `auth-owasp-methodology`, `auth-reporting`.

These carry only the core fields — no scenario, solution, endpoints or
remediation, because there is nothing to play.

### Lab lessons

| # | Slug | Family | Variant | Difficulty |
| --- | --- | --- | --- | --- |
| 1 | `auth-enum-responses` | `auth_login` | `enum_response` | apprentice |
| 2 | `auth-enum-subtle` | `auth_login` | `enum_subtle` | apprentice |
| 3 | `auth-enum-timing` | `auth_login` | `enum_timing` | apprentice |
| 4 | `auth-enum-lock` | `auth_login` | `enum_lock` | apprentice |
| 5 | `auth-brute-unlimited` | `auth_login` | `brute_unlimited` | practitioner |
| 6 | `auth-brute-ipblock` | `auth_login` | `brute_ipblock` | practitioner |
| 7 | `auth-brute-multipass` | `auth_login` | `brute_multipass` | practitioner |
| 8 | `auth-mfa-simple-bypass` | `auth_mfa` | `mfa_simple_bypass` | practitioner |
| 9 | `auth-mfa-broken-logic` | `auth_mfa` | `mfa_broken_logic` | practitioner |
| 10 | `auth-mfa-bruteforce` | `auth_mfa` | `mfa_bruteforce` | expert |
| 11 | `auth-mfa-trusted-device` | `auth_mfa` | `mfa_trusted_device` | expert |
| 12 | `auth-mfa-backup-guess` | `auth_mfa` | `mfa_backup_guess` | practitioner |
| 13 | `auth-reset-broken-logic` | `auth_reset` | `reset_broken_logic` | practitioner |
| 14 | `auth-reset-poisoning-middleware` | `auth_reset` | `reset_poisoning_mw` | practitioner |
| 15 | `auth-reset-change-bruteforce` | `auth_reset` | `reset_change_bruteforce` | practitioner |
| 16 | `auth-reset-poisoning-complete` | `auth_reset` | `reset_poisoning_mw` | expert |
| 17 | `auth-reset-predictable` | `auth_reset` | `reset_predictable` | practitioner |

`reset_poisoning_mw` is intentionally shared by lessons 14 and 16: 14 stops at
extracting the victim's token from the poisoned link, 16 chains it through to the
password change. Every implemented variant now has a lesson — `verify.py` asserts
this in both directions.

## 6. Lab families and variants

Three families, ports registered in `lab_runner.DEFAULT_PORTS`.

### `auth_login` — port 8091 (`labs/default/auth_login/app.py`)

Flask + SQLite. Users: `alice/alice-secret-2024`, `bob/hunter2`,
`carol/carol-pw-9911` (admin). Flag on the signed-in page.

| Variant | Weakness |
| --- | --- |
| `enum_response` | "No account found" vs "Incorrect password" |
| `enum_subtle` | same wording, different status code (404) and body length |
| `enum_timing` | 450 ms sleep for real users vs 20 ms for unknown |
| `enum_lock` | account lockout after 3 failures |
| `brute_unlimited` | no rate limit, no lockout, no delay at all |
| `brute_ipblock` | per-IP block that trusts a client-supplied `X-Forwarded-For` |
| `brute_multipass` | accepts a JSON array of credential pairs in one request |

Note: this app branches on a **local** `variant = VARIANT`, not the global, so
grep for both when adding a variant.

### `auth_mfa` — port 8092 (`labs/default/auth_mfa/app.py`)

Flask + SQLite. `carol` (admin, the target for every lesson) and `alice`.
SMS `CODE = 481902`, backup `BACKUP_CODE = 7391`. Flag on `/account`.

| Variant | Weakness |
| --- | --- |
| `mfa_simple_bypass` | `/account` renders without any code being submitted |
| `mfa_broken_logic` | trusts a client-supplied `mfa_ok=true` |
| `mfa_bruteforce` | 6-digit code, no rate limit, no lockout |
| `mfa_trusted_device` | `remember_device` cookie = `sha256(username)[:8]` waives the factor permanently |
| `mfa_backup_guess` | `POST /verify-backup` takes 4-digit codes with no throttling |

### `auth_reset` — port 8093 (`labs/default/auth_reset/app.py`)

Flask + SQLite. Tokens `1001` (alice), `1002` (bob), `1003` (carol).
**This app has no `/login` route and never renders the flag** — see §9.

| Variant | Weakness |
| --- | --- |
| `reset_broken_logic` | token checked for existence but not bound to the account |
| `reset_poisoning_mw` | emailed link built from `X-Forwarded-Host` / `-Proto` |
| `reset_change_bruteforce` | `POST /api/change` verifies the current password with no rate limit |
| `reset_predictable` | any integer token >= 1001 accepted, token table never consulted |

## 7. API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/stats` | dashboard counters |
| GET | `/api/topics` | topic list |
| GET | `/api/topics/{slug}` | topic with nested lessons (**no** `solution`) |
| GET | `/api/vulns/{id}` | single lesson |
| POST | `/api/vulns/{id}/solution` | **the only** route that returns the walkthrough |
| GET | `/api/labs` | all lab rows |
| GET | `/api/labs/{id}` | one lab, polled for `status` / `url` |
| POST | `/api/labs/default` | launch the lab for `{"vuln_slug": "..."}` |
| POST | `/api/labs/ai` | AI-generated lab (disabled without `AI_API_KEY`) |
| DELETE | `/api/labs/{id}` | destroy the container, mark the row `stopped` |
| GET | `/api/progress/{vuln_id}` | progress for one lesson |
| POST | `/api/progress/{vuln_id}` | record attempt / completion / lab win |

Interactive docs: <http://127.0.0.1:8000/docs>.

## 8. Docker lab lifecycle

1. Learner launches → `POST /api/labs/default` → `lab_factory` copies
   `labs/default/<family>/` into `labs/generated/build/lab-N/`.
2. The flag is generated as `FLAG{lab<N>_<8 hex>}` and reaches the app **two
   ways**: `run_container` sets it in the container environment, and
   `lab_factory` text-substitutes `CYBERLABS_FLAG_PLACEHOLDER` in any `*.py` in
   the build context. All three current apps use the env var
   (`os.environ.get("FLAG", ...)`); none use the placeholder. Either works, but
   a lab that reads neither will build fine and silently render
   `FLAG{not_provided}`.
3. `lab_factory` writes a Dockerfile; `lab_runner.build_image` runs
   `docker build`.
4. `run_container` starts it on `cyberlabs-net`, an **`internal`** bridge
   network, with `cap_drop=ALL`, `no-new-privileges`, read-only rootfs, tmpfs
   `/tmp`, and the memory/CPU/PID caps from `config.py`.
5. The container's bridge IP and family port become the lab URL.
6. `monitor_ttl` destroys anything past `LAB_TTL_MINUTES`; the destroy button
   calls `DELETE /api/labs/{id}`.

**Lab URLs are `172.18.0.x`, not `127.0.0.1`, and that is correct.** Docker
creates no port-publishing NAT rules for an `internal` network, so `-p` silently
does nothing. The host can reach the bridge IP directly and the lab still has
zero internet egress — which is the property that matters. Making URLs
`127.0.0.1` would require dropping `internal` and losing egress isolation.

`clean_stale_containers()` runs at startup and force-removes anything labelled
`cyberlabs.component=lab`, so a crashed session does not leak containers.
`MAX_CONCURRENT_LABS` is counted from **DB rows**, not live containers: a row
left in `running` after its container died still consumes a slot. Delete those
rows (`DELETE /api/labs/{id}`) to reclaim it.

## 9. Validation

The suite is `scripts/verify.py` (stdlib only, run with the backend venv). Three
sections:

```bash
cd ~/cyberlabs

# static content checks + API smoke tests (no Docker needed, ~2s)
backend/.venv/bin/python scripts/verify.py

# + end-to-end exploit checks for the three newest variants (needs Docker)
backend/.venv/bin/python scripts/verify.py --variants

# + every variant that has a check (needs Docker, several minutes)
backend/.venv/bin/python scripts/verify.py --all

# one specific variant
backend/.venv/bin/python scripts/verify.py --variant mfa_backup_guess
```

Exit code is 0 only if everything passed. Checks that exist:

- **content** — unique slugs; required fields present (lab-only fields are
  required only for lab lessons); valid difficulty; hints parse as a 3+ tier
  JSON list; family present in `DEFAULT_PORTS`; **every lesson names a variant
  the app actually implements**; **every implemented variant has a lesson**;
  contiguous lab ordering; theory ordered negative; unique ports.
- **api** — stats match seeded content; `solution` absent from every lesson
  payload; `solution` retrievable on demand; progress round-trip.
- **variants** — launch the container, confirm `/healthz` reports the expected
  variant, then assert the *intended vulnerability is present and exploitable*
  (e.g. 30 failed logins never 429; 10,000 backup codes exhausted to reach
  `/account`; an unissued reset token resets another account), then destroy the
  lab.

The bidirectional variant↔lesson check is the one that would have caught the
original gap, where three implemented variants had no lesson at all.

Other commands that are worth running after a change:

```bash
./scripts/dev.sh status && ./scripts/dev.sh logs    # process state
cd frontend && npm run build                         # catches JSX/import errors
docker ps                                             # should be empty when idle
```

## 10. Known defects and remaining work

The Authentication lesson/lab agreement defects have been fixed. What is left:

1. **No frontend tests at all.** `npm run build` is the only guard.
2. **`max_concurrent_labs` counts stale rows** (see §8). A container that dies
   without its row being cleared keeps consuming a slot until restart.
3. **No git repository.** `git status` reports nothing; there is no history to
   diff against, so `CONTINUE.md` and this document are the only record of
   intent. Worth `git init` + first commit before further work.
4. **No lesson-content versioning.** Because seeding is a destructive upsert, an
   accidental deletion in a content file deletes the lesson and its progress.
5. **`auth_login` has no session at all.** Every lab keeps its state in the
   container database keyed on the submitted username, so two learners on one
   container would share state. Fine for the disposable per-learner containers
   this module uses; it would not survive a shared deployment.
6. **The MFA 6-digit space is only partially swept by the default suite.**
   `verify.py` asserts the absence of controls over 40 attempts and then uses
   the code fixture. `--exhaustive` walks all 10^6 values; it is opt-in because
   it takes minutes.

### Fixed in the agreement pass

- `auth_reset` gained `GET/POST /login` (rate limited in every variant) and a
  `GET /account` page that carries the flag behind a real session, so
  "sign in as `carol` to retrieve the flag" is now true for all four reset
  lessons. `POST /api/change` and `POST /change` take the target account from
  the request instead of hardcoding `alice`, defaulting to `carol`.
- `auth_mfa`'s `/account` no longer falls back to serving `carol` when no
  challenge is pending; an anonymous visitor is redirected. Previously the
  "2FA is not enforced" labs were also "authentication is not enforced" labs.
- `auth_login`'s `brute_ipblock` counter now upserts, so the block actually
  engages and there is a block to bypass; `enum_lock` only counts real
  accounts, which is what makes the lockout an enumeration oracle.
- Every one of the 16 implemented variants has a behavioural check in
  `verify.py`, and two new static invariants keep that true: a variant with no
  registered check fails the content section, and a lesson whose
  `success_condition` promises the flag fails unless its check asserts flag
  reachability. A third cross-checks each lesson's advertised `endpoints`
  against the routes its lab app actually serves.

## 11. Recommended next steps

1. `git init` and commit, so the next round of edits is revertible.
2. Add the missing frontend tests (item 1 above).
3. Only then start a second topic, using `auth_theory.py` + a content module +
   a lab family as the template. Keep the one-weakness-per-variant rule and let
   `verify.py --all` gate the work.
4. AI-generated labs (`lab_generator.py`, `POST /api/labs/ai`) are still
   untouched and unverified. Leave them until the deterministic path is solid.
