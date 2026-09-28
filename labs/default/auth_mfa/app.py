"""Parameterized vulnerable MFA / second-factor app.

One weakness per run, selected by LAB_VARIANT.

Variants
--------
mfa_simple_bypass   the 2FA page is client-side only; the protected page never
                    checks that a code was submitted
mfa_broken_logic    a JSON flag in the response is trusted by the server
mfa_bruteforce      /verify has no rate limit on a 6-digit code
mfa_trusted_device  the "remember this device" token is a short predictable
                    value and permanently waives the second factor
mfa_backup_guess    the 4-digit backup-code endpoint has no throttling at all
"""

import hashlib
import hmac
import os
import random
import sqlite3

from flask import Flask, jsonify, redirect, request, url_for

app = Flask(__name__)

VARIANT = os.environ.get("LAB_VARIANT", "mfa_simple_bypass")
FLAG = os.environ.get("FLAG", "FLAG{not_provided}")
DB = "/tmp/auth_mfa.db"
PORT = 8092

CODE = "481902"  # the real code, delivered by "SMS" in a real deployment
BACKUP_CODE = "7391"  # one of the single-use codes handed out at enrolment


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as c:
        c.execute("DROP TABLE IF EXISTS users")
        c.execute(
            "CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT,"
            " pending INTEGER DEFAULT 0, verified INTEGER DEFAULT 0, device TEXT)"
        )
        c.execute(
            "INSERT INTO users VALUES ('carol','carol-pw-9911',0,0,'')"
        )
        c.execute("INSERT INTO users VALUES ('alice','alice-secret-2024',0,1,'')")
        c.commit()


def note():
    return "Platform administrator. Emergency access code issued at 09:14."


def layout(inner, title="Northwind Retail"):
    return f"""<!doctype html><title>{title}</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:620px;margin:48px auto;padding:0 20px;color:#1a1a1a}}
 input{{width:100%;padding:9px;margin-top:10px;box-sizing:border-box;font-size:15px}}
 button{{margin-top:16px;padding:10px 18px;font-size:15px;cursor:pointer}}
 .err{{color:#b00020;margin-top:14px}} .ok{{color:#0a7d28}}
 .card{{border:1px solid #ddd;padding:16px;margin-top:18px;border-radius:8px}}
 code{{background:#f2f2f2;padding:1px 5px}}
</style>
<h1>{title}</h1>
{inner}
<p style="margin-top:26px"><a href="/">home</a></p>"""


def home():
    return layout(
        """<p>Sign in to your account.</p>
<form method="post" action="/login">
 <label>Username</label><input name="username" autocomplete="off">
 <label>Password</label><input name="password" type="password">
 <button>Continue</button>
</form>""",
        "Northwind Retail &mdash; sign in",
    )


def mfa_form(msg=""):
    backup_link = (
        "<p style='margin-top:14px'><a href='/verify-backup'>"
        "Use a backup code instead</a></p>"
        if VARIANT == "mfa_backup_guess"
        else ""
    )
    return layout(
        f"""<div class="card">
  <h3>Two-factor authentication</h3>
  <p>We sent a 6-digit code to your phone ending 4417.</p>
  <form method="post" action="/verify">
    <label>Code</label><input name="code" autocomplete="one-time-code">
    <label style="margin-top:12px;display:inline-block">
      <input type="checkbox" name="remember" value="on" style="width:auto"> Remember this device
    </label>
    <button>Verify</button>
  </form>
  {f'<p class="err">{msg}</p>' if msg else ''}
  {backup_link}
</div>""",
        "Verification required",
    )


def backup_form(msg=""):
    return layout(
        f"""<div class="card">
  <h3>Use a backup code</h3>
  <p>Enter one of the 4-digit backup codes you saved when you enrolled. Each code
     works once.</p>
  <form method="post" action="/verify-backup">
    <label>Backup code</label><input name="backup_code" autocomplete="off">
    <button>Verify</button>
  </form>
  {f'<p class="err">{msg}</p>' if msg else ''}
</div>""",
        "Backup code",
    )


def account_page(user, verified_note=False):
    trusted = ""
    if verified_note:
        trusted = (
            "<p style='color:#0a7d28'>Second factor satisfied.</p>"
        )
    return layout(
        f"""<div class="card">
  <h3>Account: {user['username']}</h3>
  <p>Role: <b>{user['role'] if 'role' in user.keys() else 'admin'}</b></p>
  <p>{note()}</p>
  {trusted}
  <div style="border:1px solid #0a7d28;padding:14px;margin-top:16px">
    <code style="font-size:15px">{FLAG}</code>
  </div>
</div>""",
        "My account",
    )


@app.get("/")
def index():
    return home()


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not row or row["password"] != password:
        return home() + "<p class='err'>Invalid credentials.</p>", 200

    c = get_db()
    # Any successful first factor starts a challenge. Whether the account
    # already has MFA enrolled is decided by the /account gate, not here.
    # (Challenging only the accounts pre-flagged verified=1 left carol - the
    # administrator this module is built around - with no pending row, so her
    # login dead-ended in a redirect loop and no MFA lesson was solvable.)
    c.execute("UPDATE users SET pending = 1 WHERE username = ?", (username,))
    c.commit()
    return redirect("/mfa")


@app.get("/mfa")
def mfa():
    return mfa_form()


@app.post("/verify")
def verify():
    row = get_db().execute(
        "SELECT * FROM users WHERE pending = 1"
    ).fetchone()
    if not row:
        return redirect("/")

    code = request.form.get("code", "").strip()
    remember = bool(request.form.get("remember"))
    username = row["username"]

    c = get_db()

    if VARIANT == "mfa_trusted_device":
        # The trust cookie is a short, guessable value that permanently waives
        # the second factor for any account.
        token = request.cookies.get("remember_device", "")
        if token == hashlib.sha256(username.encode()).hexdigest()[:8]:
            c.execute("UPDATE users SET verified = 1 WHERE username = ?", (username,))
            c.commit()
            return redirect("/account")
        if code == CODE:
            c.execute(
                "UPDATE users SET verified = 1, device = ? WHERE username = ?",
                (hashlib.sha256(username.encode()).hexdigest()[:8], username),
            )
            c.commit()
            resp = redirect("/account")
            if remember:
                resp.set_cookie(
                    "remember_device",
                    hashlib.sha256(username.encode()).hexdigest()[:8],
                    max_age=60 * 60 * 24 * 365,
                )
            return resp
        return mfa_form("Invalid code."), 200

    if VARIANT == "mfa_backup_guess":
        # The SMS endpoint is throttled. The weakness this lab teaches is the
        # sibling backup-code endpoint, not this one.
        c.execute(
            "CREATE TABLE IF NOT EXISTS mfa_attempts (username TEXT PRIMARY KEY, n INTEGER)"
        )
        arow = c.execute(
            "SELECT n FROM mfa_attempts WHERE username = ?", (username,)
        ).fetchone()
        n = arow["n"] if arow else 0
        if n >= 3:
            return mfa_form("Too many attempts. Request a new code."), 429
        c.execute("INSERT OR REPLACE INTO mfa_attempts VALUES (?,?)", (username, n + 1))
        c.commit()
        if code == CODE:
            c.execute("UPDATE users SET verified = 1 WHERE username = ?", (username,))
            c.commit()
            return redirect("/account")
        return mfa_form("Invalid code."), 200

    if VARIANT == "mfa_bruteforce":
        # No rate limit, no lockout, no attempt counter.
        if code == CODE:
            c.execute("UPDATE users SET verified = 1 WHERE username = ?", (username,))
            c.commit()
            return redirect("/account")
        return mfa_form("Invalid code."), 200

    if VARIANT == "mfa_broken_logic":
        # The client sends back whether it thinks the code was right, and the
        # server believes the client.
        claimed = request.form.get("mfa_ok", "")
        if claimed == "true" or code == CODE:
            c.execute("UPDATE users SET verified = 1 WHERE username = ?", (username,))
            c.commit()
            return redirect("/account")
        return mfa_form("Invalid code."), 200

    # mfa_simple_bypass / default: code is genuinely checked, but the protected
    # page does not require verified=1.
    if code == CODE:
        c.execute("UPDATE users SET verified = 1 WHERE username = ?", (username,))
        c.commit()
        return redirect("/account")
    return mfa_form("Invalid code."), 200


@app.post("/api/verify")
def api_verify():
    """JSON challenge endpoint used by the SPA client."""
    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))
    row = get_db().execute("SELECT * FROM users WHERE pending = 1").fetchone()
    if not row:
        return jsonify(error="no pending challenge"), 400
    ok = code == CODE
    return jsonify(
        verified=ok,
        # The client stores this flag; the server has its own verified column
        # but the account page reads the client-supplied one.
        mfa_ok="true" if ok else "false",
    )


@app.get("/verify-backup")
def verify_backup_form():
    if VARIANT != "mfa_backup_guess":
        return layout("<p class='err'>No backup codes are configured.</p>", "Error"), 404
    return backup_form()


@app.post("/verify-backup")
def verify_backup():
    """VULNERABLE (mfa_backup_guess): the backup-code endpoint has no rate limit,
    no lockout, no attempt counter and no cool-off. The only thing standing
    between an attacker and the account is the size of the code."""
    if VARIANT != "mfa_backup_guess":
        return layout("<p class='err'>No backup codes are configured.</p>", "Error"), 404
    row = get_db().execute("SELECT * FROM users WHERE pending = 1").fetchone()
    if not row:
        return redirect("/")
    code = request.form.get("backup_code", "").strip()
    if code == BACKUP_CODE:
        c = get_db()
        c.execute(
            "UPDATE users SET verified = 1 WHERE username = ?", (row["username"],)
        )
        c.commit()
        return redirect("/account")
    return backup_form("Invalid backup code."), 200


@app.get("/account")
def account():
    # The account page is only reachable once the first factor has been
    # satisfied. It used to fall back to carol whenever no challenge was
    # pending, which meant an anonymous visitor got the administrator's panel:
    # that is a missing-authentication bug, not the missing-second-factor bug
    # this family teaches, and it let every MFA lesson be "solved" by skipping
    # the login entirely.
    row = get_db().execute(
        "SELECT * FROM users WHERE pending = 1"
    ).fetchone()
    if not row:
        return redirect("/")

    if VARIANT == "mfa_simple_bypass":
        # VULNERABLE: the account page renders for anyone who has merely
        # reached the login step. It never checks that a code was verified.
        return account_page(row, verified_note=False)

    if VARIANT == "mfa_broken_logic":
        claimed = request.args.get("mfa_ok", "")
        return account_page(row, verified_note=(claimed == "true" or row["verified"] == 1))

    if not row["verified"]:
        return redirect("/mfa")
    return account_page(row, verified_note=True)


@app.get("/healthz")
def healthz():
    return jsonify(ok=True, variant=VARIANT)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
