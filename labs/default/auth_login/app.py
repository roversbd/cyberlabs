"""Parameterized vulnerable login app.

One app, one weakness per run. The variant is chosen by the LAB_VARIANT env var
that the backend injects at build/run time, so every lab exposes exactly the
single behaviour it teaches and nothing else.

Variants
--------
enum_response      different error text for unknown user vs wrong password
enum_subtle        same wording, different HTTP status / body length
enum_timing        deliberate delay proportional to a constant-time compare
enum_lock          account lockout triggered by failed attempts
brute_unlimited    no throttling at all on the login endpoint
brute_ipblock      per-IP block that trusts a client-supplied X-Forwarded-For
brute_multipass    accepts an array of credential pairs in one request

Run with:  LAB_VARIANT=enum_response python app.py
"""

import hashlib
import json
import os
import sqlite3
import time

from flask import Flask, jsonify, redirect, request, url_for

app = Flask(__name__)

VARIANT = os.environ.get("LAB_VARIANT", "enum_response")
FLAG = os.environ.get("FLAG", "FLAG{not_provided}")
DB = "/tmp/auth_login.db"
PORT = 8091

USERS = [
    # username, password,        role,     note
    ("alice", "alice-secret-2024", "user", "billing contact"),
    ("bob", "hunter2", "user", "onboarding owner"),
    ("carol", "carol-pw-9911", "admin", "platform administrator"),
]


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as c:
        c.execute("DROP TABLE IF EXISTS users")
        c.execute(
            "CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, role TEXT, note TEXT)"
        )
        c.executemany("INSERT INTO users VALUES (?,?,?,?)", USERS)
        c.commit()


def find_user(username):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def home():
    return f"""<!doctype html>
<title>Northwind Retail &mdash; sign in</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 20px;color:#1a1a1a}}
 h1{{font-size:22px}} label{{display:block;margin:12px 0 4px;font-size:14px}}
 input{{width:100%;padding:9px;font-size:15px;box-sizing:border-box}}
 button{{margin-top:18px;padding:10px 18px;font-size:15px;cursor:pointer}}
 .err{{color:#b00020;margin-top:14px}} .ok{{color:#0a7d28;margin-top:14px}}
 .note{{color:#666;font-size:13px;margin-top:24px}}
 code{{background:#f2f2f2;padding:1px 5px;border-radius:3px}}
</style>
<h1>Northwind Retail</h1>
<p>Employee sign-in. Accounts: <code>alice</code>, <code>bob</code>, <code>carol</code>.</p>
<form method="post" action="/login">
  <label for="u">Username</label><input id="u" name="username" autocomplete="off">
  <label for="p">Password</label><input id="p" name="password" type="password">
  <button>Sign in</button>
</form>
<p class="note">Active variant: <code>{VARIANT}</code></p>
<p class="note"><a href="/reset">Forgot your password?</a> &middot; <a href="/">home</a></p>
"""


@app.get("/")
def index():
    return home()


def success(row, note):
    return f"""<!doctype html><title>Signed in</title>
<style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 20px}}</style>
<h1>Signed in as {row['username']}</h1>
<p>Role: <b>{row['role']}</b></p>
<div style="border:1px solid #0a7d28;padding:16px;margin-top:20px">
  <h3>Account notes</h3><p>{note}</p>
  <code style="font-size:15px">{FLAG}</code>
</div>
<p><a href="/">sign out</a></p>"""


@app.post("/login")
def login():
    raw_user = request.form.get("username", "")
    raw_pass = request.form.get("password", "")
    variant = VARIANT

    # ---- multi-credential batch -------------------------------------------
    if variant == "brute_multipass" and raw_user.lstrip().startswith("["):
        # The endpoint also accepts a JSON array of attempts and reports which
        # one succeeded, turning a rate-limited form into an offline oracle.
        try:
            attempts = json.loads(raw_user)
        except Exception:
            return f"{home()}<p class='err'>Malformed request.</p>", 400
        for a in attempts:
            row = find_user(str(a.get("username", "")))
            if row and row["password"] == str(a.get("password", "")):
                return success(row, row["note"])
        return f"{home()}<p class='err'>Invalid credentials.</p>", 200

    username = raw_user
    password = raw_pass

    # ---- per-IP blocking that trusts a client header ----------------------
    if variant == "brute_ipblock":
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        c = get_db()
        c.execute(
            "CREATE TABLE IF NOT EXISTS attempts (ip TEXT PRIMARY KEY, n INTEGER)"
        )
        row = c.execute("SELECT n FROM attempts WHERE ip = ?", (ip,)).fetchone()
        n = row["n"] if row else 0
        if n >= 3:
            return (
                f"{home()}<p class='err'>Account temporarily locked. Try again in "
                f"{60 - n} seconds.</p>",
                429,
            )
        # Must upsert. A bare INSERT left one row per attempt, so the SELECT
        # above kept finding n=1 and the counter never advanced - meaning the
        # endpoint was never actually blocked and there was nothing for the
        # learner to bypass.
        c.execute("INSERT OR REPLACE INTO attempts VALUES (?,?)", (ip, n + 1))
        c.commit()
        known = find_user(username)
        if not known or known["password"] != password:
            return f"{home()}<p class='err'>Invalid credentials.</p>", 200
        return success(known, known["note"])

    # ---- timing oracle ----------------------------------------------------
    if variant == "enum_timing":
        row = find_user(username)
        # Real users pay for a password comparison; unknown users do not.
        time.sleep(0.45 if row else 0.02)
        if not row or row["password"] != password:
            return f"{home()}<p class='err'>Invalid credentials.</p>", 200
        return success(row, row["note"])

    # ---- account lockout --------------------------------------------------
    if variant == "enum_lock":
        c = get_db()
        c.execute(
            "CREATE TABLE IF NOT EXISTS locks (username TEXT PRIMARY KEY, n INTEGER)"
        )
        known = find_user(username)
        if known is None:
            # The counter is only kept for accounts that exist, which is the
            # whole point of the lesson: locking a real account and never
            # locking a made-up one turns the lockout into an account-existence
            # oracle. Locking unknown usernames too (the previous behaviour)
            # made the oracle impossible - both cases answered 429, so there
            # was nothing to tell apart.
            return f"{home()}<p class='err'>Invalid credentials.</p>", 200
        row = c.execute("SELECT n FROM locks WHERE username = ?", (username,)).fetchone()
        n = row["n"] if row else 0
        if n >= 3:
            return (
                f"{home()}<p class='err'>Account locked due to failed logins.</p>",
                429,
            )
        c.execute(
            "INSERT OR REPLACE INTO locks VALUES (?,?)", (username, n + 1)
        )
        c.commit()
        if known["password"] != password:
            return f"{home()}<p class='err'>Invalid credentials.</p>", 200
        return success(known, known["note"])

    # ---- no throttling at all --------------------------------------------
    if variant == "brute_unlimited":
        row = find_user(username)
        if not row or row["password"] != password:
            return f"{home()}<p class='err'>Invalid credentials.</p>", 200
        return success(row, row["note"])

    # ---- the four enumeration variants ------------------------------------
    row = find_user(username)

    if variant == "enum_response":
        # Different wording reveals whether the account exists.
        if not row:
            return f"{home()}<p class='err'>No account found with that username.</p>", 200
        if row["password"] != password:
            return f"{home()}<p class='err'>Incorrect password.</p>", 200
        return success(row, row["note"])

    if variant == "enum_subtle":
        # Same wording, different status code and different body length.
        if not row:
            body = f"{home()}<p class='err'>Invalid credentials.</p>"
            return body, 404
        if row["password"] != password:
            body = f"{home()}<p class='err'>Invalid credentials.</p>"
            return body + "<!-- auth-service: upstream timeout -->", 200
        return success(row, row["note"])

    # Default/unknown variant: behaves correctly.
    row = find_user(username)
    if not row or row["password"] != password:
        return f"{home()}<p class='err'>Invalid credentials.</p>", 200
    return success(row, row["note"])


@app.post("/reset")
def reset():
    email = request.form.get("email", "")
    # Always the same answer regardless of whether the address is registered.
    return (
        f"{home()}<p class='ok'>If that address has an account, a reset link has "
        f"been sent.</p>",
        200,
    )


@app.get("/healthz")
def healthz():
    return jsonify(ok=True, variant=VARIANT)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
