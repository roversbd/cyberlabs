"""Parameterized vulnerable password-reset app.

One weakness per run, selected by LAB_VARIANT. The recovery weaknesses are the
subject of every variant; the sign-in form exists so that taking an account over
actually *ends* somewhere - without it there is no reward for a successful reset
and no way to show the takeover.

Variants
--------
reset_broken_logic      the reset flow skips the "token must match this account"
                        check, so any valid token resets any account
reset_poisoning_mw      the reset email builds its link from a proxy-controlled
                        header, so the link is sent to the attacker
reset_change_bruteforce /change-password has no rate limit, so the current
                        password can be brute-forced without touching login
reset_predictable       tokens are sequential integers

Unchanged across all variants: POST /login is rate limited, and the account page
carries the flag. The lesson for each variant drives the learner through
recovering or brute forcing a password and then signing in to claim it.
"""

import hashlib
import os
import secrets
import sqlite3
import time

from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    request,
    session,
)

app = Flask(__name__)
# Ephemeral lab, fixed key: sessions only need to survive one container's life.
app.secret_key = os.environ.get("LAB_SECRET", "northwind-lab-not-a-real-secret")

VARIANT = os.environ.get("LAB_VARIANT", "reset_broken_logic")
FLAG = os.environ.get("FLAG", "FLAG{not_provided}")
DB = "/tmp/auth_reset.db"
PORT = 8093

USERS = [("alice", "alice-secret-2024"), ("bob", "hunter2"), ("carol", "carol-pw-9911")]

# The account these labs are about. reset_change_bruteforce used to hardcode
# "alice" while its lesson said "carol"; the endpoint now takes the account
# from the request, and the lesson's target is the default.
DEFAULT_TARGET = "carol"

LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 30


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as c:
        c.execute("DROP TABLE IF EXISTS users")
        c.execute(
            "CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, email TEXT)"
        )
        for u, p in USERS:
            c.execute(
                "INSERT INTO users VALUES (?,?,?)",
                (u, p, f"{u}@northwind-retail.test"),
            )
        c.execute("DROP TABLE IF EXISTS tokens")
        c.execute(
            "CREATE TABLE tokens (token TEXT PRIMARY KEY, username TEXT, used INTEGER DEFAULT 0)"
        )
        c.execute("INSERT INTO tokens VALUES ('1001','alice',0)")
        c.execute("INSERT INTO tokens VALUES ('1002','bob',0)")
        c.execute("INSERT INTO tokens VALUES ('1003','carol',0)")
        c.execute("DROP TABLE IF EXISTS login_attempts")
        c.execute(
            "CREATE TABLE login_attempts (username TEXT PRIMARY KEY, n INTEGER, first_at REAL)"
        )
        c.commit()


def layout(inner, title="Northwind Retail"):
    return f"""<!doctype html><title>{title}</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:620px;margin:48px auto;padding:0 20px;color:#1a1a1a}}
 input{{width:100%;padding:9px;margin-top:10px;box-sizing:border-box;font-size:15px}}
 button{{margin-top:16px;padding:10px 18px;font-size:15px;cursor:pointer}}
 .err{{color:#b00020;margin-top:14px}} .ok{{color:#0a7d28;margin-top:14px}}
 pre{{background:#f6f6f6;padding:14px;overflow:auto;border:1px solid #e2e2e2}}
 code{{background:#f2f2f2;padding:1px 5px}}
 .mail{{border:1px solid #ddd;padding:14px;margin-top:18px;background:#fcfcfc}}
</style>
<h1>{title}</h1>
{inner}
<p style="margin-top:26px"><a href="/">home</a></p>"""


def home():
    who = session.get("user")
    banner = (
        f"<p class='ok'>Signed in as <b>{who}</b> &middot; "
        f"<a href='/account'>my account</a></p>"
        if who
        else ""
    )
    return layout(
        f"""{banner}
<form method="post" action="/forgot"><p>Forgot your password?</p>
<input name="email" placeholder="you@northwind-retail.test">
<button>Send reset link</button></form>
<p style="margin-top:20px"><a href="/reset?token=1001&amp;user=alice">Have a link? Set a new password</a></p>
<p><a href="/login">Sign in</a> &middot; <a href="/change">Change your password</a></p>""",
        "Northwind Retail &mdash; account recovery",
    )


@app.get("/")
def index():
    return home()


def build_link(username):
    """The reset link that gets emailed. Note where the base URL comes from."""
    if VARIANT == "reset_poisoning_mw":
        # VULNERABLE: the base URL is taken from a header set by the upstream
        # proxy and is used verbatim in the emailed link.
        base = request.headers.get("X-Forwarded-Host", "northwind-retail.test")
        proto = request.headers.get("X-Forwarded-Proto", "http")
    else:
        base = "northwind-retail.test"
        proto = "https"
    token = get_db().execute(
        "SELECT token FROM tokens WHERE username = ?", (username,)
    ).fetchone()["token"]
    return f"{proto}://{base}/reset?token={token}&user={username}"


@app.post("/forgot")
def forgot():
    email = request.form.get("email", "")
    row = get_db().execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    if not row:
        return home() + "<p class='err'>Unknown email address.</p>", 200
    link = build_link(row["username"])
    # Deliberately shown so the poisoning is observable inside the lab.
    return layout(
        f"""<p class="ok">Reset link sent to {email}.</p>
<div class="mail"><b>Delivered mail</b><pre>Subject: Reset your Northwind password

Use the link below within 30 minutes:
{link}</pre></div>""",
        "Check your inbox",
    )


@app.get("/reset")
def reset_form():
    token = request.args.get("token", "")
    user = request.args.get("user", "")
    return layout(
        f"""<form method="post" action="/reset">
 <input type="hidden" name="token" value="{token}">
 <input type="hidden" name="user" value="{user}">
 <p>Setting a new password for <b>{user or 'your account'}</b>.</p>
 <label>New password</label><input name="password" type="password">
 <button>Set password</button>
</form>""",
        "Choose a new password",
    )


def reset_success(user):
    """Shared confirmation for every reset path.

    Password changed is not the end of the story: the account is only taken
    over once the attacker can sign in with the new password, so the page
    hands them straight to the form that holds the flag.
    """
    return layout(
        f"""<p class="ok">Password updated for {user}.</p>
<p>The account is not yours until you can sign in with the new password.</p>
<p style="margin-top:18px"><a href="/login"><button>Continue to sign in</button></a></p>""",
        "Password changed",
    )


@app.post("/reset")
def reset_submit():
    token = request.form.get("token", "")
    user = request.form.get("user", "")
    newpw = request.form.get("password", "")
    c = get_db()

    if VARIANT == "reset_predictable":
        # VULNERABLE: tokens are sequential, and any integer >= 1001 is accepted
        # for any account without checking the token table at all.
        if token.isdigit() and int(token) >= 1001:
            c.execute(
                "UPDATE users SET password = ? WHERE username = ?", (newpw, user)
            )
            c.commit()
            return reset_success(user)
        return layout("<p class='err'>That reset link is invalid.</p>", "Error")

    if VARIANT == "reset_broken_logic":
        # VULNERABLE: the code checks that *a* token exists but never checks
        # that it belongs to the account being reset. Token 1001 belongs to
        # alice, yet it will happily reset carol's password.
        valid = c.execute(
            "SELECT * FROM tokens WHERE token = ?", (token,)
        ).fetchone()
        if not valid:
            return layout("<p class='err'>That reset link is invalid.</p>", "Error")
        c.execute("UPDATE users SET password = ? WHERE username = ?", (newpw, user))
        c.commit()
        return reset_success(user)

    # Default: correct behaviour.
    valid = c.execute(
        "SELECT * FROM tokens WHERE token = ? AND username = ? AND used = 0",
        (token, user),
    ).fetchone()
    if not valid:
        return layout("<p class='err'>That reset link is invalid.</p>", "Error")
    c.execute("UPDATE users SET password = ? WHERE username = ?", (newpw, user))
    c.execute("UPDATE tokens SET used = 1 WHERE token = ?", (token,))
    c.commit()
    return reset_success(user)


def login_page(msg="", status=200):
    """Always returns a string.

    It used to double as the view, so once a session existed it returned a
    redirect() Response and the error paths below blew up concatenating it with
    a message - meaning a mistyped password *after* signing in returned 500
    instead of 'Invalid credentials.'
    """
    return (
        layout(
            f"""<form method="post" action="/login">
  <label>Username</label><input name="username" autocomplete="off">
  <label style="margin-top:12px">Password</label><input name="password" type="password">
  <button>Sign in</button>
</form>{f"<p class='err'>{msg}</p>" if msg else ''}""",
            "Northwind Retail &mdash; sign in",
        ),
        status,
    )


@app.get("/login")
def login_form():
    if session.get("user"):
        return redirect("/account")
    return login_page()


@app.post("/login")
def login():
    """Rate limited in every variant.

    This is the point of the reset_change_bruteforce lesson: the sign-in form
    has an attempt budget, so guessing a password has to happen somewhere else.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    c = get_db()

    c.execute(
        "CREATE TABLE IF NOT EXISTS login_attempts "
        "(username TEXT PRIMARY KEY, n INTEGER, first_at REAL)"
    )
    row = c.execute(
        "SELECT n, first_at FROM login_attempts WHERE username = ?", (username,)
    ).fetchone()

    if row:
        n, first_at = row["n"], row["first_at"]
        if time.time() - first_at > LOGIN_LOCKOUT_SECONDS:
            n, first_at = 0, time.time()
        if n >= LOGIN_MAX_FAILURES:
            wait = int(LOGIN_LOCKOUT_SECONDS - (time.time() - first_at)) + 1
            return login_page(
                f"Too many failed attempts. Try again in {wait} seconds.", status=429
            )

    user = c.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not user or user["password"] != password:
        c.execute(
            "INSERT OR REPLACE INTO login_attempts VALUES (?,?,?)",
            (username, n + 1 if row else 1, first_at if row else time.time()),
        )
        c.commit()
        return login_page("Invalid credentials.")

    c.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
    c.commit()
    session["user"] = user["username"]
    return redirect("/account")


@app.get("/account")
def account():
    username = session.get("user")
    if not username:
        return redirect("/login")
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not row:
        session.pop("user", None)
        return redirect("/login")
    role = "administrator" if username == "carol" else "employee"
    return layout(
        f"""<div class="card" style="border:1px solid #0a7d28;padding:16px">
  <h3>Account: {row['username']}</h3>
  <p>Role: <b>{role}</b></p>
  <p>{row['email']}</p>
  <pre style="background:#f6f6f6;padding:14px;border:1px solid #e2e2e2">{FLAG}</pre>
  <p><a href="/change">Change your password</a> &middot; <a href="/">home</a></p>
</div>""",
        "My account",
    )


@app.get("/change")
def change_form():
    return layout(
        f"""<form method="post" action="/change">
  <label>Account</label><input name="username" value="{DEFAULT_TARGET}" autocomplete="off">
  <label style="margin-top:12px">Current password</label><input name="current" type="password">
  <label style="margin-top:12px">New password</label><input name="new" type="password">
  <button>Change password</button>
</form>""",
        "Change password",
    )


def _target_user(form_or_json: dict) -> str:
    """The account being changed.

    This endpoint used to be hardcoded to "alice" while its lesson said
    "carol", so the stated target and the attackable account disagreed. The
    account now comes from the request, defaulting to the lab's target.
    """
    return (form_or_json.get("username") or DEFAULT_TARGET).strip() or DEFAULT_TARGET


@app.post("/change")
def change():
    current = request.form.get("current", "")
    user = _target_user(request.form)
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (user,)
    ).fetchone()
    if not row:
        return change_form() + "<p class='err'>No such account.</p>", 200
    if row["password"] != current:
        return (
            change_form() + "<p class='err'>Current password is incorrect.</p>",
            200,
        )
    c = get_db()
    c.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (request.form.get("new", ""), user),
    )
    c.commit()
    return layout(
        f"<p class='ok'>Password changed for {user}.</p>", "Change password"
    )


@app.post("/api/change")
def api_change():
    data = request.get_json(silent=True) or {}
    user = _target_user(data)
    if VARIANT == "reset_change_bruteforce":
        # VULNERABLE: no rate limit and no lockout on this endpoint, so the
        # current password can be guessed even though /login is throttled.
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (user,)
        ).fetchone()
        if not row:
            return jsonify(ok=False, error="no such account"), 404
        if data.get("current") == row["password"]:
            new = data.get("new")
            if new:
                c = get_db()
                c.execute(
                    "UPDATE users SET password = ? WHERE username = ?", (new, user)
                )
                c.commit()
            return jsonify(ok=True, username=user)
        return jsonify(ok=False, error="incorrect"), 200
    # Correct behaviour everywhere else: the endpoint still changes the named
    # account, but only after a valid session.
    if session.get("user") != user:
        return jsonify(ok=False, error="not signed in as this account"), 403
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (user,)
    ).fetchone()
    ok = row is not None and data.get("current") == row["password"]
    return jsonify(ok=ok, error=None if ok else "incorrect"), (200 if ok else 429)


@app.get("/healthz")
def healthz():
    return jsonify(ok=True, variant=VARIANT)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
