"""Authentication labs 1-14: the PortSwigger-style enumeration, brute force,
MFA and password-reset group.

Each lab binds to one variant of a shared family app, so the container exposes
exactly the one weakness being taught.
"""

from __future__ import annotations

from .builder import lesson

LOGIN = "auth_login"
MFA = "auth_mfa"
RESET = "auth_reset"

PS_ENUM = "https://portswigger.net/web-security/user-enumeration"
PS_BRUTE = "https://portswigger.net/web-security/authentication/lab-brute-forcing-2fa-and-credential-stuffing"
PS_MFA = "https://portswigger.net/web-security/multi-factor/lab-2fa-broken-logic"
PS_RESET = "https://portswigger.net/web-security/host-header/exploiting-password-reset-poisoning-via-middleware"
PS_RATELIMIT = "https://portswigger.net/web-security/authentication/lab-broken-brute-force-protection-still-observable-due-to-case-sensitive-password"
PS_KNOW = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
)


def _theory(
    what: str,
    normal: str,
    wrong: str,
    attacker: str,
    why: str,
    fix: str,
    detect: str,
    real: str,
) -> str:
    """Assemble the 8-part lab narrative. The lesson name is rendered as the
    page title, so the body starts straight at the definition."""
    return f"""
{what}

## How it normally works

{normal}

## Where it goes wrong

{wrong}

## Attacker's view

{attacker}

## Why it works

{why}

## Remediation

{fix}

## Detection

{detect}

## Real-world relevance

{real}
"""


def enumeration_labs() -> list[dict]:
    return [
        lesson(
            "auth-enum-responses",
            "Username enumeration via different error responses",
            category="Credentials & Enumeration",
            summary=(
                "The login form tells you whether an account exists by using "
                "different wording for an unknown user than for a wrong password."
            ),
            scenario=(
                "Northwind Retail runs a small staff portal. You have found the "
                "sign-in page but you have no valid credentials. Your goal is to "
                "determine which usernames are real so you can target them."
            ),
            theory=_theory(
                what=(
                    "**Username enumeration** through differing error messages. When the "
                    "login form responds with *\"No account found with that "
                    "username\"* for an unknown user but *\"Incorrect password\"* for a "
                    "known one, the form has become a user directory with a rate limit."
                ),
                normal=(
                    "A correct login returns one generic failure for every bad "
                    "credential combination.\n\n"
                    "```http\nPOST /login\nusername=nosuchuser&password=whatever\n```\n\n"
                    "```http\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n"
                    "<p class='err'>Invalid credentials.</p>\n```\n\n"
                    "The same body is returned for a real user with a wrong password."
                ),
                wrong=(
                    "The endpoint looks the user up and branches on the result before "
                    "ever checking the password:\n\n"
                    "```python\nuser = find_user(username)\n"
                    "if not user:\n    return 'No account found with that username.'\n"
                    "if user.password != password:\n    return 'Incorrect password.'\n```\n\n"
                    "The two branches are distinguishable from the outside, so the "
                    "attacker learns which accounts exist without any credentials."
                ),
                attacker=(
                    "1. Request a username that is very unlikely to exist.\n"
                    "2. Request a username you know exists (the lab tells you the "
                    "accounts).\n"
                    "3. Compare the two responses. If they differ, you have an oracle.\n"
                    "4. Automate the check over a wordlist to build a list of real "
                    "accounts — target the ones whose names look like senior staff."
                ),
                why=(
                    "The failure path leaks an internal fact (does this row exist?) "
                    "that the client had no need to know. Enumeration is usually "
                    "rated low on its own, but it is the multiplier that makes every "
                    "other credential attack cheaper."
                ),
                fix=(
                    "- Return one message, one status code, and a comparable body for "
                    "every credential failure.\n"
                    "- Perform the password check unconditionally, against a dummy hash "
                    "when the user does not exist, so the code path is also uniform.\n"
                    "- Return the same redirect for success and failure if you want to "
                    "avoid a post-login enumeration surface.\n"
                    "- Never reveal *\"this address is registered*\" on signup, "
                    "recover, or change-username flows either."
                ),
                detect=(
                    "- Log failed authentications with a `reason` code that is "
                    "internal only.\n"
                    "- Alert when one source IP enumerates many distinct usernames "
                    "and gets a consistent response shape — a high rate of "
                    "*distinct-username* failures is the signature, not volume.\n"
                    "- Alert on a small number of *successful* logins to many different "
                    "accounts from one source (the real harm of enumeration)."
                ),
                real=(
                    "Username lists feed credential stuffing, targeted phishing, and "
                    "spear-phishing pretexting. Sites that enumerate on the login form "
                    "very often enumerate on the forgot-password form too — always "
                    "test both."
                ),
            ),
            objectives=[
                "Identify that a login endpoint discloses account existence",
                "Explain why generic, uniform failure responses remove the oracle",
            ],
            hints=[
                "Log in twice: once with a username that does not exist, once with one "
                "of the accounts the page lists. Read both error messages carefully.",
                "The two responses are not random. Try the same wrong password against "
                "a real and a fake user and diff the messages word by word.",
                "Use Burp: send the request to Repeater twice, one real username and "
                "one fake, and compare the response bodies in the two tabs.",
                "The correct flag appears on the account page for a user you have "
                "successfully identified. Enumeration alone is not the goal — confirm "
                "the user exists, then move on to the next lab for the full attack.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Note the accounts mentioned on the page: `alice`, `bob`, `carol`.\n"
                "2. In Burp, intercept the login form and send a request to Repeater.\n"
                "3. Request A (unknown user):\n"
                "   ```http\n   POST /login\n   \n"
                "   username=nosuchuser&password=wrong\n   ```\n"
                "   Response: `No account found with that username.`\n"
                "4. Request B (known user, wrong password):\n"
                "   ```http\n   POST /login\n   \n"
                "   username=carol&password=wrong\n   ```\n"
                "   Response: `Incorrect password.`\n"
                "5. The two messages differ, so the form reveals account existence. "
                "Any wordlist run against `/login` now yields a reliable user list.\n\n"
                "**Why it works** — the handler branches on the lookup result and "
                "returns early, so the response body encodes whether the row exists. "
                "Uniform failure responses close the oracle."
            ),
            methodology=(
                "Compare the response for a known-good username with the response for a "
                "guaranteed-absent one, looking at status, headers, body text, and body "
                "length. Then automate across a username wordlist."
            ),
            credentials=(
                "No credentials needed. The page names three accounts: `alice`, `bob`, "
                "`carol`."
            ),
            endpoints="GET / · POST /login · POST /reset · GET /healthz",
            behaviour=(
                "An unknown username returns 'No account found with that username.' A "
                "known username with a wrong password returns 'Incorrect password.'"
            ),
            success=(
                "Establish that the two failures are distinguishable and identify which "
                "of the listed accounts exist."
            ),
            remediation=(
                "Return a single generic failure response for all credential failures."
            ),
            detection=(
                "Alert on one source enumerating many distinct usernames, and on many "
                "successful logins for different accounts from one source."
            ),
            references=[PS_ENUM, PS_KNOW],
            lab_family=LOGIN,
            lab_variant="enum_response",
            sort_order=1,
        ),
        lesson(
            "auth-enum-subtle",
            "Subtly different enumeration signals",
            category="Credentials & Enumeration",
            summary=(
                "Identical wording, but a different status code and a different "
                "body length give the oracle away."
            ),
            scenario=(
                "The Northwind Retail login page now returns the same error text for "
                "every failure — a good start. Determine whether account existence is "
                "still disclosed."
            ),
            theory=_theory(
                what=(
                    "**Subtle enumeration.** The application returns the same human-readable "
                    "message for unknown users and for wrong passwords, but the machine-readable "
                    "signals still differ. Any of these is enough: an HTTP status code, a body "
                    "length, a response header, a cookie, or a redirect."
                ),
                normal=(
                    "For any bad credential combination the response should be "
                    "byte-for-byte identical.\n\n"
                    "```http\nPOST /login\nusername=carol&password=wrong\n```\n\n"
                    "```http\nHTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 2143\n\n"
                    "<p class='err'>Invalid credentials.</p>\n```\n\n"
                    "The unknown-username case returns the exact same status, headers and body."
                ),
                wrong=(
                    "In this lab the wording is identical but:\n\n"
                    "- an unknown username returns **404**, a known user returns **200**;\n"
                    "- the wrong-password response carries an extra trailing comment, so its "
                    "body is **longer**.\n\n"
                    "```python\nif not user:\n    return body, 404\n"
                    "if user.password != password:\n    return body + '<!-- auth-service: ... -->', 200\n```"
                ),
                attacker=(
                    "1. Send a request with a random username. Note status and body length.\n"
                    "2. Send one with a real username. Note status and body length.\n"
                    "3. A status or length difference is a working oracle even though the "
                    "text is identical.\n"
                    "4. For scripting, use response length as the signal — it is often "
                    "the only difference an automated tool can rely on."
                ),
                why=(
                    "Matching the visible message is only half of the job. The status "
                    "line, the `Content-Length` header and any dynamic fragment are all "
                    "part of the observable response, and they are exactly what automated "
                    "tooling reads."
                ),
                fix=(
                    "- Use one status code for every authentication failure.\n"
                    "- Return a body generated by the same code path for both cases.\n"
                    "- Ensure no timing difference: do the hash comparison even when the "
                    "user does not exist (compare against a fixed dummy hash).\n"
                    "- Test with a response-diffing tool; eyeballing the message is not "
                    "enough to prove uniformity."
                ),
                detect=(
                    "- Record status + response length in auth failure logs; alert on a "
                    "source whose failure status codes cluster on two distinct values.\n"
                    "- Add a regression test that asserts both cases return identical "
                    "status, headers and body length."
                ),
                real=(
                    "This is the most common real-world enumeration pattern because "
                    "teams fix the copy but not the status code. A 404 vs 200 difference is "
                    "trivially automatable and is often what credential-stuffing tooling "
                    "keys on."
                ),
            ),
            objectives=[
                "Detect enumeration that is invisible in the message text",
                "Use status code and response length as enumeration signals",
            ],
            hints=[
                "Ignore the message text. Compare the status line at the top of each "
                "response, and compare the `Content-Length` header.",
                "A 404 for one username and a 200 for another is your signal, even "
                "though both say 'Invalid credentials'.",
                "In Burp, put both responses in separate Repeater tabs and turn on "
                "'Highlight differences' in the response viewer, or compare lengths in "
                "the bottom bar.",
                "Confirm the difference on a second username pair to be sure it is not a "
                "coincidence, then move on.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Send to Repeater:\n"
                "   ```http\n   POST /login\n   Content-Type: application/x-www-form-urlencoded\n"
                "   \n   username=nosuchuser&password=wrong\n   ```\n"
                "   Observe: `HTTP/1.1 404 Not Found`, `Content-Length: 1893`.\n"
                "2. Send again with a real user:\n"
                "   ```http\n   POST /login\n   Content-Type: application/x-www-form-urlencoded\n"
                "   \n   username=carol&password=wrong\n   ```\n"
                "   Observe: `HTTP/1.1 200 OK`, `Content-Length: 1934`.\n"
                "3. The bodies both read 'Invalid credentials.', but the status code and "
                "the length differ, so the account is still enumerable.\n\n"
                "**Why it works** — the handler returns a 404 before reaching the shared "
                "render path, and appends a diagnostic comment on the other branch. "
                "Uniform status + uniform body removes the signal."
            ),
            methodology=(
                "Diff the full response — status line, headers, and body length — between a "
                "known and an unknown username, ignoring the visible text."
            ),
            credentials=(
                "No credentials needed. Accounts referenced on the page: `alice`, `bob`, "
                "`carol`."
            ),
            endpoints="GET / · POST /login · GET /healthz",
            behaviour=(
                "Both failures say 'Invalid credentials.' Unknown usernames return 404 "
                "with a shorter body; known usernames return 200 with a slightly longer "
                "body."
            ),
            success=(
                "Identify the status-code or body-length difference that discloses "
                "account existence."
            ),
            remediation=(
                "Return an identical status code, headers, and body length for every "
                "authentication failure."
            ),
            detection=(
                "Log status and response length on failures; alert when one source's "
                "failures cluster on two distinct status codes."
            ),
            references=[PS_ENUM, PS_KNOW],
            lab_family=LOGIN,
            lab_variant="enum_subtle",
            sort_order=2,
        ),
        lesson(
            "auth-enum-timing",
            "Timing-based account enumeration",
            category="Credentials & Enumeration",
            summary=(
                "The responses are identical — but the server takes dramatically "
                "longer to reject a real username than a fake one."
            ),
            scenario=(
                "Northwind Retail's login page returns byte-identical responses for "
                "every failure and no status or length difference. Determine whether "
                "account existence can still be recovered."
            ),
            theory=_theory(
                what=(
                    "**Timing-based enumeration.** When an application returns early for "
                    "unknown users but performs work (a password hash comparison) for real "
                    "users, the response time becomes the oracle. A memory-hard hash costs "
                    "tens of milliseconds on purpose; skipping it is trivially measurable."
                ),
                normal=(
                    "Both branches must do the same work:\n\n"
                    "```python\nDUMMY = b'$2b$12$...'  # a real hash of a random value\n"
                    "def login(username, password):\n"
                    "    user = find_user(username) or DUMMY_USER\n"
                    "    ok = bcrypt.checkpw(password.encode(), user.hash)  # always runs\n"
                    "    if not ok or user is DUMMY_USER:\n"
                    "        return generic_error()\n"
                    "    return success()\n```\n\n"
                    "Now both cases cost roughly the same wall-clock time."
                ),
                wrong=(
                    "In this lab the handler sleeps on the *existing user* branch only:\n\n"
                    "```python\nrow = find_user(username)\n"
                    "time.sleep(0.45 if row else 0.02)\n"
                    "if not row or row.password != password:\n"
                    "    return generic_error()\n```"
                ),
                attacker=(
                    "1. Establish a baseline: send N requests for a random username and "
                    "record the median response time.\n"
                    "2. Send N requests for a candidate username and record the median.\n"
                    "3. If the medians separate consistently (and they will — the "
                    "difference here is ~430 ms, not noise), you have an oracle.\n"
                    "4. Only compare medians or means over many samples. A single "
                    "request is dominated by network jitter."
                ),
                why=(
                    "The delay is an intentional stand-in for the password check, but any "
                    "code path that does strictly more work for a known user leaks the "
                    "same information. Network jitter means you need many samples, but "
                    "the separation between a `bcrypt` compare and nothing is far larger "
                    "than jitter."
                ),
                fix=(
                    "- Always perform the password verification, using a dummy hash when "
                    "the username is unknown.\n"
                    "- Keep the work uniform *and* the code path uniform; a branch that "
                    "skips a query is also a branch.\n"
                    "- Add a small fixed jitter to the failure response to widen the noise "
                    "band — this helps but is not a substitute for uniform work.\n"
                    "- Do not use `sleep()` as rate limiting; use real rate limiting."
                ),
                detect=(
                    "- Record per-request latency server-side, keyed by whether the "
                    "username existed (internal field only).\n"
                    "- Alert when a source submits many distinct usernames whose response "
                    "latency clusters into two groups — a bimodal distribution across a "
                    "*username* sweep is the tell.\n"
                    "- Front-end timing is not a reliable detection signal on its own."
                ),
                real=(
                    "Timing oracles are common in frameworks where the ORM short-circuits: "
                    "`User.objects.filter(email=x).first()` returning `None` early versus "
                    "hashing a password. They are also the basis of blind SQL injection, so "
                    "an unexpected timing signal is worth investigating further."
                ),
            ),
            objectives=[
                "Measure response time reliably enough to distinguish a real delay from "
                "network jitter",
                "Fix a timing oracle by making the work uniform",
            ],
            hints=[
                "The bodies are identical this time. Stop looking at the response and "
                "look at how long it takes to arrive.",
                "Send about ten requests for a random username and ten for `carol`, then "
                "compare the averages. One request each will be misleading.",
                "In Burp use the search box in the proxy history and read the 'Time' "
                "column, or write a small script that times each request and prints the "
                "median for both usernames.",
                "If the two usernames separate by hundreds of milliseconds across many "
                "samples, the oracle is confirmed. Note the technique, then continue to "
                "the brute-force labs.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Pick two usernames: a random one and `carol`.\n"
                "2. Time 10 requests each, e.g. with a small script:\n"
                "   ```python\n"
                "   import time, httpx\n"
                "   for user in ('nosuchuser', 'carol'):\n"
                "       times = []\n"
                "       for _ in range(10):\n"
                "           t = time.perf_counter()\n"
                "           httpx.post(BASE + '/login',\n"
                "                       data={'username': user, 'password': 'x'})\n"
                "           times.append(time.perf_counter() - t)\n"
                "       print(user, sorted(times)[5])\n"
                "   ```\n"
                "3. Observe: `nosuchuser` median ~0.05 s, `carol` median ~0.50 s. The "
                "~450 ms gap is far outside network jitter, so the account exists.\n"
                "4. Run the username wordlist through the same measurement to enumerate "
                "real accounts.\n\n"
                "**Why it works** — the handler sleeps 450 ms only when the user lookup "
                "succeeded, and 20 ms otherwise. Doing the real `bcrypt` comparison in "
                "both branches (against a dummy hash when the user is absent) equalises "
                "the timing."
            ),
            methodology=(
                "Measure median response latency over many samples for a known-valid and a "
                "known-absent username; a consistent gap larger than the jitter band is a "
                "timing oracle."
            ),
            credentials="No credentials needed. Accounts: `alice`, `bob`, `carol`.",
            endpoints="GET / · POST /login · GET /healthz",
            behaviour=(
                "Every failure returns the identical body and status. Responses for an "
                "existing username are roughly 450 ms slower than for a non-existent one."
            ),
            success=(
                "Demonstrate a consistent response-time difference between an existing "
                "and a non-existent account."
            ),
            remediation=(
                "Always perform the password verification, using a dummy hash when the "
                "username is unknown, so both branches cost the same."
            ),
            detection=(
                "Alert when a username sweep produces a bimodal latency distribution from "
                "a single source."
            ),
            references=[PS_ENUM, PS_KNOW],
            lab_family=LOGIN,
            lab_variant="enum_timing",
            sort_order=3,
        ),
        lesson(
            "auth-enum-lock",
            "Account lockout as an enumeration oracle",
            category="Credentials & Enumeration",
            summary=(
                "Per-account lockout means a successful guess attempt changes the "
                "state of that account — which tells you the account exists."
            ),
            scenario=(
                "Northwind Retail locks an account after repeated failed logins. Use "
                "that behaviour to work out which usernames are real. **Do not lock "
                "any account other than the ones provided for this lab.**"
            ),
            theory=_theory(
                what=(
                    "**State-based enumeration.** Lockout is per account, so it can only "
                    "be triggered for accounts that exist. The transition from 'invalid "
                    "credentials' to 'account locked' is therefore an existence oracle. This "
                    "is the reason naive lockout is worse than no lockout at all: it hands "
                    "an attacker a *reliable, free* way to test usernames, and it hands them a "
                    "denial-of-service against any victim they can name."
                ),
                normal=(
                    "Rate limiting should be **source-based** and applied uniformly, and the "
                    "lockout message should be identical for every failure:\n\n"
                    "```python\n"
                    "rate_limit(source_ip, 'login', limit=10, window=300)\n"
                    "if not verify(username, password):\n"
                    "    return generic_error()   # same for unknown and known users\n"
                    "```"
                ),
                wrong=(
                    "```python\nn = failures_for(username)\n"
                    "if n >= 3:\n    return 'Account locked due to failed logins.', 429\n"
                    "if not verify(username, password):\n"
                    "    record_failure(username)\n"
                    "    return 'Invalid credentials.', 200\n```\n\n"
                    "The 429 and its message appear only for accounts that exist, so three "
                    "attempts against a candidate username confirms it exists."
                ),
                attacker=(
                    "1. Send 3–4 failed logins for a candidate username.\n"
                    "2. If the response changes to a lockout message or 429, the account "
                    "exists. If it stays 'Invalid credentials.', it does not.\n"
                    "3. Repeat for a wordlist. You now have a user list *and* a denial-of-"
                    "service against anyone you name.\n"
                    "4. This is the trade-off to remember: lockout buys brute-force "
                    "resistance at the price of enumeration plus DoS."
                ),
                why=(
                    "Rate limiting that is keyed on something the attacker does not fully "
                    "control (their source address) and that returns a distinguishable "
                    "response is a trade, not a win. The enumeration is a side effect of "
                    "state being per-account."
                ),
                fix=(
                    "- Prefer **source-based** throttling plus **soft** progressive delays "
                    "over hard per-account lockout.\n"
                    "- If you do lock per account, never tell the user they are locked on a "
                    "login response — return the generic error and enforce internally.\n"
                    "- Cap lockout by a *trusted* source attribute, not a client header.\n"
                    "- Provide an automatic unlock/expiry so a DoS does not persist, and a "
                    "verified self-service recovery path.\n"
                    "- Alert on lockouts of high-value accounts; that pattern is either an "
                    "attack or a user in trouble."
                ),
                detect=(
                    "- Alert on any account lockout (rare enough to be signal), "
                    "especially for admin/privileged accounts.\n"
                    "- Alert when one source causes lockouts across many different "
                    "accounts — that is a DoS pattern, not credential guessing.\n"
                    "- Correlate lockouts with source IP and with subsequent successful "
                    "logins from elsewhere."
                ),
                real=(
                    "Lockout-based enumeration is why many large sites still leak user "
                    "existence despite uniform error messages. It also enables a cheap "
                    "denial of service: repeatedly failing a known-privileged username locks "
                    "the CEO out."
                ),
            ),
            objectives=[
                "Use a per-account state change to determine whether an account exists",
                "Explain the enumeration-versus-lockout trade-off",
            ],
            hints=[
                "The error text changes after a few failed attempts — but only for some "
                "usernames. Try the same small number of failures against two different "
                "usernames and compare.",
                "Submit three or four wrong passwords for a candidate username. Then do "
                "the same for a random one. One of them changes behaviour.",
                "In Repeater, send the request several times for `carol` and watch the "
                "status code, then repeat with a made-up username and compare.",
                "A `429` response that only ever appears for real accounts is your oracle. "
                "Note the DoS implication, then move on.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Send three failed logins for a real account:\n"
                "   ```http\n   POST /login\n   \n   username=carol&password=wrong1\n   ```\n"
                "   (repeat with `wrong2`, `wrong3`)\n"
                "2. The fourth response is:\n"
                "   ```http\n   HTTP/1.1 429 Too Many Requests\n   ...\n"
                "   <p class='err'>Account locked due to failed logins.</p>\n   ```\n"
                "3. Do the same for `nosuchuser`. Every response stays "
                "`Invalid credentials.` with status 200 — it never locks, because the "
                "lock counter is only written for accounts that exist.\n"
                "4. Conclusion: the presence of the lockout proves existence. The same "
                "mechanism also lets an attacker lock any named account on demand.\n\n"
                "**Why it works** — the failure counter is keyed on username, so the "
                "state transition is only reachable for real accounts, and the 429 + "
                "lockout message is a distinguishable response. Source-based throttling "
                "with a uniform error removes the oracle."
            ),
            methodology=(
                "Submit a fixed small number of failed logins per candidate username and "
                "compare the responses; a lockout message or 429 that only appears for real "
                "accounts is the oracle."
            ),
            credentials=(
                "No valid credentials needed. Accounts: `alice`, `bob`, `carol`. Test only "
                "these — this lab intentionally locks them."
            ),
            endpoints="GET / · POST /login · GET /healthz",
            behaviour=(
                "After 3 failed attempts for a real username, responses become HTTP 429 "
                "with an 'Account locked' message. Non-existent usernames never lock."
            ),
            success=(
                "Trigger the lockout for a real account and show that a non-existent "
                "username does not produce it."
            ),
            remediation=(
                "Use source-based throttling and soft progressive delays; never reveal "
                "lockout state on the login response."
            ),
            detection=(
                "Alert on any account lockout, and on one source locking many different "
                "accounts."
            ),
            references=[PS_ENUM, PS_KNOW],
            lab_family=LOGIN,
            lab_variant="enum_lock",
            sort_order=4,
        ),
        lesson(
            "auth-brute-unlimited",
            "Brute-forcing a login with no rate limit",
            difficulty="practitioner",
            category="Brute Force",
            summary=(
                "The login endpoint has no rate limit, no lockout, no delay and no "
                "CAPTCHA — the only control is the strength of the password."
            ),
            scenario=(
                "Northwind Retail's employee login accepts as many attempts as you "
                "send it. `bob` picked a weak password. Recover it."
            ),
            theory=_theory(
                what=(
                    "**Missing brute-force protection.** Every control that would make "
                    "online guessing expensive is absent: no per-account rate limit, no "
                    "lockout, no increasing delay, no CAPTCHA, and no monitoring. The "
                    "endpoint returns the same generic error for every failure, which "
                    "removes the usual excuse that \"the app is protecting itself\"."
                ),
                normal=(
                    "A login endpoint stacks layered controls, any one of which breaks "
                    "a naive attack:\n\n"
                    "```python\n"
                    "@app.post('/login')\n"
                    "def login():\n"
                    "    user = lookup(request.form['username'])\n"
                    "    if not user:\n"
                    "        sleep(0.5)                       # equalise timing\n"
                    "        return generic_error()\n"
                    "    ok = check_password(user, request.form['password'])\n"
                    "    if not ok:\n"
                    "        record_failure(user.id)            # per-account counter\n"
                    "        if failures(user.id, window='15m') > 5:\n"
                    "            raise Locked()                 # cool-off + alert\n"
                    "        sleep(0.25 * failures(user.id))     # back-off\n"
                    "        return generic_error()\n"
                    "    clear_failures(user.id)\n"
                    "    login(user)\n"
                    "```\n\n"
                    "The second factor, MFA, and a breached-password check at "
                    "enrolment all reduce the value of guessing in the first place."
                ),
                wrong=(
                    "```python\n"
                    "@app.post('/login')\n"
                    "def login():\n"
                    "    user = lookup(request.form['username'])\n"
                    "    if not user or user.password != request.form['password']:\n"
                    "        return 'Invalid credentials.', 200\n"
                    "    login(user)\n"
                    "```\n\n"
                    "No state is kept between requests, so nothing accumulates and no "
                    "threshold can ever be crossed. The endpoint is a pure function, "
                    "which is also what makes it so cheap to hammer."
                ),
                attacker=(
                    "1. Confirm there is no penalty: send the same wrong password 50 "
                    "times. Every response is `200` with `Invalid credentials.`, and "
                    "there is never a `429`.\n"
                    "2. Send 50 *correct-for-someone-else* attempts and confirm the "
                    "account is still usable afterwards — a lockout would have "
                    "impaired your own target.\n"
                    "3. Run a password list against the target account, one request "
                    "each, stopping on the `200` that returns the account page:\n"
                    "   ```python\n"
                    "   import httpx\n"
                    "   for pw in open('rockyou-75.txt'):\n"
                    "       pw = pw.strip()\n"
                    "       r = httpx.post(BASE + '/login',\n"
                    "                       data={'username': 'bob', 'password': pw})\n"
                    "       if 'Signed in as' in r.text:\n"
                    "           print('password =', pw); break\n"
                    "   ```\n"
                    "4. Size the list to the window you have. A few hundred common "
                    "passwords covers most real accounts; thousands still takes "
                    "seconds against an unthrottled endpoint."
                ),
                why=(
                    "Rate limiting is the only thing standing between an unthrottled "
                    "endpoint and a dictionary attack, and it has been omitted "
                    "entirely. The password's entropy is doing the work alone — and "
                    "human-chosen passwords average far less entropy than people "
                    "believe, which is what turns a fast server into a cracked "
                    "account."
                ),
                fix=(
                    "- Rate-limit failed authentications **per account** (a handful per "
                    "15 minutes), not per source address — a rotating-IP attacker "
                    "beats per-IP limits, and a shared NAT makes per-IP limits unfair.\n"
                    "- Add exponential back-off and a lockout with a cool-off period "
                    "and an out-of-band notification to the real account owner.\n"
                    "- Make the unknown-user and wrong-password paths cost the same, so "
                    "nothing leaks through timing.\n"
                    "- Reject any password found in a breached-password corpus at "
                    "enrolment and change time.\n"
                    "- Alert on failure-rate spikes and on any single account "
                    "accumulating failures across many sources.\n"
                    "- Offer MFA, which removes password guessing from the attack path "
                    "entirely."
                ),
                detect=(
                    "- Alert when failures per account exceed a small threshold in a "
                    "window, and on a global failure-rate spike.\n"
                    "- Alert on a source that never succeeds but keeps submitting — a "
                    "pure enumeration or guessing pattern.\n"
                    "- Log the username alongside the failure; a rate limit keyed only "
                    "on IP cannot see a distributed attempt against one account.\n"
                    "- Track *failure rate*, not request volume: a busy but successful "
                    "user and a silent attacker look identical on volume alone."
                ),
                real=(
                    "Unthrottled login endpoints remain common on internal tools, "
                    "forgotten admin panels, self-hosted instances and legacy "
                    "software that shipped before rate limiting became a default "
                    "framework feature. The bug bounty finding is usually trivial to "
                    "demonstrate and uncontentious: 30 requests, a count, and a "
                    "screenshot of 30 identical failures."
                ),
            ),
            objectives=[
                "Recognise a login endpoint with no attempt budget at all",
                "Rate-limit failed authentication per account, with back-off",
            ],
            hints=[
                "Before you run a wordlist, find out what the app does when you are "
                "wrong. Send the same bad password twenty times and read every "
                "response.",
                "If you never see a 429, never get a delay, and the wording never "
                "changes, there is no attempt budget to exhaust. The wordlist is the "
                "hard part, not the lockout.",
                "The account page is the signal — a successful login returns "
                "`Signed in as bob` and the flag, not an error paragraph.",
                "Run a small list first (the hundred most common passwords) and stop "
                "on the first response containing `Signed in as`. Keep the request "
                "serial; there is no need for concurrency here.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Establish that nothing accumulates. Repeat the same failing "
                "request and count the responses:\n"
                "   ```http\n   POST /login\n   "
                "Content-Type: application/x-www-form-urlencoded\n   \n"
                "   username=bob&password=wrong\n   ```\n"
                "   Every iteration returns `200 OK` with `Invalid credentials.`, the "
                "body is byte-identical, and the response time does not grow. No "
                "`429`, no lockout, no CAPTCHA after any number of attempts.\n"
                "2. Brute force with a password list:\n"
                "   ```python\n   import httpx\n   "
                "BASE = 'http://<lab-address>'\n   \n"
                "   for pw in open('rockyou-75.txt'):\n"
                "       pw = pw.strip()\n"
                "       r = httpx.post(BASE + '/login',\n"
                "                       data={'username': 'bob', 'password': pw},\n"
                "                       timeout=10)\n"
                "       if 'Signed in as' in r.text:\n"
                "           print('password =', pw)\n"
                "           break\n"
                "   ```\n"
                "3. The response for the winning password is the account page, which "
                "contains the flag.\n\n"
                "**Why it works** — the handler is a pure function of the request. "
                "There is no `attempts` table, no counter, no `429` branch and no "
                "delay, so the endpoint's cost to the attacker is bounded only by "
                "network latency. A correct password is found by trying passwords, "
                "which is precisely what rate limiting exists to prevent."
            ),
            methodology=(
                "Test whether failed authentication has any consequence before "
                "spending time on a wordlist: repeat one failing request enough times "
                "to cross any sane threshold and look for a status-code change, a "
                "wording change, or latency growth. If none appears, the attempt "
                "budget is effectively unlimited and the attack reduces to throughput, "
                "so size the wordlist to your window and run it serially."
            ),
            credentials=(
                "Target: `bob`, whose password is weak. Accounts: `alice`, `bob`, "
                "`carol`."
            ),
            endpoints="GET / · POST /login · GET /healthz",
            behaviour=(
                "`POST /login` accepts unlimited attempts: no rate limit, no lockout, "
                "no delay, no CAPTCHA, and the same generic `Invalid credentials.` "
                "error for every failure."
            ),
            success=(
                "Brute force `bob`'s password and reach the account page to retrieve "
                "the flag."
            ),
            remediation=(
                "Rate-limit failed authentications per account with exponential "
                "back-off and a lockout that alerts the account owner, equalise the "
                "unknown-user and wrong-password paths, and check new passwords "
                "against a breached-password corpus."
            ),
            detection=(
                "Alert on failures per account exceeding a small threshold, on a "
                "global failure-rate spike, and on sources that never succeed but "
                "keep submitting."
            ),
            references=[
                PS_BRUTE,
                PS_RATELIMIT,
                PS_KNOW,
            ],
            lab_family=LOGIN,
            lab_variant="brute_unlimited",
            sort_order=5,
        ),
        lesson(
            "auth-brute-ipblock",
            "Bypassing brute-force protection with IP spoofing",
            difficulty="practitioner",
            category="Brute Force",
            summary=(
                "Login is blocked after a few attempts per IP — but the block trusts "
                "an `X-Forwarded-For` header you control."
            ),
            scenario=(
                "Northwind Retail throttles login: three wrong attempts and you are "
                "blocked. Show that the protection can be bypassed without valid "
                "credentials. `bob` uses a weak password."
            ),
            theory=_theory(
                what=(
                    "**Rate-limit bypass via a trusted client header.** The blocklist is keyed "
                    "on the source address, but the address is read from `X-Forwarded-For` — a "
                    "header any client can set. The protection therefore counts attempts per "
                    "*header value* rather than per attacker, and is trivially reset."
                ),
                normal=(
                    "The application must resolve the real source from the connection, and only "
                    "trust proxy headers when the immediate peer is a known proxy:\n\n"
                    "```python\n"
                    "def client_ip(request):\n"
                    "    peer = request.remote_addr\n"
                    "    if peer not in TRUSTED_PROXIES:\n"
                    "        return peer                      # header ignored\n"
                    "    return last_entry(request.headers.get('X-Forwarded-For'))\n"
                    "```\n\n"
                    "Or, better, terminate rate limiting at the edge (WAF / gateway) where "
                    "the real peer address is always known."
                ),
                wrong=(
                    "```python\nip = request.headers.get('X-Forwarded-For', request.remote_addr)\n"
                    "n = attempts_for(ip)\n"
                    "if n >= 3:\n    return 'Locked', 429\n"
                    "```\n\n"
                    "No trust check. Every request with a fresh header value gets a fresh "
                    "budget."
                ),
                attacker=(
                    "1. Confirm the block: send three wrong passwords for `bob` and watch "
                    "for the 429.\n"
                    "2. Change the `X-Forwarded-For` value and send the same request — the "
                    "counter resets.\n"
                    "3. Automate: iterate a password list, sending a new "
                    "`X-Forwarded-For` per request. The rate limit never engages.\n"
                    "4. Related header names to check: `X-Real-IP`, `X-Client-IP`, "
                    "`True-Client-IP`, `CF-Connecting-IP`, `Forwarded`."
                ),
                why=(
                    "The server confuses a *claim about* the client with the client's actual "
                    "address. Header-based client IP is only trustworthy when the peer is a "
                    "proxy you control and you strip the header before it reaches the app."
                ),
                fix=(
                    "- Derive the client address from the connection, not from a request "
                    "header.\n"
                    "- Only honour forwarding headers when `remote_addr` is in an explicit "
                    "proxy allow-list, and take only the last hop.\n"
                    "- Strip inbound `X-Forwarded-For` at the edge before proxying to the "
                    "app.\n"
                    "- Rate-limit on **account** as well as source, so header rotation does "
                    "not help.\n"
                    "- Add a global per-account ceiling independent of any source metric."
                ),
                detect=(
                    "- Alert on high volume of login requests carrying "
                    "`X-Forwarded-For`/`X-Real-IP` from untrusted paths — a normal browser "
                    "does not need to set these.\n"
                    "- Alert when a single account accumulates failures across many distinct "
                    "client-IP values.\n"
                    "- Log both the peer address and the claimed header value so the "
                    "discrepancy is visible."
                ),
                real=(
                    "This is a widespread configuration mistake, especially where a CDN or "
                    "load balancer sits in front of the app. It appears in bug bounty "
                    "reports constantly because the fix is often a one-line change in the "
                    "trusted-proxy list."
                ),
            ),
            objectives=[
                "Bypass a per-IP rate limit by rotating a client-supplied header",
                "Identify all the header names commonly trusted for client IP",
            ],
            hints=[
                "The lock counter is per IP address. Find out which header the server uses "
                "to decide what your IP address is.",
                "Look at the login request in Burp. Try adding an `X-Forwarded-For` header "
                "with an arbitrary value and see whether the lock still applies.",
                "In Repeater, send three failures to trigger the lock, then send the "
                "fourth with a new `X-Forwarded-For: 10.9.9.9`. If it is accepted, you "
                "have a fresh budget.",
                "`bob`'s password is weak. Run a small password list with a rotating "
                "`X-Forwarded-For` per request and confirm the flag on the account page.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Trigger the block:\n"
                "   ```http\n   POST /login\n   X-Forwarded-For: 10.0.0.1\n   \n"
                "   username=bob&password=wrong\n   ```\n"
                "   Repeat three times. The fourth returns:\n"
                "   ```http\n   HTTP/1.1 429 Too Many Requests\n"
                "   <p class='err'>Account temporarily locked...</p>\n   ```\n"
                "2. Now send the same request with a different claimed address:\n"
                "   ```http\n   POST /login\n   X-Forwarded-For: 203.0.113.77\n   \n"
                "   username=bob&password=wrong\n   ```\n"
                "   Response: `200 OK` — `Invalid credentials.` The counter is fresh.\n"
                "3. Automate the reset:\n"
                "   ```python\n"
                "   for i, pw in enumerate(wordlist):\n"
                "       r = httpx.post(BASE + '/login',\n"
                "                        headers={'X-Forwarded-For': f'198.51.100.{i}'},\n"
                "                        data={'username': 'bob', 'password': pw})\n"
                "       if 'Account notes' in r.text:\n"
                "           print('found', pw); break\n"
                "   ```\n"
                "4. Read the flag from the account page.\n\n"
                "**Why it works** — `request.headers.get('X-Forwarded-For', "
                "request.remote_addr)` trusts the header unconditionally, so the rate limit "
                "is per *claimed* address. Only honour the header when the immediate peer is "
                "a known proxy, and rate-limit per account as well."
            ),
            methodology=(
                "Trigger the block, then vary the client-IP header the application trusts "
                "and confirm the counter resets. Automate a password list with a fresh "
                "header value per request."
            ),
            credentials=(
                "Target account: `bob` (weak password). Other accounts: `alice`, `carol`."
            ),
            endpoints="GET / · POST /login · GET /healthz",
            behaviour=(
                "Login blocks after 3 failures for a given X-Forwarded-For value, but the "
                "value is taken from the request with no trust check."
            ),
            success=(
                "Bypass the block by rotating X-Forwarded-For, then authenticate as `bob` "
                "to retrieve the flag."
            ),
            remediation=(
                "Resolve the client IP from the connection, honour forwarding headers only "
                "from trusted proxies, and rate-limit per account as well as per source."
            ),
            detection=(
                "Alert on login traffic carrying X-Forwarded-For from untrusted paths, and "
                "on failures for one account spread across many client IPs."
            ),
            references=[PS_BRUTE, PS_KNOW],
            lab_family=LOGIN,
            lab_variant="brute_ipblock",
            sort_order=6,
        ),
        lesson(
            "auth-brute-multipass",
            "Multiple credential attempts in a single request",
            difficulty="practitioner",
            category="Brute Force",
            summary=(
                "The login endpoint accepts a JSON array of credential pairs and "
                "reports which one worked — so one request is N attempts, and a control that "
                "counts requests is not a control."
            ),
            scenario=(
                "Northwind Retail's login accepts a whole array of credential pairs in one "
                "request. Show what that does to any per-request control, and use it to get in "
                "as `bob`, who has a weak password."
            ),
            theory=_theory(
                what=(
                    "**Batch authentication as a brute-force amplifier.** If an endpoint accepts "
                    "an array of credentials and validates them server-side, then one HTTP request "
                    "per *account* but many attempts per *request*. Any rate limit counted in "
                    "requests is now counted once per batch."
                ),
                normal=(
                    "A login endpoint authenticates exactly one principal per request. Bulk "
                    "operations (if any) verify a single authenticated actor's authorisation, "
                    "they do not accept a list of passwords:\n\n"
                    "```python\n"
                    "@app.post('/login')\n"
                    "def login():\n"
                    "    user = authenticate(username, password)   # one pair, one check\n"
                    "```"
                ),
                wrong=(
                    "```python\n"
                    "for attempt in json.loads(request.form['username']):\n"
                    "    user = authenticate(attempt['username'], attempt['password'])\n"
                    "    if user:\n"
                    "        return success(user)\n"
                    "return generic_error()\n```\n\n"
                    "One request can try hundreds of passwords. The rate limiter sees one "
                    "request, and the response tells you which attempt succeeded."
                ),
                attacker=(
                    "1. Detect the batch format. In this lab it is signalled by a username "
                    "field starting with `[`.\n"
                    "2. Send one request containing an array of attempts:\n"
                    "   ```http\n"
                    "   POST /login\n"
                    "   Content-Type: application/x-www-form-urlencoded\n"
                    "   \n"
                    "   username=[{\"username\":\"bob\",\"password\":\"a\"},"
                    "   {\"username\":\"bob\",\"password\":\"b\"}]\n   ```\n"
                    "3. Look for the response that renders the account page — that is the "
                    "successful attempt.\n"
                    "4. Scale the array size up until you hit a payload limit, then batch "
                    "your wordlist across requests.\n"
                    "5. Generalise: a differing *response* per attempt is also an oracle "
                    "even when only the last one succeeds."
                ),
                why=(
                    "Rate limiting is usually implemented at the HTTP layer, counting "
                    "requests. It has no notion of how many authentication *decisions* a "
                    "single request contains, so batching moves the work outside the limiter's "
                    "unit of account."
                ),
                fix=(
                    "- Accept exactly one credential set per authentication request.\n"
                    "- Reject array or nested object types for credential fields with a "
                    "schema validator.\n"
                    "- Rate-limit and lock on **failed authentication decisions*, not on "
                    "HTTP requests.\n"
                    "- Cap request body size and reject oversized payloads early.\n"
                    "- Where a bulk API is genuinely needed, it must require an already "
                    "authenticated, authorised administrative actor — and never be reachable "
                    "pre-authentication."
                ),
                detect=(
                    "- Alert on login requests whose body contains JSON/array structure in "
                    "credential fields, or on an unusually large request body to the login "
                    "endpoint.\n"
                    "- Count failed *authentications* server-side, not requests, and alert "
                    "when one account exceeds a decision budget.\n"
                    "- Rate-limit by (account, source) on the verification function itself."
                ),
                real=(
                    "This pattern shows up wherever a convenience API was added for mobile "
                    "or SSO clients without a security review. It is also the reason some "
                    "password-spraying tools target a *login* endpoint rather than a "
                    "dedicated auth one."
                ),
            ),
            objectives=[
                "Recognise an endpoint that performs multiple authentication decisions per "
                "request",
                "Explain why request-based rate limiting fails against batched attempts",
            ],
            hints=[
                "The rate limit counts requests. Find an endpoint that accepts more than one "
                "credential per request.",
                "Look at the login handler: if the username field starts with `[`, it is "
                "parsed as a JSON array of attempt objects.",
                "In Repeater, set the username field to "
                "`[{\"username\":\"bob\",\"password\":\"hunter2\"}]` and send. Compare it "
                "with a normal form request.",
                "`bob`'s password is in a small common-password list. Send a batch of the "
                "top ~20 passwords in one array and read the flag off the account page.",
            ],
            solution=(
                "**Walkthrough**\n\n"
                "1. Send a normal form request — it is rate-limited and returns "
                "`Invalid credentials.`\n"
                "2. Now send a batch. The username field holds a JSON array:\n"
                "   ```http\n   POST /login\n"
                "   Content-Type: application/x-www-form-urlencoded\n   \n"
                "   username=[{\"username\":\"bob\",\"password\":\"password\"},"
                "   {\"username\":\"bob\",\"password\":\"123456\"},"
                "   {\"username\":\"bob\",\"password\":\"hunter2\"},"
                "   {\"username\":\"bob\",\"password\":\"letmein\"}]\n   ```\n"
                "3. The server loops over the array and, on a match, returns the account "
                "page — including the flag — in the **single** response. No lockout "
                "triggered, because only one request was sent.\n"
                "4. The successful attempt in the batch was `hunter2`.\n\n"
                "**Why it works** — the handler iterates `json.loads(username)` and calls the "
                "authenticate function per element. The rate limiter counts HTTP requests, so "
                "a batch of N attempts costs one unit of budget. Rate-limiting the "
                "*authentication decision* rather than the request is the fix."
            ),
            methodology=(
                "Probe whether the login endpoint accepts more than one credential set per "
                "request, then send a batch of common passwords for the target account in a "
                "single array."
            ),
            credentials="Target: `bob`. Other accounts: `alice`, `carol`.",
            endpoints="GET / · POST /login · GET /healthz",
            behaviour=(
                "If the username field is a JSON array, the server authenticates every entry "
                "in one request and renders the account page for the one that matches."
            ),
            success=(
                "Send multiple credential attempts in a single request and authenticate as "
                "`bob`."
            ),
            remediation=(
                "Accept one credential set per request and rate-limit on failed "
                "authentication decisions rather than HTTP requests."
            ),
            detection=(
                "Alert on array/JSON structure inside credential fields and on large bodies "
                "sent to the login endpoint; count failed authentications, not requests."
            ),
            references=[PS_BRUTE, PS_KNOW],
            lab_family=LOGIN,
            lab_variant="brute_multipass",
            sort_order=7,
        ),
    ]
