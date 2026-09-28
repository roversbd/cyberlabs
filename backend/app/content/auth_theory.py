"""Authentication theory: fundamentals, architectures, and the learning map.

These are learning modules, not labs. Each one still follows the same
definition / normal operation / request-response / assumptions / mistakes /
attacker view / defences structure used by the hands-on labs.
"""

from __future__ import annotations

from .builder import lesson

# ---------------------------------------------------------------------------
# Learning map
# ---------------------------------------------------------------------------

LEARNING_MAP = """
## Authentication — Learning Map

Authentication is a **verification** problem: proving *who you are*. The moment
you accept that proof, everything downstream (authorisation, session handling,
business rules) is built on an assumption that may already be false. Most
authentication flaws are failures to check that proof consistently.

Work through the five stages in order. Each stage feeds the next.

### Stage 1 — Foundations
What a credential is, what proves identity, and the difference between
identifying and authenticating.
→ *Authentication Foundations*, *Credentials and Passwords*, *Authentication
Factors and MFA*, *Tokens and Verifiers*

### Stage 2 — Where authentication lives
The same guarantee is implemented very differently depending on the
architecture. The bug is usually a consequence of the architecture, not a typo.
→ *Stateful Architecture*, *Stateless Architecture*, *SPA and API
Authentication*, *Mobile Authentication*, *Single Sign-On and Delegation*

### Stage 3 — Discovery
Before you can break authentication you have to map it: find every login path,
every alternate endpoint, every recovery flow.
→ *Authentication Attack Surface*, *OWASP Testing Methodology*

### Stage 4 — The weaknesses
Grouped by the primitive that is broken.
→ **Credentials & enumeration** (labs 1–6, 15–20)
→ **Registration & account lifecycle** (21–30, 106–112)
→ **Password policy & comparison** (31–39)
→ **Login workflow & state** (40–50, 118–126)
→ **Password reset & recovery** (51–66)
→ **MFA** (67–86)
→ **One-time passwords** (87–97)
→ **Magic links** (98–105)
→ **Security questions** (113–117)

### Stage 5 — Exploitation discipline
Turning a weakness into a proven, reproducible result without causing damage.
→ *From Finding to Report*

### What this module deliberately excludes
Session management, access control (IDOR/BOLA), and the internals of OAuth,
OpenID Connect and JWT cryptography are **separate modules**. Where a lab
straddles a boundary — a "remember this device" token, a magic-link session —
it is taught strictly as an *authentication* artefact: the thing that decides
whether the second factor is satisfied.
"""


def _foundation_lessons() -> list[dict]:
    return [
        lesson(
            "auth-foundations",
            "Authentication Foundations",
            category="Fundamentals",
sort_order=-120,
            summary=(
                "What authentication actually proves, how it differs from "
                "identification and authorisation, and where the trust boundary sits."
            ),
            theory="""
# Authentication Foundations

## What it is

**Authentication** is the process of establishing that a request originates from
a specific principal (a person, a service, a device). **Identification** is
merely claiming to be someone. **Authorisation** is deciding what that someone
may do afterwards.

```
Authentication  ->  "Is this really Alice?"      -> establishes identity
Authorisation   ->  "What may Alice do?"         -> establishes permission
```

Authentication is the *gate*. Every authorisation bug is easier to exploit when
the gate itself is weak, which is why attackers almost always start here.

### The three questions behind every auth mechanism

1. **What is presented?** A password, a code, a token, a certificate, a
   biometric measurement.
2. **What is it checked against?** A stored value, a server-side record, a
   cryptographic signature.
3. **What state does success produce?** A session, a token, a flag on a record,
   a redirect.

A vulnerability almost always lives in one of those three. Presentation leaks
information, comparison is inconsistent, or the resulting state is reachable
without the check.

## Normal operation

A correct login does the same three things every time, regardless of path:

1. **Look up** the principal, using a lookup that does not leak whether it
   exists.
2. **Compare** the presented secret against the stored one, in constant time.
3. **Establish state** server-side, and only then redirect.

Example request and response for a well-behaved login:

```http
POST /login HTTP/1.1
Host: northwind-retail.test
Content-Type: application/x-www-form-urlencoded

username=carol&password=correct-horse-battery-staple
```

```http
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: session=8f14e45fceea167a5a36dedd4bea2543; HttpOnly; Secure; SameSite=Lax
```

Note what is *absent*: the response does not say whether `carol` exists, and it
does not distinguish "wrong username" from "wrong password".

## Security assumptions

A correct design assumes all of the following. Break any one of them and the
module has a bug.

- The **lookup key** is not attacker-controlled beyond a reasonable rate.
- The **comparison** is constant-time and normalises input consistently.
- The **resulting state** can only be reached by passing the check.
- The **same rules** are applied on every endpoint that accepts a credential.
- **Failed attempts** are observable, and observability is not itself a
  side-channel.
- The **recovery flow** proves identity at least as strongly as login does.

## Implementation mistakes

| Mistake | Consequence |
| --- | --- |
| Different error for unknown user | Username enumeration |
| `sleep()` on the user branch | Timing oracle |
| `==` on password hashes | Timing / non-constant-time compare |
| Rate limit on `/login` only | Alternate paths are unthrottled |
| IP block trusting `X-Forwarded-For` | Brute force via header rotation |
| Reset token checked but not bound to user | Account takeover |
| `X-Forwarded-Host` used in reset email | Reset link poisoning |
| Protected page checks only "arrived from step 1" | MFA bypass |
| Recovery via security questions | Weak knowledge factor |

## What an attacker looks for

1. **Alternate paths.** A different endpoint, HTTP method, content type, or
   host header that reaches the same logic with different enforcement.
2. **Information leaks in the failure path.** Status codes, body length,
   response time, and differing wording.
3. **Missing rate limits** on anything that accepts a guess: login, MFA
   verification, recovery, password change, backup codes.
4. **Inconsistent state checks.** Does the server re-verify, or does it trust a
   client-supplied flag / a previous redirect?
5. **Recovery flows**, which are frequently weaker than login and rarely
   monitored.
6. **Account lifecycle** — can a suspended or locked account still authenticate?

## Defensive recommendations

- Return one generic message, one status code, and a comparable response body
  for every credential failure.
- Compare with `hmac.compare_digest` (or `bcrypt.checkpw`), never `==`, and
  always hash the supplied candidate first so lengths match.
- Rate-limit **per account and per source**, and back the source address with a
  trusted proxy configuration rather than a client-supplied header.
- Require the same proof of identity on every credential-accepting path; wrap
  it in one shared function so paths cannot drift.
- Bind reset and verification tokens to the account, single-use, short-lived,
  and compare them in constant time.
- Build absolute URLs from a server-side configured base, never from headers.
- Re-check authorisation on every request; never let a client assert that a
  step was completed.
- Alert on enumeration-shaped traffic, MFA brute force, and recovery abuse.

## References

- OWASP Authentication Cheat Sheet
- OWASP ASVS V2 Authentication requirements
- CWE-204 Observable Response Discrepancy
- CWE-307 Improper Restriction of Excessive Authentication Attempts
""",
            objectives=[
                "Explain the difference between identification, authentication and authorisation",
                "Describe the three questions every auth mechanism must answer",
                "Categorise a given auth bug as a presentation, comparison, or state problem",
            ],
            references=[
                "OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "OWASP ASVS 4.0.1 Chapter V2 — https://owasp.org/www-project-application-security-verification-standard/",
                "CWE-204 — https://cwe.mitre.org/data/definitions/204.html",
            ],
        ),
        lesson(
            "auth-credentials",
            "Credentials and Passwords",
            category="Fundamentals",
sort_order=-119,
            summary=(
                "How passwords are stored, compared, and normalised — and the "
                "subtle bugs that appear in each of those three steps."
            ),
            theory="""
# Credentials and Passwords

## What it is

A **credential** is any value a user presents to prove identity. A password is
the most common one. Password security has three separate concerns, and bugs
hide in all three:

1. **Acceptance** — is this password even allowed? (policy)
2. **Storage** — how is it kept at rest? (hashing)
3. **Comparison** — is it checked correctly? (the part most people get wrong)

## Normal operation

A correct implementation:

- **Hashes** with a memory-hard function (argon2id, scrypt, bcrypt). Never a
  fast hash: a fast hash turns a stolen database into a GPU-speed guessing
  exercise.
- **Salts** per user, so identical passwords produce different hashes and
  precomputation tables are worthless.
- **Normalises** input consistently between enrollment and login, so a password
  typed with a trailing space at signup works at login.
- **Compares** in constant time via the algorithm's own verify function.
- **Compares equal-length material** — if you compare raw UTF-8 bytes, a prefix
  match can return early.

```python
# correct
import bcrypt
def verify(password: str, stored_hash: bytes) -> bool:
    candidate = bcrypt.hashpw(password.encode(), stored_hash)
    return bcrypt.checkpw(password.encode(), stored_hash)   # constant-time
```

## Security assumptions

- Hashing is deliberately slow, and the cost factor is tuned over time.
- The stored hash is never returned to a client, not even on an error path.
- Password comparison is not short-circuited by length or prefix.
- Unicode handling does not let two different byte sequences that render
  identically be treated inconsistently across the two code paths.

## Implementation mistakes

- **Truncation.** The system only ever looks at the first 8 or 12 characters, so
  a long password adds no security.
- **Length check that rejects.** A max length of 8 makes brute force trivial
  and pushes users to reuse.
- **Case-insensitive comparison.** Accepts a password the user never set.
- **Whitespace not normalised.** `str.strip()` on login but not on signup (or
  the reverse) silently creates a second password.
- **Unicode normalisation skipped.** Visually identical passwords fail or,
  worse, two registrations map to the same account.
- **`==` on a hash.** Non-constant-time, and language-dependent.
- **Length leak.** Comparing `len(a) == len(b)` first returns immediately on a
  mismatch and reveals the stored length.
- **Comparison short-circuit.** A loop with `if a[i] != b[i]: return False`
  leaks position of the first difference.

## Request/response example of a normalisation bug

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=carol&password=carol-pw-9911%20
```

Trailing space. If signup trimmed but login did not, the response is
`Invalid credentials` — and the same password *without* the space works. The
attacker learns the stored value's exact byte sequence by bisection.

## What an attacker looks for

- Max/min length enforcement (both are exploitable).
- Whether a password set through one path is accepted at another.
- Unicode confusables that normalise to the same value.
- Case-folding bugs in non-ASCII scripts.
- Whether the comparison is a library call or hand-rolled.

## Defensive recommendations

- Use argon2id (or scrypt/bcrypt) with per-user salt and a tuned cost.
- Reject over-long input early to avoid unbounded hashing cost.
- Normalise once, in one function, used by both signup and login. Decide
  explicitly whether you trim, case-fold, and Unicode-normalise (NFKC), and
  document the choice.
- Always use the algorithm's `verify` function; never compare digests yourself.
- Enforce a minimum length (12+) and check against a breach corpus, not a
  composition rule that pushes `Password1!`.
- Never silently truncate.

## References

- OWASP Password Storage Cheat Sheet
- NIST SP 800-63B — Digital Identity Guidelines
- CWE-521 Weak Password Requirements
- CWE-916 Use of Password Hash With Insufficient Computational Effort
""",
            objectives=[
                "Choose an appropriate password hashing scheme and justify it",
                "Identify truncation, normalisation and comparison bugs on sight",
            ],
            references=[
                "OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
                "NIST SP 800-63B — https://pages.nist.gov/800-63-3/sp800-63b.html",
            ],
        ),
        lesson(
            "auth-factors",
            "Authentication Factors and MFA",
            category="Fundamentals",
sort_order=-118,
            summary=(
                "Something you know, have, are — and why a second factor still "
                "fails if the flow around it is not stateful."
            ),
            theory="""
# Authentication Factors and MFA

## What it is

Authentication factors are classified by the property they prove:

| Class | Property | Example | Phishable? |
| --- | --- | --- | --- |
| Knowledge | something you know | password, PIN | Yes |
| Possession | something you have | phone, token, smartcard | Partly |
| Inherence | something you are | fingerprint, face | No |
| Location | somewhere you are | IP range, geofence | No |

**Multi-factor authentication (MFA)** means requiring factors from *more than
one* class. Two passwords are **not** MFA — they are the same class twice.

## Normal operation

A correct MFA flow is a **state machine** with server-side state:

```
  password accepted
        |
        v
  server issues a challenge bound to (user, session, device, nonce, expiry)
        |
        v
  client submits factor response + challenge id
        |
        v
  server verifies against ITS OWN stored state, marks session.factor2 = satisfied
        |
        v
  only now are protected resources served
```

The critical property: **the server decides**. The client may render a
"verified" screen, but the flag that matters lives in server-side state and is
checked on every protected request.

## Security assumptions

- The challenge is bound to the pending session, not to a global variable.
- The second factor is required on every protected resource, server-side.
- A client-supplied `mfa_ok=true` is treated as untrusted input.
- Codes are compared in constant time, expire, and are single-use.
- "Remember this device" issues a **new, high-entropy, revocable** credential —
  not a guessable one, and not a permanent bypass.
- Recovery of a lost factor is at least as strong as the factor itself.

## Implementation mistakes

- **Client-side-only enforcement.** The 2FA page is JS, but the protected page
  never checks whether a code was submitted. Skip the page, keep the cookie.
- **Server trusts a client flag.** `mfa_ok=true` posted by the client is
  accepted as proof.
- **Global pending state.** A single `pending_user` variable means concurrent
  sessions cross-contaminate.
- **No rate limit on code verification.** A 6-digit code is 10^6; at even 500
  req/s that is ~33 minutes of wall-clock guessing.
- **Codes not bound to session.** A code observed for one login completes
  another.
- **Backup codes never rotated**, or stored unhashed, or guessable.
- **Password-only fallback.** An alternate path that requires only one factor
  defeats the whole design.
- **Predictable "trusted device" token.** A short hash prefix becomes a
  permanent MFA waiver.

## Request/response example

```http
POST /api/verify HTTP/1.1
Content-Type: application/json

{"challenge_id":"a91f...","code":"481902"}
```

Correct response — the server's own state changes:

```http
HTTP/1.1 200 OK
Set-Cookie: session=...; factor2=1; HttpOnly; Secure; SameSite=Strict
```

Broken response — the *client* is told it succeeded, and the protected resource
never re-checks:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"mfa_ok":"true"}
```

## What an attacker looks for

- Direct GET on the protected page after only the password step.
- Whether a cookie alone (no server state) is sufficient.
- Replay of a code across sessions.
- Unthrottled `/verify`.
- A `remember_device` or `trusted` cookie with low entropy.
- Any endpoint that returns the same data without requiring the second factor.

## Defensive recommendations

- Store factor state server-side and check it on **every** protected request.
- Rate-limit verification per account, per device and per source; add a small
  constant delay and lock on repeated failure.
- Bind challenges to the session with a stored nonce, single-use, 5–10 minutes.
- Enforce the second factor on the API, not only on the web UI.
- Require step-up authentication for sensitive actions, not just at login.
- Trust-device tokens: ≥128 bits of entropy, stored hashed, revocable, expiring.
- Publish a re-enrolment and recovery path that does not weaken the factors.

## References

- OWASP Authentication Cheat Sheet — MFA section
- OWASP ASVS V2.5 — https://owasp.org/www-project-application-security-verification-standard/
- CWE-308 Use of Single-factor Authentication
- CWE-287 Improper Authentication
""",
            objectives=[
                "Distinguish multi-factor from multi-step authentication",
                "Draw the server-side state machine a correct MFA flow needs",
                "Explain why a client-supplied verified flag is not evidence",
            ],
            references=[
                "OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "CWE-308 — https://cwe.mitre.org/data/definitions/308.html",
            ],
        ),
        lesson(
            "auth-tokens",
            "Tokens and Verifiers",
            category="Fundamentals",
sort_order=-117,
            summary=(
                "The properties a recovery, verification, or remember-me token "
                "must have — and how each missing property becomes a takeover."
            ),
            theory="""
# Tokens and Verifiers

## What it is

Any value the server issues and later accepts back as proof is a **token**:
password-reset tokens, email-verification tokens, magic links, enrolment
codes, "remember this device" cookies. They are authentication artefacts and
must be treated as bearer secrets.

Five properties decide whether a token is safe:

1. **Unpredictable** — ≥128 bits of cryptographic randomness.
2. **Single-use** — consumed on first successful use.
3. **Time-bounded** — short expiry (minutes, not days).
4. **Bound** — to a specific account, action and session.
5. **Stored safely** — hashed at rest where possible, never logged.

## Normal operation

Issue → deliver → verify → consume, atomically:

```sql
-- verify is one statement, so a token cannot be spent twice
UPDATE reset_tokens
   SET used_at = now()
 WHERE token_hash = ? AND account_id = ? AND used_at IS NULL AND expires_at > now()
RETURNING account_id;
```

If that returns no rows, the token was invalid, already used, wrong account, or
expired — and the client is told only "invalid".

```http
POST /forgot-password  (always the same response)
```

```http
HTTP/1.1 200 OK

If that address has an account, a reset link has been sent.
```

```http
POST /reset  token=<128-bit>&new_password=...
```

```http
HTTP/1.1 302 Found
Location: /login?reset=complete
```

## Security assumptions

- Entropy comes from a CSPRNG, never from a counter, timestamp, or user id.
- The token is compared against a **hash** of the stored value, in constant
  time.
- Consumption is atomic — two concurrent redemptions cannot both succeed.
- The account is derived **from the token**, never from a request parameter.
- Absolute URLs are built from server configuration, not from request headers.

## Implementation mistakes

| Mistake | Result |
| --- | --- |
| Sequential / timestamped token | Trivially guessable |
| Token never expires | Permanent takeover vector |
| Token reusable | Link in old mail still works |
| Token not bound to account | Reset anyone with any valid token |
| `user_id` read from the request | Reset arbitrary accounts |
| Token in `Referer` to third parties | Leaks via outbound links |
| Token compared with `==` | Timing oracle |
| Reset link host from `X-Forwarded-Host` | Attacker-controlled link in victim mail |
| Token echoed in the response body | Leaks into logs, caches, devtools |

## What an attacker looks for

- Low-entropy tokens: try small integers, then dates, then hashes of ids.
- Reuse: redeem the same link twice.
- Substitution: redeem Alice's token for Bob's account.
- `user` / `uid` parameters in the URL that the server trusts.
- Whether the reset page or a third-party image leaks the URL.
- Whether the host in the emailed link matches the real host.

## Defensive recommendations

- `secrets.token_urlsafe(32)` or better; store only a hash (SHA-256 is fine,
  the token already has full entropy).
- Expire in 15–60 minutes, single-use, consumed atomically.
- Bind to account and purpose; ignore any account identifier in the request.
- Build links from a configured base URL. Strip `Referer` on the reset page, or
  use a `Referrer-Policy: no-referrer` policy and avoid third-party subresources.
- Same generic response for every forgot-password request.
- Invalidate all outstanding tokens after a successful reset.

## References

- OWASP Forgot Password Cheat Sheet
- CWE-640 Weak Password Recovery Mechanism for Forgotten Password
- CWE-598 Use of GET Request Method With Sensitive Query Strings
- CWE-200 Exposure of Sensitive Information
""",
            objectives=[
                "Evaluate a token design against the five required properties",
                "Explain why the account must be derived from the token server-side",
            ],
            references=[
                "OWASP Forgot Password Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
                "CWE-640 — https://cwe.mitre.org/data/definitions/640.html",
            ],
        ),
    ]


def _architecture_lessons() -> list[dict]:
    return [
        lesson(
            "arch-stateful",
            "Stateful Architecture",
            category="Architectures",
sort_order=-116,
            summary=(
                "Server-side sessions, where the auth decision is stored, and "
                "why the state location dictates the attack surface."
            ),
            theory="""
# Stateful Architecture

## What it is

The server keeps the authentication result in its own datastore. The client
holds an opaque **session identifier**; the server looks it up on every request
and decides from the stored record.

```
POST /login  ──►  server sets  session=8f14e45f...  ──►  server row: {uid: 7, factor2: 1}
GET  /orders  ──►  cookie 8f14e45f...  ──►  lookup  ──►  authorised
```

## Normal operation

1. Login succeeds → generate 128+ bits of randomness → store the record server-side.
2. Set the identifier as `HttpOnly; Secure; SameSite=Lax`, `__Host-` prefixed.
3. On each request, resolve the identifier to a record; if the record's
   authentication state does not satisfy the resource's requirement, refuse.
4. Rotate the identifier on privilege change (login, MFA, password change).

## Security assumptions

- Session identifiers are unpredictable and generated by a CSPRNG.
- The stored record is the *only* source of truth; nothing the client asserts
  about its own auth state is trusted.
- Protected endpoints check the record, not the path the user took to reach them.
- The identifier is not derived from anything guessable (user id, timestamp).

## Implementation mistakes

- **Flow-based state**: the server remembers "user is at step 2" in a cookie
  the client can rewrite, then lets a protected page trust that cookie.
- **One code path, many endpoints**: `/login` is throttled, but
  `/api/auth/login` and `/api/auth/jwt/refresh` are not.
- **Check on the way in, not on the way through**: verification happens once and
  the resulting state is assumed, rather than being re-checked per request.
- **No rotation on privilege change**, so a pre-login identifier survives login.

## What an attacker looks for

- Protected resources reachable without a completed flow.
- Endpoints that return the same data as an authenticated path but skip the
  check.
- Session identifiers that are not high-entropy (this is a *check* though, not
  a break — session management is a separate module).

## Defensive recommendations

- Keep all authentication state in the datastore, keyed by an opaque id.
- Re-check the record on every request; never rely on a remembered step.
- Centralise credential verification in one function that every path calls.
- Rotate identifiers on login and on any privilege change.
- Keep the flow state minimal and server-side, with explicit, short transitions.

## References

- OWASP Session Management Cheat Sheet (background only)
- OWASP Authentication Cheat Sheet
""",
            objectives=[
                "Describe where authentication state lives in a stateful design",
                "Explain why a protected page must consult the server record",
            ],
            references=[
                "OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
        ),
        lesson(
            "arch-stateless",
            "Stateless Architecture",
            category="Architectures",
sort_order=-115,
            summary=(
                "Self-contained tokens, why they shift the problem from server "
                "state to signing and revocation — and the auth bugs that remain."
            ),
            theory="""
# Stateless Architecture

## What it is

The server keeps **no** authentication state. Instead it issues a signed,
self-describing token; each request is authorised by verifying the signature
and the claims. This is the shape behind JWT-based and API-key schemes.

> Scope note: token *cryptography* (signature algorithms, `alg` confusion, key
> handling) belongs to a separate cryptography module. What follows is the
> authentication-flow behaviour that remains relevant here.

## Normal operation

```
POST /login      ──►  signed token {sub, exp, factor2, jti}
GET  /orders     ──►  Authorization: Bearer <token>
                  ──►  verify signature, check exp, check factor2 claim, look up jti
```

The auth decision travels with the request. Two properties make it work:

- **Tamper-evidence** — the claims cannot be edited by the holder.
- **Revocation** — `jti` (a token id) is checked against a server-side deny or
  allow list, so a token can be killed before `exp`.

Without revocation, "log out" cannot invalidate anything before expiry. That is
an authentication-lifecycle problem, not merely a session problem.

## Security assumptions

- Only the server can produce a valid token.
- Every protected endpoint actually verifies the signature and the claims it
  needs — including the second-factor claim.
- Expiry is enforced, and is short.
- The token id is checked so revocation works.

## Implementation mistakes

- **Claims trusted from the client.** A client that receives
  `{"factor2": false}` and re-sends `{"factor2": true}` has broken it, unless the
  token is signed by the server.
- **Second factor omitted from the token**, so a fresh token from a
  password-only endpoint is accepted by 2FA-protected endpoints.
- **Inconsistent claim requirements** between endpoints — the classic
  "web/mobile inconsistency" and "password fallback" labs.
- **No `jti`**, so revocation is impossible and logout is cosmetic.
- **Long expiry** to avoid re-login, extending the window after a compromise.

## What an attacker looks for

- Endpoints that accept a token but check fewer claims than their siblings.
- A token-issuing endpoint reachable with only one factor.
- The same data served by an endpoint that skips the factor check.

## Defensive recommendations

- Sign tokens; never accept claims from a request body or unsigned header.
- Issue tokens *after* the full flow, including the second factor.
- Put factor state in a claim and check it in a shared middleware.
- Keep `exp` short (minutes) and use refresh with rotation and `jti` reuse
  detection for revocation.
- Use a single authorisation/verification middleware so endpoints cannot drift.

## References

- OWASP REST Security Cheat Series
- OWASP JSON Web Token Cheat Sheet (for the cryptography module)
- RFC 8725 JWT Best Current Practices
""",
            objectives=[
                "Explain how a stateless design replaces server-side auth state",
                "Identify the authentication checks that must move into claims + middleware",
            ],
            references=[
                "OWASP REST Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
                "RFC 8725 — https://www.rfc-editor.org/rfc/rfc8725",
            ],
        ),
        lesson(
            "arch-spa-api",
            "SPA and API Authentication",
            category="Architectures",
sort_order=-114,
            summary=(
                "Why a JavaScript client is an untrusted attacker, and the auth "
                "mistakes that follow from forgetting that."
            ),
            theory="""
# SPA and API Authentication

## What it is

A single-page app holds no secrets. Everything it can do, a user can do by
opening devtools. The API is the real application; the SPA is a view.

## Normal operation

- The API authenticates every request itself.
- Credentials are sent once, in the body, over TLS. The API returns a token or
  sets a cookie; the SPA stores it.
- The SPA performs **no** security decision. Hiding a button is UX, not control.
- `Authorization: Bearer …` or an `HttpOnly` cookie — either is fine.

## Security assumptions

- The API never trusts a request body field as a security-relevant flag.
- The API does not rely on the SPA having performed a step.
- CORS does not become the access-control mechanism.

## Implementation mistakes

- **Client-side gating.** The SPA hides `/admin`, and the API serves it to
  anyone authenticated. (Authorisation — separate module — but the
  *authentication* analogue is: the SPA "remembers" that MFA passed.)
- **Server trusts `mfa_verified` from the client.** The API accepts
  `{"mfa_verified": true}` and issues a full token.
- **Tokens in `localStorage`.** Any XSS exfiltrates them. (Mentioned as an
  authentication consequence; XSS is a separate module.)
- **Auth decided in the SPA, API unverified.** Classic broken-function-level
  auth.
- **Multiple auth routes**: `/api/login` and `/api/session` with different
  enforcement.

## What an attacker looks for

- The SPA bundle for undocumented API routes.
- A JSON field that looks like a security flag.
- A second, less-protected login route.

## Defensive recommendations

- Authenticate and re-verify in the API on every request.
- Never read a security decision from the request body.
- Prefer `HttpOnly; Secure; SameSite` cookies over `localStorage`.
- Enforce the second factor in API middleware, not in SPA state.
- Give the API one authentication entry point, used by every route.

## References

- OWASP API Security Top 10 — API8 Security Misconfiguration
- OWASP Authentication Cheat Sheet
""",
            objectives=[
                "List the security decisions a SPA must never make on its own",
                "Explain why request-body flags cannot be evidence of authentication",
            ],
            references=[
                "OWASP API Security Top 10 — https://owasp.org/API-Security/",
                "OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
        ),
        lesson(
            "arch-mobile",
            "Mobile Authentication",
            category="Architectures",
sort_order=-113,
            summary=(
                "Deep links, intent handling, and the API that must not assume "
                "the mobile client behaved."
            ),
            theory="""
# Mobile Authentication

## What it is

A native app ships an API client and a UI. The UI is as untrusted as a browser
SPA, with two additions: intent/deep-link handling, and secrets that are
genuinely embedded (and therefore extractable).

## Normal operation

- The app authenticates against the same API as web, with identical rules.
- Deep links (`myapp://reset?token=…`) are validated: scheme allow-list, host
  check, and the token is still verified server-side.
- Client-side secrets are not relied upon; the API enforces rate limits and
  state.

## Security assumptions

- The API is the enforcement point.
- Deep links cannot be used to skip a flow step.
- Response differences between the mobile API and the web API do not exist for
  authentication purposes.

## Implementation mistakes

- **Deep link that sets auth state**: opening a crafted link completes
  registration or bypasses the challenge.
- **Deeper mobile API surface** with weaker checks than the web API.
- **Hardcoded API keys** treated as authentication.
- **Different code path** for the app: the web enforces MFA, the mobile API
  does not.

## What an attacker looks for

- `intent-filter` reachable URLs exported by the app.
- A mobile API that accepts a `stage` parameter to skip MFA.
- Different behaviour for the same credential across channels.

## Defensive recommendations

- Same authentication middleware for every channel.
- Validate deep-link inputs and always re-verify server-side.
- No security decisions based on client build, header, or channel identifier.
- Treat keys as public; authorise by identity, not possession.

## References

- OWASP Mobile Application Security Verification Standard (MASVS)
- OWASP API Security Top 10
""",
            objectives=[
                "Explain why a deep link must never establish authentication state",
                "Describe the 'same rules on every channel' requirement",
            ],
            references=[
                "OWASP MASVS — https://mas.owasp.org/MASVS/",
                "OWASP API Security Top 10 — https://owasp.org/API-Security/",
            ],
        ),
        lesson(
            "arch-sso",
            "Single Sign-On and Delegation",
            category="Architectures",
sort_order=-112,
            summary=(
                "Where the trust boundary moves when an identity provider is "
                "involved, and the authentication bugs that follow."
            ),
            theory="""
# Single Sign-On and Delegation

## What it is

An **identity provider (IdP)** authenticates the user; the **relying party (RP)**
consumes the result. The RP no longer sees a password, so it must trust an
assertion instead — and the whole security model becomes "is this assertion
genuine, and is it for me, and has it been used already?"

> Scope note: the internals of OAuth 2.0 and OpenID Connect (grant types,
> scopes, token introspection) are a separate module. The authentication
> behaviour covered here is: **does the RP correctly decide that the user
> proved their identity?**

## Normal operation

```
User ──► RP /login ──► IdP (authenticates) ──► signed assertion ──► RP validates:
   • signature valid against the *RP's* configured IdP key
   • audience (aud) == this RP
   • recipient / destination == this RP
   • issuer == trusted IdP
   • notBefore/expiresAt valid, clock skew bounded
   • assertion ID (InResponseTo) not already consumed
   • the required authentication context / ACR was actually met
   • NameID and any role attributes come from the *signed* assertion
```

## Security assumptions

- The RP validates the signature against the key it pinned for that IdP.
- Audience and recipient are checked. An assertion minted for another relying
  party must be rejected.
- Assertions are single-use; replay is prevented by tracking the assertion id.
- The required authentication level is enforced. If the policy demands
  multi-factor, an assertion that reports single-factor must not be accepted.
- No attribute is read from an unsigned part of the message, a header, or a
  user-editable profile field.

## Implementation mistakes

- **Signature wrapping (XSW)**: the signed element is valid but the
  application reads a *different*, attacker-supplied element.
- **Signature not required**: the assertion is accepted unsigned because
  "the IdP would not send it like that".
- **Audience not checked**: an assertion for RP-A is replayed at RP-B.
- **Replay**: the same assertion is submitted twice within its validity window.
- **ACR ignored**: the IdP authenticated with one factor, the policy required
  two, and the RP accepted it.
- **Account linking on email only**, so an attacker who controls the victim's
  email at another IdP inherits the account.

## What an attacker looks for

- The federation endpoints, the IdP entity id, and the metadata URL.
- Whether `aud` and recipient are validated.
- Whether the assertion id is remembered.
- Whether an alternative, weaker login path exists that skips the IdP.
- Whether the name/email can be changed at the IdP after linking.

## Defensive recommendations

- Validate signature **and** audience **and** recipient **and** issuer.
- Enforce single-use assertion ids and a strict clock skew.
- Enforce the required authentication context (ACR) — this is where "MFA was
  required but only a password was used" is caught.
- Use strict, explicit library configuration; do not hand-roll XML parsing.
- Never read identity or role from a profile field the user can edit.
- Provide an alternative path for users who cannot use the IdP that is
  **equally** strong, or it becomes the weak link.

## References

- OWASP Authentication Cheat Sheet — SSO section
- NIST SP 800-63C — https://pages.nist.gov/800-63-3/sp800-63c.html
- CWE-347 Improper Verification of Cryptographic Signature
""",
            objectives=[
                "List the checks an RP must perform on an identity assertion",
                "Explain how ignoring the authentication context turns MFA into single-factor",
            ],
            references=[
                "OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "CWE-347 — https://cwe.mitre.org/data/definitions/347.html",
            ],
        ),
    ]


def _method_lessons() -> list[dict]:
    return [
        lesson(
            "auth-attack-surface",
            "Authentication Attack Surface",
            category="Methodology",
sort_order=-111,
            summary=(
                "A repeatable map of every path that can establish or change "
                "identity — the checklist that makes the rest of the module systematic."
            ),
            theory="""
# Authentication Attack Surface

## What it is

Before testing anything, enumerate **every** place a user can become
authenticated, or change who they are. A vulnerability in the main login form is
often a duplicate of one in a forgotten mobile API.

## The map

Work through this list for any application. For each entry, record: the
endpoint, the HTTP method, the required factors, the rate limiting, and the
failure behaviour.

1. **Login** — form, JSON API, GraphQL mutation, SOAP, gRPC, WebSocket.
2. **Alternate credentials** — HTTP Basic, API key, mobile app login,
   "remember me", cookie, `Authorization` header.
3. **Registration** — signup, invite acceptance, social signup, tenant creation.
4. **Verification** — email verification, phone verification, device binding.
5. **MFA** — challenge issuance, verification, enrolment, disable, recovery,
   backup codes, trusted devices, step-up.
6. **Recovery** — forgot password, password change, email change, username
   change, security questions, support-assisted recovery.
7. **Magic links / one-time links** — issue, consume, expire.
8. **Federation** — IdP redirect, callback, logout, account linking.
9. **Administrative** — impersonation, support tooling, bulk user APIs.
10. **Account lifecycle** — register, activate, suspend, disable, delete,
    reactivate.

## Normal operation

For each entry, a tester should be able to answer:

- What proves identity here, and how many factor classes?
- Is it throttled, per account and per source?
- Does the failure path leak anything (wording, status, length, timing)?
- Does success produce server-side state, and is that state re-checked?
- Are all paths enforcing the same rules?

## What an attacker looks for

The **gaps between** entries: an endpoint that exists in the bundle but not in
the docs, a versioned API (`/v1/` vs `/v2/`) with different enforcement, a
method override, a GraphQL mutation that mirrors a hardened REST route, a
support tool that skips MFA.

## Defensive recommendations

- Maintain an inventory of authentication endpoints and review each one when
  the auth logic changes.
- Centralise verification so new endpoints inherit the rules.
- Test the gaps, not just the documented path.

## References

- OWASP Testing Guide — Identity Management
- OWASP ASVS V2
""",
            objectives=[
                "Produce a complete authentication surface map for an application",
                "Identify where rules drift between parallel endpoints",
            ],
            references=[
                "OWASP Testing Guide 4.2 Identity Management — https://owasp.org/www-project-web-security-testing-guide/",
            ],
        ),
        lesson(
            "auth-owasp-methodology",
            "OWASP Authentication Testing Methodology",
            category="Methodology",
sort_order=-110,
            summary=(
                "The order of operations for testing authentication, and the "
                "evidence needed to call a weakness a real finding."
            ),
            theory="""
# OWASP Testing Methodology

## What it is

A repeatable order of operations, so testing is systematic rather than a
sequence of guesses.

## The order

1. **Map** the authentication surface (see *Authentication Attack Surface*).
2. **Test username enumeration** — different response, subtle difference,
   status code, body length, timing.
3. **Test brute-force protection** — is it present at all, is it per account,
   per source, and can it be bypassed by header rotation, IP rotation, or a
   parallel endpoint?
4. **Test password policy** — acceptance of weak/common passwords, length
   enforcement, normalisation.
5. **Test the registration flow** — verification bypass, duplicate registration,
   normalisation, parameter pollution.
6. **Test the account lifecycle** — can a suspended, locked, or deleted account
   still authenticate?
7. **Test MFA** — can the challenge be skipped, replayed, or brute-forced? Is
   there a fallback that requires only one factor?
8. **Test recovery** — token predictability, reuse, expiry, binding, host
   poisoning, leakage, and whether recovery is weaker than login.
9. **Test magic links and one-time links** — same five properties as reset.
10. **Test inconsistent enforcement** — web vs mobile vs API, GET vs POST,
    method override, content type.

## Evidence needed for a finding

- **A reproducible request.** Exact method, path, headers, body, in order.
- **The observed difference**, quantified: status code, byte length, or timing
  over several samples.
- **The impact**, stated concretely: "obtained carol's account", not "could
  lead to".
- **A negative control**: the same request against a non-existent user, so the
  reviewer can see the distinction you are relying on.
- **Minimal, non-destructive proof.** No permanent lockout of a real account,
  no mass data change.

## Discipline

- Rate your own testing; do not lock out accounts you do not own.
- Prefer two test accounts you own (victim and attacker) over guessing real
  users.
- Clean up: reset any password you changed, remove enrolment you added.
- Record timing comparisons as a distribution, not a single sample.

## References

- OWASP Web Security Testing Guide — Identity Management
- OWASP Authentication Cheat Sheet
""",
            objectives=[
                "Run authentication testing in a systematic order",
                "Assemble the evidence a reviewer needs to accept a finding",
            ],
            references=[
                "OWASP WSTG — https://owasp.org/www-project-web-security-testing-guide/",
            ],
        ),
        lesson(
            "auth-reporting",
            "From Finding to Report",
            category="Methodology",
sort_order=-109,
            summary=(
                "Turning a working exploit into a report that is reproducible, "
                "honest about impact, and easy to verify."
            ),
            theory="""
# From Finding to Report

## The five questions

Before writing anything, answer all five. If any answer is "no" or "I am not
sure", you have a hypothesis, not a finding.

1. **What is broken?** The specific check that is missing or wrong.
2. **What can I do with it?** The concrete capability gained.
3. **How do I reproduce it?** Exact steps and requests, from a clean session.
4. **Who is affected?** Which accounts, which roles, what blast radius.
5. **What is the real-world impact?** In terms of the business, not the CWE.

## Writing it

**Title** — the weakness and the impact:
> Account takeover of any user via predictable password-reset token

**Summary** — two or three sentences: what, where, impact.

**Steps to reproduce** — numbered, with raw requests. Include a negative
control.

**Evidence** — the flag or the concrete result. Screenshots of a *result*,
never of a request containing a real session cookie.

**Impact** — who can do what now. Be specific. "An unauthenticated attacker can
reset the password of any account, including administrators."

**Remediation** — the fix at the root cause, not a symptom.

**Detection** — what to log and alert on, so the fix can be verified and future
attempts are caught.

## Severity calibration

| Finding | Typical severity |
| --- | --- |
| Username enumeration | Low |
| User enumeration enabling targeted phishing | Informational–Low |
| Brute force with no rate limit, weak password | High |
| MFA bypass | High |
| Password reset for arbitrary accounts | Critical |
| Password reset poisoning → takeover | Critical |

Severity comes from the *worst realistic outcome*, discounted by what an
attacker must already have.

## Common mistakes in reports

- Claiming impact you did not demonstrate.
- Showing a request that includes a live session cookie (rotate it, redact it).
- Reporting a missing header as a finding with no exploitation path.
- Pasting a wall of requests instead of the one that matters.
- Omitting the negative control, so the reviewer cannot verify the difference.

## References

- OWASP Testing Guide — Reporting
- CVSS v3.1 User Guide
""",
            objectives=[
                "Answer the five reporting questions before writing a report",
                "Calibrate severity from demonstrated impact",
            ],
            references=[
                "CVSS v3.1 — https://www.first.org/cvss/v3-1/",
            ],
        ),
    ]


AUTH_THEORY_LESSONS: list[dict] = [
    *_foundation_lessons(),
    *_architecture_lessons(),
    *_method_lessons(),
]
