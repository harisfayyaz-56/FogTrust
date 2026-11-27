# Limitations and ethics: identity, access, enrollment, revocation and audit (Member 1)

## What this slice does and does not protect

| Protects against | Does not protect against |
|---|---|
| Guessing passwords (Argon2, per-IP and per-username limits) | A user who chooses a weak password that passes the validators, or reuses a leaked one |
| A stolen session cookie being used for long (HttpOnly, SameSite=Strict, 30-minute idle and 8-hour absolute expiry) | Malware on the administrator's own computer, which acts inside a live session |
| A viewer or operator calling admin endpoints directly | A real administrator who decides to misuse their power (this is detected and recorded, not prevented) |
| Forged, expired, reused or raced enrollment tokens | A valid token that leaks before it is used: whoever uses it first gets a node. Tokens are short-lived and one-time to make that window small |
| Changes to past audit events | Deleting the **newest** events by editing the database file directly (see below) |

## Known limits (stated plainly)

1. **Rate limits live in server memory.** They reset when the server restarts and are not shared between several server processes. This is fine for the single-laptop demo; production would use Redis.
2. **Rate limits can lock out honest users.** One attacker can block a username for up to an hour, or everyone behind a shared network address for a minute. This trade-off was chosen over unlimited guessing.
3. **Truncating the end of the audit log.** The triggers block `DELETE` through SQLite. Someone who edits the database file with another tool can remove the newest events, leaving a shorter chain that still verifies. Detecting this needs the latest hash stored outside the database (e.g. printed in each daily report).
4. **No multi-factor login.** One password protects an administrator account.
5. **One administrator can act alone.** Revocation and role changes need no second approval; the defence is the record, not a second person.
6. **The SQLite file is not encrypted at rest.** Secrets inside it are hashed (passwords with Argon2, tokens with SHA-256), but node names, roles and audit details are readable by anyone with access to the file.
7. **No HTTPS on localhost.** `COOKIE_SECURE` is off for development and must be on in any real deployment.
8. **Revocation is permanent by design.** A node revoked by mistake must enroll again with a new key and receives a new ID.

## Ethics

- **Personal data is minimised.** Accounts need only a username and password: no email, phone or real name. Demo accounts get random passwords that are printed once and never stored in plain text.
- **The audit log records people.** It stores usernames, IP addresses and actions. It exists for security investigation only, should be readable only by administrators (enforced), and in a real deployment needs a retention period and users who are told it exists.
- **Generic errors are deliberate.** Users are told "Invalid username or password" rather than which part was wrong. This is slightly less helpful to honest users and was chosen to protect them from account probing.
- **Tests attack only our own broker.** Every attack in the T1, T5 and T-final evidence runs against a local server with synthetic data.
- **No claim of unbreakable security.** This is a coursework prototype with the limits above; the evidence shows what was tested, not that nothing else can go wrong.
