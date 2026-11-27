# Demo script: Member 1's part (about 3 minutes)

Before the demo: `python manage.py seed_demo_users` (note the passwords), start the server, and keep two
browser windows: one signed in as `admin1`, one as `viewer1`. Generate one node key in advance:
`python -m fogtrust_crypto.node_sim keygen --key-file keys/gateway-01.key`.

| Time | Say | Do | What the audience sees |
|---|---|---|---|
| 0:00 | "People sign in with a session; the server decides what each role may do." | Sign in as `viewer1`. Try a wrong password once first | Same "Invalid username or password" for any failure |
| 0:20 | "An admin issues a one-time enrollment token. It is shown once and stored only as a hash." | As `admin1`: create a token (dashboard or `POST /enrollment-tokens/`) | The token, its expiry; the token list never shows it again |
| 0:40 | "The node proves it owns its key and enrolls." | `$env:FOGTRUST_ENROLL_TOKEN = "<token>"` then `python -m fogtrust_crypto.node_sim enroll --key-file keys/gateway-01.key --name gateway-01` | `Enrolled as <node id>`; the node appears as `active` |
| 1:00 | "A stolen token is useless after it has been used." | Run the same enroll command with a second key and the same token | `HTTP 401 ENROLL_TOKEN_INVALID` |
| 1:20 | "A viewer cannot revoke, even by calling the API directly." | As `viewer1`, attempt the revoke | `403 Access denied.`, nothing changes |
| 1:40 | "Revocation needs the exact node name." | As `admin1`: revoke with a misspelt name, then with `gateway-01` | `CONFIRMATION_REQUIRED`, then `revoked` with who, when and why |
| 2:10 | "The revoked node is refused on its very next request." | `python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-01.key --count 1` | `HTTP 403 NODE_REVOKED` |
| 2:30 | "Every one of these steps is in a log that cannot be edited." | Open the audit log, then `POST /audit/verify/` (or `python manage.py verify_audit_chain`) | Login, token, enroll, reuse refused, access denied, revoke failure and success, heartbeat refused; `valid: true` |

If asked "what if someone edits the database?": run `python -m pytest backend/audit/tests/test_chain.py -k edited -v`
to show the edit being detected at the exact sequence number.
