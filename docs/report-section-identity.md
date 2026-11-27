# Final report section: identity, access control, enrollment, revocation and audit

*Member 1. Every claim below points to a test, a measurement or a log in `test-evidence/identity-T1-T5.md`.*

## 1. What this part of FogTrust does
The broker must know **who** is acting, **allow only what that role may do**, and keep a record of every
security decision that **cannot be quietly changed**. This part covers:

- **People:** login, sessions with expiry, three roles (Administrator, Operator, Viewer) enforced on the server, and user management.
- **Nodes:** FR-1 enrollment with a one-time token and proof of key possession, and FR-6 revocation with confirmation. It also includes the authentication class that checks every signed node request (using Member 2's engine).
- **Evidence:** an append-only, hash-chained audit log, and the shared Decision record that the dashboard's evidence view reads.
- **The project skeleton:** settings, stable error codes, the JSON error format, request IDs, size limits and rate limits that every other slice builds on.

## 2. Design decisions and why

| Decision | Alternative | Why this one |
|---|---|---|
| **Django REST Framework** | FastAPI (suggested in the brief) | Password hashing, sessions, CSRF, permissions and parameterised queries are built in and widely reviewed. Hand-assembling them is where critical defects come from (ADR recorded in Week 1) |
| **Session cookie + CSRF for people; Ed25519 signatures for nodes** | One token scheme for both | A browser needs HttpOnly cookies that scripts cannot read. A machine needs a key it never sends. A node signature is refused on staff endpoints, and a staff cookie is refused on node endpoints |
| **One capability table** (`accounts/permissions.py`) and `require("nodes.revoke")` on each view | Role checks written inside each view | One place to read, test and review. Unknown capability names fail at start-up. `/auth/me/` returns the same list for the dashboard, but hiding buttons is never the protection |
| **Generic errors to the client, precise reason in the audit log** | Tell the client exactly what failed | A wrong password, an unknown user and a disabled account look identical, and so do forged, expired, used and cancelled tokens. Attackers learn nothing; administrators still see the real reason |
| **Enrollment token stored only as SHA-256**, shown once, 15-minute expiry, one use | Store the token; long-lived tokens | A database leak gives no usable token. The token has 256 bits of randomness, so a fast hash without salt is safe |
| **Proof of possession at enrollment** | Accept any public key with a valid token | Without it, someone with a token could register a victim's public key. The node signs the token, name and key with its private key |
| **Conditional UPDATE for one-time actions** (token redemption, revocation, cancellation) | Read, check, then write | Read-then-write lets two simultaneous requests both win. `UPDATE ... WHERE used_at IS NULL` lets exactly one row change |
| **State change, audit event and Decision in one transaction** | Write the audit event afterwards | An action can never succeed without its record. Failures are written after the rollback, so the record of a refusal is not rolled back with it |
| **Audit log: SHA-256 hash chain + SQLite triggers + model guards** | An ordinary table | Three layers: the code refuses edits, the database refuses `UPDATE`/`DELETE` even from raw SQL, and the chain detects anything that gets past both |
| **Revocation is permanent; revoked status is checked before the signature** | Allow re-activation; check the signature first | A revoked identity can never return with its old key. Checking status first gives a clear `NODE_REVOKED` and avoids extra work for a banned node |
| **Failed node signatures do not lower trust** | Penalise every failure | Node IDs are public. Charging failures to the claimed node would let anyone get an honest node auto-revoked by sending garbage "as" it |

## 3. How it fits the required architecture
Browser interface (Member 4) → **API layer** (`accounts`, `nodes`, `audit`, `core`: validation, permissions,
throttles, error format) → **security engine** (enrollment and revocation gates with their rules, using
Member 2's `fogtrust_crypto` for key and signature checks) → **repository** (Users, EnrollmentToken, Node,
NodeNonce, Decision, append-only AuditEvent) → **fixtures** (`seed_demo_users`, `create_enrollment_token`).
Trust boundaries are drawn in `diagrams/identity-slice-dataflow.md`; threats ID-1 to ID-12 are in
`threat-model/identity-access-audit.md`.

## 4. Evidence

| Claim | Evidence |
|---|---|
| T1: forged, expired, used, cancelled and raced tokens, someone else's key, and borrowed node IDs are all refused, each with its precise reason recorded | `identity-T1-T5.md` T1 table (rows 1a to 1h) |
| T5: a revoked node is refused on its very next request and never gets a task; other roles cannot revoke; confirmation is required; revoking twice conflicts | `identity-T1-T5.md` T5 table and W4.13 |
| Every API route × every role (76 combinations) behaves as the contract's role table; a new route left out of the table fails the build | `test_access_matrix.py`, `identity-T1-T5.md` "full matrix" |
| Edits, deletions and recomputed hashes in the audit log are detected | `audit/tests/test_chain.py`, `test_append_only.py` |
| Login: rate limited per IP and per username; session ID rotated on login; idle and absolute expiry | `accounts/tests/test_auth.py` |
| Enrollment decision median 2.6 ms; revocation median 1.0 ms; signed node request median 1.6 ms | `identity-T1-T5.md` measurements |
| 0 of 1,000 forged or replayed requests accepted; 0 of 500 honest requests refused | same, Week 4 measurements |
| After a server restart: revoked node still revoked, replay still refused, audit chain still valid | live runs in `identity-T1-T5.md` |
| 468 automated tests in this slice (accounts 89, audit 41, core 41, nodes 297), all passing within the team's 811 | `python -m pytest backend/accounts backend/audit backend/core backend/nodes` |

## 5. Problems found and fixed (honest list)

| # | Finding | Severity | Fix |
|---|---|---|---|
| D1 | DRF trusted the client's `X-Forwarded-For` header, so rotating it defeated the per-IP login and enrollment limits | High | `NUM_PROXIES = 0`: clients are identified by the socket address only; regression tests added |
| D2 | The node task endpoint identified the caller by a bare `X-Node-Id` header: anyone with a node ID could read its tasks, and a malformed ID gave a `500` | **Critical** | Signed-request authentication, a database replay store, and per-node and failed-auth rate limits |
| D3 | A merge dropped the `trust` and `tasks` apps from settings, so `main` failed CI | High | Apps restored; the access-matrix guard now compares route lists in both directions |
| D4 | The trust engine's auto-revoke edited the node directly, so tasks were never requeued | Medium | Auto-revoke now calls the same `revoke_node` service and signal |
| D5 | New nodes started at a hard-coded trust of 100, ignoring the admin's policy (80) | Medium | Enrollment reads the current policy and records its version in the Decision |
| D6 | Validation errors repeated the submitted value (`"<x>" is not a valid choice`), and the Django admin login page had no rate limit | Medium | Echoing messages replaced with generic ones; Django admin available only with `DEBUG=True` |
| D7 | `revoke_node` announced `node_revoked`, but nothing listened, so a revoked node's in-flight tasks stayed assigned until the stall detector ran, which also charged the node a failure it never caused | Medium | Scheduler receiver requeues them (or fails them with `NODE_REVOKED` when out of attempts) and releases the load; `test_revocation_requeue.py` |

Lesson: security rules that live in one shared place (permissions table, error catalog, `log_event`) were
easy to keep correct across four people; rules copied into individual views were where the defects were.

## 6. Limitations and ethics
See `identity-limitations-ethics.md`.

## 7. What would come next
Rate-limit counters in a shared store (Redis) so limits survive restarts and multiple processes; the audit
chain head copied outside the database so truncating the newest events is detectable; multi-factor login
for administrators; and a two-person rule for revocation and role changes.
