# Threat Model — Identity, Access and Audit slice

| | |
|---|---|
| Slice | Member 1 (FR-1 enrollment, FR-6 revocation, login, roles, audit) |
| Method | STRIDE per trust boundary |
| Version | 0.2 (Week 2) |

This file is Member 1's contribution to the team threat model. The team needs **at least eight
threats mapped to mitigations** in total; this slice provides ten. Each row names the test or
evidence that proves the mitigation works, so every claim in the final report can link to one.

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| User passwords | Grant access to the dashboard and admin functions |
| Session cookies | Equivalent to a logged-in user while valid |
| Enrollment tokens | Let a new device become a trusted node |
| Node public keys (and the node's private key, held only on the node) | Define node identity |
| Node status (active / revoked) | Decides who may receive tasks |
| Audit log | The evidence that every decision and admin action is traceable |
| Secret key (`DJANGO_SECRET_KEY`) | Signs sessions and CSRF tokens |

## 2. Actors

| Actor | Trust |
|---|---|
| Administrator | Trusted, but actions must still be logged (insider risk) |
| Operator | Trusted for the normal workflow only |
| Viewer | Read-only |
| Enrolled node | Trusted only while active and while its signatures verify |
| Anonymous network client | Untrusted (could be a spoofed node or a password-guessing script) |

## 3. Trust boundaries (input for the data-flow diagram, drawn by Member 4)

| ID | Boundary | Crossing | Controls at the boundary |
|---|---|---|---|
| TB1 | Browser → API | Login, dashboard calls | Session cookie, CSRF, role permissions, input validation |
| TB2 | Edge node → API | Enrollment, heartbeats, results | Enrollment token + proof of possession, Ed25519 signatures, replay checks |
| TB3 | API → Security engine | Function calls inside the process | Engine receives validated, normalised data only |
| TB4 | API → Database | ORM queries | Parameterised queries, append-only audit triggers |
| TB5 | Admin → Configuration | Policy and role changes | Admin role, confirmation, audit event per change |

## 4. Threats and mitigations

| ID | Threat | STRIDE | Boundary | Mitigation | Evidence (test / artefact) |
|---|---|---|---|---|---|
| ID-1 | **Password guessing / credential stuffing** against `/auth/login/` | Spoofing | TB1 | Argon2 hashing; login throttled 5/min per IP **and** 20/hour per username (stops IP rotation); identical error for unknown user, wrong password and disabled account; every failure audited (`auth.login`, `failure`) with the precise reason; Django admin login page disabled outside DEBUG | `test_login_is_rate_limited_per_client` ✅, `test_login_is_rate_limited_per_username_across_ips` ✅, `test_wrong_password_and_unknown_user_look_identical` ✅, `test_failed_login_is_audited_without_the_password` ✅ |
| ID-2 | **Session hijacking** (stolen or long-lived session cookie) | Spoofing | TB1 | HttpOnly + SameSite=Strict cookie; 30-minute idle expiry; 8-hour absolute expiry; expires at browser close; session ID rotated on login (no fixation); logout deletes the server-side session | `test_idle_session_expires` ✅, `test_absolute_session_timeout` ✅, `test_login_rotates_session_key` ✅, `test_old_session_cookie_is_useless_after_logout` ✅ |
| ID-3 | **Cross-site request forgery** (another site makes the admin's browser revoke a node, or logs the victim into an attacker's account) | Tampering | TB1 | Django CSRF token required on every state-changing request **including login**; SameSite=Strict; CSRF failures audited as `access.denied` | `test_csrf_enforced_for_session_users` ✅, `test_login_requires_csrf_token` ✅, `test_logout_requires_csrf_token` ✅ |
| ID-4 | **Privilege escalation** (viewer or operator calls an admin endpoint directly, bypassing the UI) | Elevation of privilege | TB1 | Deny-by-default (`IsAuthenticated` globally); one capability table (`accounts/permissions.py`) and `require()` on every route; disabled accounts denied; generic 403; `access.denied` audit event | `test_role_matrix` ✅ (every role × every access level), `test_denied_request_is_audited` ✅; `test_viewer_cannot_revoke` (T5, Part 2) |
| ID-5 | **Spoofed node enrollment** (attacker invents or guesses a token) | Spoofing | TB2 | Tokens are 256-bit random, one-time, expire in 15 minutes, stored only as SHA-256 hashes; enrollment throttled 10/min; identical error for all token failures | T1 cases a to c (Week 4): no token, forged token, expired token |
| ID-6 | **Enrollment token reuse or race** (two devices use one leaked token) | Spoofing | TB2 | Token marked used in the same transaction that creates the node, with a conditional update; `used_by_node` unique | T1 case d: reused token; concurrent-enrollment test |
| ID-7 | **Node impersonation** (attacker claims an enrolled node's ID with their own key) | Spoofing | TB2 | Proof of possession at enrollment; every later request signed with the registered key; key cannot be changed after enrollment | T1 case e (with Member 2): wrong-key signature → `NODE_SIGNATURE_INVALID` |
| ID-8 | **Revoked node keeps working** | Elevation of privilege | TB2 | Status checked first on every node request; revoked nodes excluded from scheduling; in-flight tasks requeued | T5: heartbeat after revoke → `NODE_REVOKED`; no task assigned |
| ID-9 | **Audit log tampering or repudiation** (an insider deletes the record of their action) | Repudiation, Tampering | TB4 | Append-only at application level (model and queryset refuse changes) and database level (SQLite triggers); SHA-256 hash chain; `verify_audit_chain` command and `POST /audit/verify/` | `test_database_triggers_block_raw_sql` ✅, `test_edited_event_is_detected` ✅, `test_deleted_event_is_detected` ✅, `test_edit_with_recomputed_hash_is_still_detected_at_next_event` ✅ |
| ID-10 | **Secret or stack-trace leakage** through errors, logs or exports | Information disclosure | TB1, TB4 | Global exception handler returns only stable codes; validation messages never echo input; secrets read from `.env` (git-ignored); audit `details` redacted at any depth; exports exclude keys and hashes | `test_crash_hides_internal_details` ✅, `test_validation_errors_never_echo_input` ✅, `test_sensitive_keys_are_redacted_at_any_depth` ✅ |
| ID-11 | **SQL injection** through login, filters or search | Tampering | TB4 | Django ORM only (parameterised); input validated by strict serializers; no raw SQL with string formatting | `test_sql_injection_in_username_is_harmless` ✅, `test_invalid_filters_are_rejected` ✅; node search (Part 2) |
| ID-12 | **Oversized or malformed input** exhausting the server | Denial of service | TB1, TB2 | 256 KB body limit; JSON-only parser; unknown fields rejected; password length capped at 128 before hashing | `test_oversized_body_is_rejected` ✅, `test_malformed_json_is_rejected` ✅, `test_malformed_login_bodies_are_rejected` ✅ |

✅ = test already written and passing.

## 5. Residual risks (for the limitations statement)

- Rate limiting uses an in-memory cache, so limits reset when the server restarts and do not
  span several server processes. Acceptable for a single-laptop demo; production would use Redis.
- Throttling is per client IP and per username. Behind a shared NAT one attacker can lock out
  classmates for a minute, and anyone can lock a known username out for up to an hour.
- Deleting the newest audit events directly from the database file (bypassing SQLite) leaves a
  shorter chain that still verifies. Detecting this needs the latest hash kept outside the database.
- An administrator can still perform harmful actions; the design detects and records them
  (audit chain) rather than preventing them.
- The SQLite file itself is not encrypted at rest. Anyone with file-system access can read
  non-secret data; secrets are hashed, and tampering with the audit table is detectable.
- HTTPS is not used on localhost, so `COOKIE_SECURE` is off in development. It must be on in any
  deployment beyond the laptop.
