# User and administrator guide: accounts, roles, enrollment tokens, revocation and the audit log

Member 1's slice. For node keys and encrypted results see `guide-node-and-crypto.md`.
All commands run from `backend/` with the virtual environment active.

## 1. Roles

| Role | Can do |
|---|---|
| **Viewer** | Sign in and read: nodes, tasks, trust scores, decisions, policy |
| **Operator** | Everything a viewer can, plus submit and cancel tasks, view results, export reports |
| **Administrator** | Everything, plus enrollment tokens, revoking nodes, policy changes, user management, the audit log |

New accounts are **viewers** unless an administrator chooses otherwise. Roles are checked by the server on
every request, so a role change or a disabled account takes effect on the user's very next click.

## 2. Signing in

- Sign in on the dashboard with your username and password.
- After **5 failed attempts in a minute** from one computer, or **20 in an hour** for one username, login is paused (`RATE_LIMITED`). Wait and try again.
- Your session ends after **30 minutes without activity**, **8 hours after you signed in**, or when you close the browser. You will see "Your session has expired. Please sign in again."
- "Invalid username or password" is shown for every failed login on purpose; ask an administrator if your account may be disabled.

## 3. Administrators: first setup

```
python manage.py migrate
python manage.py createsuperuser          # your own administrator account
python manage.py seed_demo_users          # demo only: admin1, operator1, viewer1 with random passwords, shown once
```

## 4. Managing users

| Task | API |
|---|---|
| List users | `GET /api/v1/users/?role=operator` |
| Create a user | `POST /api/v1/users/` `{"username": "...", "password": "...", "role": "operator"}` |
| Change a role | `PATCH /api/v1/users/{id}/` `{"role": "viewer"}` |
| Disable / re-enable | `PATCH /api/v1/users/{id}/` `{"is_active": false}` |

Passwords must be at least 10 characters, not common and not all digits. You cannot remove your own
administrator role or disable yourself (this prevents locking everyone out). Every change is audited.

## 5. Enrolling a node

1. Create a one-time token: dashboard, or `POST /api/v1/enrollment-tokens/` `{"label": "gateway in lab 2", "expires_in_minutes": 15}`,
   or on the server: `python manage.py create_enrollment_token --label "gateway in lab 2"`.
2. **Copy the token now.** It is shown once; the server keeps only its hash.
3. Give it to the node operator through a private channel. It works **once** and expires after 15 minutes by default.
4. The node enrolls itself (`guide-node-and-crypto.md`). It appears in the node list as `active`.
5. A token you no longer need: `POST /api/v1/enrollment-tokens/{id}/cancel/`.

If enrollment is refused, the node only sees "Enrollment rejected." The real reason (expired, already used,
cancelled, wrong proof) is in the audit log and the Evidence view.

## 6. Revoking a node

Use this when a node is compromised, misbehaving or retired.

`POST /api/v1/nodes/{id}/revoke/` `{"reason": "3 integrity failures in 10 minutes", "confirm_name": "gateway-03"}`

- `confirm_name` must be the node's **exact** name; otherwise nothing happens (`CONFIRMATION_REQUIRED`).
- The reason must be 10 to 500 characters and is stored with your username and the time.
- Effect is immediate: the node's next request gets `NODE_REVOKED`, it receives no new tasks, and its in-flight tasks go back to the queue.
- **Revocation is permanent.** To bring the device back, give it a new token; it must use a **new key** and gets a new node ID.
- The trust engine can also revoke automatically when a score falls below the policy limit; these show `source: automatic`.

## 7. The audit log

| Task | How |
|---|---|
| Read it | `GET /api/v1/audit/?action=node.revoke&outcome=failure&since=2026-11-20T00:00:00Z` |
| Check nothing was changed | `POST /api/v1/audit/verify/`, or `python manage.py verify_audit_chain` |

A healthy result is `"valid": true`. If it says `valid: false`, note `first_broken_sequence` and `problem`,
stop using the database, and keep a copy for investigation:

| Problem | Meaning |
|---|---|
| `hash_mismatch` | That event was edited |
| `link_mismatch` | That event was replaced or reordered |
| `sequence_gap` | An event before it was deleted |

The log cannot be edited or deleted through the application or SQL. To start a clean local database,
delete `db.sqlite3` and run `migrate` again (`manage.py flush` will be refused).

## 8. Troubleshooting

| You see | Meaning | What to do |
|---|---|---|
| `AUTH_REQUIRED` | Not signed in | Sign in |
| `AUTH_SESSION_EXPIRED` | Idle or 8-hour limit reached | Sign in again |
| `PERMISSION_DENIED` "Access denied." | Your role cannot do this | Ask an administrator |
| `CSRF_FAILED` | Security token missing or stale | Refresh the page |
| `RATE_LIMITED` | Too many attempts | Wait for the time in `Retry-After` |
| `CONFIRMATION_REQUIRED` | Revoke name did not match | Type the node name exactly |
| `NODE_ALREADY_REVOKED` | Someone revoked it first | Nothing to do |
| `CONFLICT` on a user change | You tried to demote or disable yourself | Ask another administrator |

Every error includes a `request_id`. Quote it when reporting a problem: the same ID is in the server log and the audit event.
