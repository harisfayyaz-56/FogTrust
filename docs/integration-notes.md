# Phase 3 integration notes — dashboard ↔ Django broker

This document records how the React dashboard connects to the real Django API,
which endpoints it uses, the mismatches found against `docs/api-contract.md`
and the backend code, and the backend changes the owner still needs to make.

The frontend was changed only under `frontend/`. No backend file was edited.

## 1. Running the two halves

```powershell
# Terminal 1 — broker (from the repo root, with backend dependencies installed)
cd backend
python manage.py migrate
python manage.py runserver 127.0.0.1:8000

# Terminal 2 — dashboard
cd frontend
npm install
npm run dev            # http://127.0.0.1:5173/
```

`frontend/.env` (git-ignored) and `frontend/.env.example` both contain:

```dotenv
VITE_USE_MOCK=false
VITE_API_BASE_URL=
```

- `VITE_USE_MOCK=false` is the real-mode default. Even if the file is missing,
  the client defaults to real mode.
- `VITE_API_BASE_URL` stays empty so requests use the Vite proxy
  (`/api` → `http://127.0.0.1:8000`). Set an absolute broker URL only when the
  dashboard is served from a different origin; then configure
  `DJANGO_CSRF_TRUSTED_ORIGINS` for that origin as well.
- The navbar "Demo Data Mode" toggle still switches to the bundled fixtures at
  runtime. Demo mode is fully offline: it returns fixtures without calling the
  broker, so a live session cannot leak real data into the demo. Real-mode
  failures are shown as errors and never silently replaced by mock data.

### CSRF and the dev proxy

`frontend/vite.config.ts` keeps the browser's `Host` header
(`changeOrigin: false`). Django compares the `Origin` header with the request
host during CSRF checks; rewriting `Host` to `127.0.0.1:8000` while `Origin`
remains `http://127.0.0.1:5173` makes every POST fail with `CSRF_FAILED`.

If the proxy is not used, the broker must trust the dashboard origin:

```dotenv
DJANGO_CSRF_TRUSTED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

The broker does not ship a CORS middleware. A cross-origin dashboard would also
need `django-cors-headers` (or a reverse proxy that makes both sides
same-origin). The proxy approach avoids both problems.

## 2. Authentication flow used by the dashboard

1. `GET /api/v1/auth/csrf/` sets the `csrftoken` cookie (readable by JS).
2. `POST /api/v1/auth/login/` sends `X-CSRFToken` and the credentials.
   The response sets the HttpOnly `fogtrust_session` cookie and rotates the
   CSRF token.
3. All requests use `credentials: 'include'`.
4. `GET /api/v1/auth/me/` returns `username`, `role`, `permissions` and
   `session_idle_timeout`.
5. Every mutating request sends the current `X-CSRFToken`.
6. On `403 CSRF_FAILED` the client fetches a fresh token and retries once.
7. On `401` from any endpoint except login, the client clears the session and
   shows the login screen. A network outage does **not** log the user out.
8. The visible idle countdown resets on every successful request, mirroring the
   server's idle timeout, so an active user is not signed out early.

The client maps server errors to short, safe messages:

| Status | Typical code | Dashboard message |
|---|---|---|
| 401 | `AUTH_INVALID_CREDENTIALS` | Invalid username or password. |
| 401 | `AUTH_REQUIRED`, `AUTH_SESSION_EXPIRED` | Your session has expired. Please sign in again. |
| 403 | `PERMISSION_DENIED` | Your role is not allowed to perform this action. |
| 403 | `CSRF_FAILED` | Your security token expired. Refresh the page and try again. |
| 413 | `PAYLOAD_TOO_LARGE` | The request is too large. Reduce the payload and try again. |
| 422 | `RESULT_INTEGRITY_FAILED` | The result failed an integrity check, so it was not accepted. |
| 429 | `RATE_LIMITED` | Too many requests. Please wait a moment and try again. |
| 500 | `INTERNAL_ERROR` | The broker hit an internal error. Try again; if it persists, contact an administrator. |
| 502/503/504 | `SERVICE_UNAVAILABLE` | The FogTrust broker is unavailable. Check that the backend is running. |
| transport | `NETWORK_ERROR` | Cannot reach the FogTrust broker. Check that the backend is running and the API URL is correct. |

## 3. Endpoints the dashboard calls

Base path is `/api/v1/`. "Wired" means the route exists in the current
`backend/config/urls.py` tree.

| Method | Path | Permission | Wired? | Frontend use |
|---|---|---|---|---|
| GET | `/health/` | public | yes | navbar health indicator |
| GET | `/auth/csrf/` | public | yes | CSRF bootstrap / refresh |
| POST | `/auth/login/` | public + CSRF | yes | sign in |
| POST | `/auth/logout/` | signed in | yes | sign out |
| GET | `/auth/me/` | signed in | yes | role, permissions, idle timeout |
| GET | `/nodes/` | `nodes.view` | yes | overview, nodes, trust picker, tasks, reports |
| GET | `/nodes/{id}/` | `nodes.view` | yes | node detail (available; views mostly use the list) |
| POST | `/nodes/{id}/revoke/` | `nodes.revoke` | yes | revoke node |
| GET | `/nodes/{id}/trust/` | `trust.view` | **no** | trust history chart/table |
| GET | `/nodes/{id}/heartbeats/` | any signed-in role | **no** | rejected-heartbeat evidence |
| GET | `/enrollment-tokens/` | `tokens.manage` | yes | token list |
| POST | `/enrollment-tokens/` | `tokens.manage` | yes | create one-time token |
| POST | `/enrollment-tokens/{id}/cancel/` | `tokens.manage` | yes | cancel token |
| GET | `/decisions/` | `decisions.view` | yes | overview, evidence, reports |
| GET | `/audit/` | `audit.view` | yes | overview, evidence, audit log, reports |
| POST | `/audit/verify/` | `audit.verify` | yes | hash-chain verification |
| GET | `/tasks/list/` | `tasks.view` | **no** | task queue |
| POST | `/tasks/` | `tasks.submit` | **no** | submit task (`Idempotency-Key`) |
| POST | `/tasks/{id}/cancel/` | `tasks.cancel` | **no** | cancel queued task |
| GET | `/policy/` | `policy.view` | **no** | trust policy view |
| POST | `/policy/` | `policy.change` | **no** | admin settings publish |
| GET | `/users/` | `users.manage` | yes | user management |
| POST | `/users/` | `users.manage` | yes | create user |
| PATCH | `/users/{id}/` | `users.manage` | yes | change role / enable / disable |

Reports are generated in the browser from nodes and decisions
(`frontend/src/services/report.ts`). The dashboard does not call a
`/reports/export/` endpoint, so the proposed route is not required for the
current UI.

## 4. Mismatches found

### 4.1 Tasks and trust apps are not installed or routed — blocking

`backend/config/settings.py` lists only `core`, `accounts`, `audit` and
`nodes` in `INSTALLED_APPS`. `backend/config/urls.py` includes only `core`,
`accounts`, `audit` and `nodes`. As a result:

- `/api/v1/tasks/...` and `/api/v1/tasks/list/` return `404`.
- `/api/v1/nodes/{id}/trust/` and `/api/v1/policy/` return `404`.
- The trust, task-queue, evidence and admin-settings screens cannot load real
  data yet.

`backend/tasks/urls.py` and `backend/trust/urls.py` already exist, so the fix
is small (see section 5).

### 4.2 Heartbeat history endpoint is missing — blocking evidence detail

The contract lists `GET /nodes/{id}/heartbeats/` and the evidence view calls
it, but no view or URL implements it. The client tolerates the failure
(`Promise.allSettled`), so the rest of the evidence screen still works; the
rejected-heartbeat list is simply empty. There is also no heartbeat model in
the routed apps yet.

### 4.3 Trust history is paginated

`NodeTrustHistoryView` extends `ListAPIView` with the project's
`StandardPagination`, so it returns
`{count, next, previous, results}`. The frontend originally expected a bare
array. `getNodeTrustHistory()` now accepts both shapes and returns the
`results` array.

### 4.4 Policy author field name

`PolicyConfigSerializer` returns `changed_by_username`; the dashboard type and
UI use `changed_by`. `getPolicy()`/`updatePolicy()` now map
`changed_by_username` → `changed_by`. No backend change is required.

### 4.5 Trust records have no `explanation` field

`TrustScoreRecordSerializer` returns `rules_fired`, but not a single
`explanation` string. The trust view displays one. The client now derives it
from the `reason` values in `rules_fired`, with a score-change fallback.

### 4.6 Task list path differs from the contract

The contract says `GET /tasks/`; `backend/tasks/urls.py` routes the list at
`GET /tasks/list/` because `POST /tasks/` is the submit route. The dashboard
uses `/tasks/list/`, matching the code. If the owner prefers the contract
path, add a GET handler on `/tasks/` or an alias; otherwise keep the current
path and update the contract.

### 4.7 Task response has fewer fields than the UI type

`TaskDetailSerializer` returns `assigned_node_name` but not `created_by` or
`deadline_at`. The frontend marks those fields optional and does not depend on
them. `assigned_node_name` was added to the TypeScript type; the UI still maps
the UUID to a name from the node list.

### 4.8 Enrollment token creation returns a partial object

`POST /enrollment-tokens/` returns only
`{id, label, token, expires_at}`. The list endpoint adds `status`, `created_by`
and `used_by_node`. The client fills `created_at`, `used_at` and
`cancelled_at` so the creation response is safe to pass around, then reloads
the list. No backend change is required.

### 4.9 Revocation response is partial

`POST /nodes/{id}/revoke/` returns only
`{id, status, revoked_at, revoked_by, revoke_reason}`. The dashboard refetches
the node list after a successful revocation, so it does not depend on the
partial object. No backend change is required.

### 4.10 Permission names

The frontend previously used UI-only names such as `tokens.view`,
`tokens.create`, `tokens.cancel`, `users.view` and `users.create`. The backend
`CAPABILITIES` map exposes `tokens.manage` and `users.manage`. The demo
permission sets, sidebar gates and route guards now use the backend names
exactly. `nodes.enroll` was removed because it is not a backend capability.

### 4.11 Error envelope

The backend envelope
`{"error": {"code", "message", "request_id", "details?"}}` matches what the
client already parsed. No change is required.

## 5. Backend changes requested from the owner

1. Add the missing apps to `INSTALLED_APPS` in `backend/config/settings.py`:

   ```python
   "tasks",
   "trust",
   ```

2. Include their URL maps in `backend/config/urls.py`:

   ```python
   path("api/v1/", include("tasks.urls")),
   path("api/v1/", include("trust.urls")),
   ```

3. Run migrations for the newly installed apps:

   ```powershell
   python manage.py makemigrations tasks trust
   python manage.py migrate
   ```

4. Implement `GET /api/v1/nodes/{id}/heartbeats/` (any signed-in role) with the
   standard paginated envelope and `?accepted=true|false`. The dashboard
   expects the fields already declared in `HeartbeatRecord`:
   `id`, `node`, `node_name`, `counter`, `nonce_prefix`, `sent_at`,
   `received_at`, `reported_load`, `accepted`, `reason_code`.

5. Decide the canonical task list path. Either keep `/tasks/list/` and update
   `docs/api-contract.md`, or add a `GET /tasks/` list handler. The current
   dashboard uses `/tasks/list/`.

6. Optional, to remove frontend normalisation: return `changed_by` as well as
   `changed_by_username`, add `explanation` to trust records, and return
   `created_by`/`deadline_at` on tasks.

7. If the dashboard will not use the Vite proxy, add CORS support and set
   `DJANGO_CSRF_TRUSTED_ORIGINS` for the dashboard origin. With the proxy this
   is not needed.

## 6. Acceptance status

The dashboard was exercised against a temporary local broker (Django 5.2.19,
SQLite, `DEBUG=True`) with one admin, one operator and one viewer, two nodes
(one active, one revoked) and two enrollment tokens. No backend file was
modified for the test.

| Acceptance item | Result |
|---|---|
| Real login as each role | **Pass.** `admin1`, `operator1` and `viewer1` signed in through the Vite proxy with the session cookie and CSRF header. The navbar showed the correct role for each. |
| Real nodes | **Pass.** `/nodes/` rendered `gateway-01` (active, trust 92) and `gateway-02` (revoked, trust 40) with real UUIDs, fingerprints and load. |
| Real trust scores | **Partial.** Node `trust_score` is real and visible in the fleet and overview. Per-node history is blocked: the `trust` app is not installed/routed, so `/nodes/{id}/trust/` returns 404 and the view shows "The requested resource is not available on the FogTrust broker." |
| Real tasks | **Blocked.** The `tasks` app is not installed/routed, so `/tasks/list/` returns 404. The task queue and the overview's task count show a clear error; other overview data still renders. |
| Real audit events | **Pass.** `/audit/` listed real events (`auth.login`, `audit.verify`) and `/audit/verify/` reported the chain intact. |
| Wrong-role action shows "not allowed" | **Pass.** An operator and a viewer calling the real client's `revokeNode`, `getUsers` and `getEnrollmentTokens` each received `403 PERMISSION_DENIED`, mapped to "Your role is not allowed to perform this action." Admin-only tabs were absent from their sidebars. |
| Session expiry | **Pass.** Deleting the server-side sessions and then making a request produced `401`; the client cleared the session and showed the login screen. |
| Demo mode unaffected | **Pass.** The demo role buttons and the "Demo Data Mode" toggle still load fixture data; toggling demo off with no real session returns to the login screen. |

Build and unit tests pass: `npm run build`, `npm test` (6/6).

Two behaviours worth knowing:

- The overview treats a partial endpoint failure as a warning, not a fatal
  error, so the nodes, trust, decisions and audit cards remain usable while
  tasks are unavailable. A total failure of nodes, decisions and tasks still
  shows the error state.
- `404` is mapped to "The requested resource is not available on the FogTrust
  broker." An unrouted endpoint (the current tasks/trust case) therefore looks
  different from a network outage or a permission error.

Once the backend owner applies section 5, re-run the smoke test below; the
trust and task rows should then move from "blocked" to "pass" without any
further frontend change.

### Smoke test

```powershell
# Real mode, backend on 127.0.0.1:8000
cd frontend
npm run dev
```

1. Sign in as an admin: check nodes, audit, tokens, users and policy.
2. Sign in as an operator: tasks and reports are visible; tokens, users and
   admin settings are hidden; a forced revoke returns "Your role is not
   allowed to perform this action."
3. Sign in as a viewer: only read-only tabs are visible; task submit/cancel and
   policy changes are refused by the server.
4. Let the session idle past `SESSION_IDLE_TIMEOUT_SECONDS`: the next request
   returns 401, the client clears the session and shows the login screen.
5. Toggle "Demo Data Mode": the fixture data returns, and toggling it off
   restores the real session (or the login screen if it expired).
