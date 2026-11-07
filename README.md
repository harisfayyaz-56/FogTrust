# FogTrust

A secure edge-to-cloud task broker for a simulated fog-computing network.

Edge nodes enroll with a one-time token and prove their identity with Ed25519 signatures. The broker
verifies signed heartbeats, scores each node's trustworthiness, and assigns tasks only to trusted
nodes with spare capacity. Results come back encrypted and tamper-evident, misbehaving nodes can be
revoked, and every decision is recorded in an append-only, hash-chained audit log.

**Stack:** Python, Django REST Framework, SQLite, `cryptography`, React

## Quick start

Requires Python 3.11 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
```

Copy `.env.example` to `.env` and set `DJANGO_SECRET_KEY` to a random value:

```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

Then:

```bash
cd backend
python manage.py migrate
python manage.py generate_server_key     # result-encryption key; paste the line it prints into .env
python manage.py seed_demo_users         # admin1, operator1, viewer1 with random passwords (shown once)
python manage.py runserver
```

Check http://127.0.0.1:8000/api/v1/health/ returns `"status": "ok"`.
(`createsuperuser` also works and always creates an administrator.)

### Enroll a simulated node

```bash
cd backend
TOKEN=$(python manage.py create_enrollment_token --label "lab node" --minutes 15)   # printed once
python -m fogtrust_crypto.node_sim keygen --key-file keys/gateway-01.key
FOGTRUST_ENROLL_TOKEN=$TOKEN python -m fogtrust_crypto.node_sim enroll --key-file keys/gateway-01.key --name gateway-01
```

Administrators can do the same from the API (`POST /api/v1/enrollment-tokens/`), list nodes
(`GET /api/v1/nodes/`) and revoke one (`POST /api/v1/nodes/{id}/revoke/`). See the API contract.
On Windows PowerShell use `$env:FOGTRUST_ENROLL_TOKEN = "<token>"` instead of the `VAR=value` prefix.

## Tests

```bash
python -m pytest
```

## Documentation

| Document | Contents |
|---|---|
| [docs/data-model.md](docs/data-model.md) | Tables, decision schema, audit event format, input validation rules |
| [docs/api-contract.md](docs/api-contract.md) | Endpoints, request and response shapes, roles, error codes |
| [docs/threat-model/](docs/threat-model/) | Threats and mitigations per slice |
| [docs/test-evidence/](docs/test-evidence/) | Input, expected, actual and result for T1 to T5 and T-final, with measurements |
| [docs/decisions/](docs/decisions/) | Architecture decision records |

## Status

| Week | Milestone | State |
|---|---|---|
| 1 | Requirements, data model, API contract, threat model, skeleton | Done |
| 2 | Authentication, audit log, one end-to-end slice | Done |
| 3 | Security engine, dashboard, features | In progress: identity, enrollment, revocation, users and evidence view done; replay defence and encrypted results done; heartbeat/task endpoints, trust engine and dashboard pending |
| 4 | Integration, adversarial tests, measurement, hardening | Planned |
| 5 | Fixes, evaluation, documentation, demo | Planned |
