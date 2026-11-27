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
| [docs/guide-identity-admin.md](docs/guide-identity-admin.md) | User and administrator guide: roles, sign-in, users, enrollment tokens, revocation, audit log |
| [docs/diagrams/identity-slice-dataflow.md](docs/diagrams/identity-slice-dataflow.md) | Data flow and trust boundaries for people, enrollment and the audit log |
| [docs/identity-limitations-ethics.md](docs/identity-limitations-ethics.md), [docs/demo-script-identity.md](docs/demo-script-identity.md), [docs/report-section-identity.md](docs/report-section-identity.md) | Limitations and ethics, demo script, report section for the identity slice |
| [docs/guide-node-and-crypto.md](docs/guide-node-and-crypto.md) | User and administrator guide: node keys, enrollment, rejection codes, server key, policy, revocation |
| [docs/node-signing-spec.md](docs/node-signing-spec.md) | How requests are signed, replay defence, result encryption |
| [docs/security-review-api.md](docs/security-review-api.md) | Every API route, how it is authenticated, and the findings |
| [docs/diagrams/crypto-slice-dataflow.md](docs/diagrams/crypto-slice-dataflow.md) | Data flow and trust boundaries for nodes and results |
| [docs/sample-data/](docs/sample-data/) | Sanitized signed requests with their expected outcomes |
| [docs/crypto-limitations-ethics.md](docs/crypto-limitations-ethics.md), [docs/demo-script-crypto.md](docs/demo-script-crypto.md), [docs/report-section-crypto.md](docs/report-section-crypto.md) | Limitations and ethics, demo script, report section for this slice |

## Status

| Week | Milestone | State |
|---|---|---|
| 1 | Requirements, data model, API contract, threat model, skeleton | Done |
| 2 | Authentication, audit log, one end-to-end slice | Done |
| 3 | Security engine, dashboard, features | Backend done: identity, enrollment, revocation, users, evidence data, replay defence, encrypted results, trust engine, task queue, signed node authentication, heartbeat and result endpoints. Dashboard pending |
| 4 | Integration, adversarial tests, measurement, hardening | Backend done: attack runs T1 to T5, fuzzing, measurements, security review (see test-evidence). Dashboard integration pending |
| 5 | Fixes, evaluation, documentation, demo | In progress |