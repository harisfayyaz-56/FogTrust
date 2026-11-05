# FogTrust: Secure Edge-to-Cloud Task Broker

A simulated fog-computing broker that **authenticates edge nodes and assigns jobs only to nodes
that are trusted and have capacity**. Nodes enroll with a one-time token, prove their identity with
Ed25519 signatures, send signed heartbeats, and return encrypted, tamper-evident results. Every
decision is explained and recorded in an append-only, hash-chained audit log.

Class 2, Group 2 — Cloud and Fog Computing Security (Proposal 17).

## Team

| Member | Slice | Requirements |
|---|---|---|
| Member 1 — Ayesha | Identity, Access and Audit | FR-1 Enrollment, FR-6 Revocation, login, roles, audit log |
| Member 2 | Cryptography and Node Simulator | FR-2 Signed heartbeat, FR-5 Encrypted results |
| Member 3 | Scheduler and Trust Engine | FR-3 Task queue, FR-4 Trust score |
| Member 4 | Dashboard, Evidence and QA | FR-7 Operations dashboard, test runner, packaging |

## Repository layout

```
backend/            Django + DRF API (layers 2 and 4: API and repository)
  config/           settings, URLs
  core/             health check, error codes, exception handler, request IDs
  accounts/         users and roles
engine/             security engine, plain Python (layer 3)
simulator/          edge node simulator scripts
frontend/           React dashboard (layer 1)
fixtures/           safe sample data (layer 5)
docs/               data model, API contract, threat model, decisions
```

## Requirements

- Python 3.11, 3.12 or 3.13
- Git
- VS Code (recommended), with the Python extension

## First-time setup

### Windows (PowerShell)

```powershell
git clone <repo-url>
cd fogtrust
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

If PowerShell blocks the activation script, run this once and try again:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### macOS / Linux

```bash
git clone <repo-url>
cd fogtrust
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

### Then, on every OS

1. Open `.env` and paste the generated value after `DJANGO_SECRET_KEY=`.
2. Create the database and an admin account:

   ```
   cd backend
   python manage.py migrate
   python manage.py createsuperuser
   ```

3. Start the server:

   ```
   python manage.py runserver
   ```

4. Open http://127.0.0.1:8000/api/v1/health/ — you should see `"status": "ok"`.
   The developer data view is at http://127.0.0.1:8000/django-admin/.

## Running tests

From the repository root (with the virtual environment active):

```
python -m pytest
```

Tests use `config.settings_test`, an in-memory database and a throwaway secret key, so they do not
need `.env` and never touch your local data.

## Documentation

| Document | Contents |
|---|---|
| [docs/data-model.md](docs/data-model.md) | Tables, decision schema, audit event format, input validation rules |
| [docs/api-contract.md](docs/api-contract.md) | Endpoints, request and response shapes, roles, error codes |
| [docs/threat-model/](docs/threat-model/) | Threats and mitigations per slice |
| [docs/decisions/](docs/decisions/) | Architecture decision records |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Branching, commits, review rules |

## Status

| Week | Milestone | State |
|---|---|---|
| 1 | Requirements, data model, API contract, threat model, skeleton | In progress |
| 2 | Authentication, audit log, one end-to-end slice | Planned |
| 3 | Security engine, dashboard, features | Planned |
| 4 | Integration, adversarial tests, measurement, hardening | Planned |
| 5 | Fixes, evaluation, documentation, demo | Planned |
