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
python manage.py createsuperuser
python manage.py runserver
```

Check http://127.0.0.1:8000/api/v1/health/ returns `"status": "ok"`.

## Tests

```bash
python -m pytest
```

## Documentation

Design documents (data model, API contract, threat model) are in [`docs/`](docs/).
See [CONTRIBUTING.md](CONTRIBUTING.md) for branch and commit conventions.
