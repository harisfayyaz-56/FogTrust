# ADR-001: Use Django REST Framework instead of FastAPI

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-05 |
| Decided by | All four members |

## Context

The project brief suggests Python, FastAPI, asyncio, `cryptography` and SQLite, and states that
equivalent open-source tools may be approved. Acceptance requires **zero unresolved critical
authorization, injection or secret-exposure defects**.

## Decision

Use **Django 5.2 LTS with Django REST Framework**, SQLite, and the `cryptography` library.
The security engine stays a separate plain-Python package with no Django imports.

## Reasons

1. Password hashing (Argon2), sessions with expiry, CSRF protection, permission classes,
   throttling and parameterised queries are built in and widely reviewed. With FastAPI the
   team would assemble these from several libraries, and each hand-built piece is a place
   for a critical defect.
2. The team already knows Django, which shortens Week 2.
3. Migrations and the admin panel help inspect data during development.
4. Django 5.2 is a long-term-support release (security fixes until April 2028).

## Consequences

- Request validation uses DRF serializers instead of Pydantic.
- Heartbeat handling is synchronous; at the demo scale (5 to 10 simulated nodes) this is
  measured in the T6 experiment rather than assumed.
- Instructor approval for the equivalent stack is recorded below.

## Approval

| Date | Approved by | Evidence |
|---|---|---|
| _fill in_ | _instructor / TA name_ | _screenshot or message link_ |
