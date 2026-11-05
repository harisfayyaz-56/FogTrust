## What this PR does

<!-- One or two sentences. Link the requirement: FR-1 ... FR-7, T1 ... T6, T-final -->

## Slice / owner

- [ ] Member 1 — Identity, Access and Audit
- [ ] Member 2 — Cryptography and Node Simulator
- [ ] Member 3 — Scheduler and Trust Engine
- [ ] Member 4 — Dashboard, Evidence and QA

## How I tested it

<!-- Commands you ran, new tests added -->

## Security checklist

- [ ] No secrets, keys, tokens or `.env` committed
- [ ] Input validated on the server (types, sizes, allowed values)
- [ ] Permissions checked on the server for every new endpoint
- [ ] Errors use codes from `backend/core/errors.py`; no stack traces or input echoed back
- [ ] Security-relevant actions are written to the audit log (once it exists)
- [ ] `python -m pytest` passes locally
