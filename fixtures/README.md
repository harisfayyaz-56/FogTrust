# fixtures/ (safe sample data)

Sample inputs for tests and the demo. Everything here must be **safe and synthetic**:

- no real passwords, keys, tokens, names or IP addresses
- demo accounts use obviously fake passwords that are documented in the README and
  changed before any shared deployment
- node keys used in fixtures are generated for testing only and marked `TEST ONLY`

Planned files (Week 1 to 2):

| File | Owner | Purpose |
|---|---|---|
| `users.json` | Member 1 | One admin, one operator, one viewer |
| `enrollment_cases.json` | Member 1 | Valid, expired, reused and forged tokens (T1) |
| `heartbeats.json` | Member 2 | Valid, stale, replayed, counter-regressed (T2) |
| `tasks.json` | Member 3 | Normal queue plus load-balancing scenarios (T3, T6) |
| `results.json` | Member 2 | Valid and tampered ciphertexts (T4) |
| `malformed/` | Member 4 | Oversized, wrong type, missing fields (T-final) |
