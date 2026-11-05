# engine/ (security engine)

Plain Python, **no Django imports**, so every function can be unit-tested on its own
(the brief requires the security engine to be "independently testable").

| Package | Owner | Contents |
|---|---|---|
| `engine/crypto/` | Member 2 | Ed25519 signing and verification, replay checks, result encryption (X25519 + HKDF + AES-256-GCM) |
| `engine/trust/` | Member 3 | Rule-based trust score, eligibility, load balancer |

Rules for this folder:

- Functions take plain values (bytes, str, dicts, dataclasses) and return a decision object
  that matches the **Decision schema** in `docs/data-model.md`, section 4.
- No database access, no network calls, no global state. The Django layer loads data,
  calls the engine, and saves the result.
- Every decision carries `engine_name`, `engine_version`, `reason_code` and `rules_fired`
  so it can be reproduced later.
