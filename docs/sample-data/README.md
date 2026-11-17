# Sample data (test-fixture layer)

`heartbeats.json` and `results.json` are complete, signed requests with the outcome each must produce: normal cases and
the attacks from T1, T2, T4 and T5 (spoofed node, replay, altered result, revoked node), plus oversized and malformed input.

- **Only public material is in these files** (public keys, headers, bodies, ciphertext). The keys behind them are derived from public strings that end in `TEST-ONLY` inside `backend/fogtrust_crypto/samples.py`. They are for testing and must never be used for anything real.
- Cases run **in order** against a fresh replay store, so the "replay" case really is a copy of the case before it.
- Check them: `cd backend && python -m fogtrust_crypto.samples --check ../docs/sample-data` (prints PASS or FAIL per case; exit code 1 on any FAIL).
- Recreate them: `python -m fogtrust_crypto.samples --write ../docs/sample-data`.
- The test suite does both: `backend/fogtrust_crypto/tests/test_samples.py`.

| File | Cases |
|---|---|
| `heartbeats.json` | 14: valid, replay, counter not increasing, wrong key, body altered, stale, future, unknown node, no headers, not JSON, unexpected field, oversized, revoked node, valid again |
| `results.json` | 10: valid, replay, altered before signing, altered in transit, made for another task, assigned elsewhere, wrong key, stale, not JSON, wrong envelope |