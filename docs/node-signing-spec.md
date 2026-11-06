# Node Signing Spec (Member 2)

| | |
|---|---|
| Version | 0.1 (Week 2) |
| Author | Member 2 |
| Implements | [api-contract.md](api-contract.md) section 2.2, plus the enrollment proof in section 5.4 |
| Code | `backend/fogtrust_crypto/` (`keys.py`, `node_auth.py`, `result.py`, `node_sim.py`) |

This file records how the signing scheme in the contract is implemented, and the small
clarifications Member 2 needs the team to accept. Nothing here changes a field name or shape.

## 1. What is signed

```
string_to_sign = METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" hex(SHA-256(body))
```

| Part | Rule | Why |
|---|---|---|
| METHOD | Upper case: `GET POST PUT PATCH DELETE` | Stops a signed POST being replayed as another method |
| PATH | The request target as sent, **including `?query` if there is one** (`request.get_full_path()` in Django) | An unsigned query string could be altered by an attacker |
| TIMESTAMP | Integer Unix seconds, 0 to 10^12 | No floats, so both sides print the same digits |
| NONCE | Exactly 32 lowercase hex characters | One format, no case ambiguity |
| body | The **raw bytes** that were sent, hashed with SHA-256. Empty body is hashed too | The node signs what it sends; the server hashes what it received. No JSON re-serialising, so no "same data, different bytes" failures |

Any value containing a newline, a space or a non-ASCII character is refused before signing or
verifying, so one field can never be read as part of another.

The signature is Ed25519, sent base64 in `X-Node-Signature` (64 bytes decoded).

## 2. Check order implemented (Week 2)

| Step | Check | Code | HTTP |
|---|---|---|---|
| 1 | The four headers are present and non-empty | `NODE_SIGNATURE_MISSING` | 401 |
| 2 | Node id is a UUID and an enrolled node | `NODE_UNKNOWN` | 401 |
| 3 | Node status is `active` (**before** the signature, as the contract says) | `NODE_REVOKED` | 403 |
| 4 | Timestamp, nonce and signature are well formed, and the signature verifies | `NODE_SIGNATURE_INVALID` | 401 |

Steps 5 and 6 (timestamp window, nonce, counter) are added in Week 3. A successful
verification already returns the signed `timestamp` and `nonce` for them.

## 3. Clarifications to record in the contract changelog

1. **PATH includes the query string.** Section 2.2 says `PATH`; this fixes what that means.
2. **The server must read `request.body` (raw bytes) before DRF parses `request.data`.**
3. **A malformed timestamp, nonce or signature header is `NODE_SIGNATURE_INVALID`**, reported at step 4,
   after the node lookup. Only an absent or empty header is `NODE_SIGNATURE_MISSING`.
4. **The client sees only the generic message** from `errors.py`. The precise code goes to the audit log
   and the Decision, which is what the T1 and T2 evidence uses.

Suggested changelog row for `api-contract.md` section 7:

| Date | Version | Change | By |
|---|---|---|---|
| (date) | 0.2 | Section 2.2: PATH includes the query string; raw body bytes are hashed; malformed signed headers return `NODE_SIGNATURE_INVALID` | Member 2 |

## 4. Verification result

`verify_node_request()` returns a `VerificationResult`. `result.to_decision("heartbeat")` gives a dict in the
shared Decision schema ([data-model.md](data-model.md) section 4): `decision` (`allow` or `deny`),
`reason_code`, `explanation`, `rules_fired` (every rule evaluated), `evidence`, `engine_name`,
`engine_version`, `thresholds`, `latency_ms`, `decided_at`. The API layer adds `decision_id` and `request_id`.

`evidence` holds only non-secret values: node id, an 8-character key-fingerprint prefix, the claimed
timestamp, a 4-character nonce prefix and an 8-character body-hash prefix. Never keys, signatures or bodies.

## 5. Calling it from the API layer (for Member 1)

Not yet run against a real `Node` model, because that model does not exist yet. The shape is:

```python
from fogtrust_crypto.node_auth import NodeInfo, verify_node_request

def lookup(node_id):
    node = Node.objects.filter(id=node_id).first()
    return NodeInfo(node.public_key, node.status) if node else None

raw_body = request.body  # read BEFORE touching request.data
result = verify_node_request(request.headers, request.method, request.get_full_path(), raw_body, lookup)
decision = result.to_decision("heartbeat")        # store as a Decision row
if not result.accepted:
    raise APIError(result.reason_code)            # audit action: heartbeat.rejected / node.request_rejected
```

For enrollment, call `verify_enrollment_proof(public_key, token, name, proof)` from `fogtrust_crypto.keys`
instead of writing a second implementation. It returns `False` on any bad input and never raises.

## 6. Running the node simulator

From the `backend/` folder:

```bash
python -m fogtrust_crypto.node_sim keygen    --key-file keys/gateway-03.key
python -m fogtrust_crypto.node_sim enroll    --key-file keys/gateway-03.key --name gateway-03   # token from FOGTRUST_ENROLL_TOKEN
python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-03.key --count 5 --interval 2
python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-03.key --dry-run
```

`keys/` is git-ignored. The state file next to the key holds the node id and the heartbeat counter,
which is saved **before** each send so a number is never reused. On Windows, file mode bits do nothing:
keep `keys/` in a folder only your account can read.

## 7. Known limits (for the limitations statement)

- A stolen private key is full impersonation until an admin revokes the node.
- If a node loses its counter file it must be re-enrolled (Week 3 replay rules).
- Node clocks must be roughly correct (Week 3 timestamp window).