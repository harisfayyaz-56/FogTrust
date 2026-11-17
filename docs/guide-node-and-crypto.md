# User and administrator guide: nodes, keys and encrypted results

For the people who run edge nodes and the administrators who look after the broker's keys. Installing and starting the server is in the [README](../README.md); this guide starts after that.

## 1. Node operators

A node is one machine (here, a simulated one) that proves its identity with a private key and sends signed requests. Three files matter, all in one folder (default `backend/keys/`, which Git ignores):

| File | What it is | Treat it as |
|---|---|---|
| `<name>.key` | The node's private key | A password. Never share it, never commit it, never put it in a synced folder such as OneDrive |
| `<name>.state.json` | The node id and the heartbeat counter | Needed to keep working; losing it means re-enrolling |

### Start a node
```bash
cd backend
python -m fogtrust_crypto.node_sim keygen --key-file keys/gateway-01.key                 # once: creates the identity
# an administrator gives you a one-time enrollment token (it works once and expires)
FOGTRUST_ENROLL_TOKEN=<token> python -m fogtrust_crypto.node_sim enroll --key-file keys/gateway-01.key --name gateway-01
python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-01.key --count 5 --interval 10
```
PowerShell: `$env:FOGTRUST_ENROLL_TOKEN = "<token>"` instead of the `VAR=value` prefix. Add `--dry-run` to see the signed request without sending it.

### Send a result
```bash
python -m fogtrust_crypto.node_sim result --key-file keys/gateway-01.key --task-id <task id> --payload '{"answer":42}'
```
The result is encrypted on the node, so only the broker can read it, and a changed byte is detected. The task must be assigned to your node.

### If a request is refused
The reply carries a code. What it means and what to do:

| Code | Meaning | What to do |
|---|---|---|
| `NODE_SIGNATURE_MISSING` | The signed-request headers are missing | You are not using the node program, or a proxy removed the headers |
| `NODE_SIGNATURE_INVALID` | The signature does not match | The key file does not belong to this node id, or the message was changed on the way. If you lost the key, enroll again |
| `NODE_UNKNOWN` | This node id is not enrolled | Check the `.state.json`; enroll again with a new token |
| `NODE_REVOKED` | An administrator banned this node | It cannot recover. Ask the administrator, who must issue a new token |
| `HEARTBEAT_STALE` | Your clock is too far from the server's (default limit 30 s) | Correct the node's clock (network time) |
| `HEARTBEAT_REPLAYED` | The broker already received this exact message | Do not resend the same bytes. A retry must be signed again with a new nonce (the program does this) |
| `HEARTBEAT_COUNTER_REGRESSED` | The counter did not go up | The node restarted without its counter. Keep `.state.json` safe; if it is lost, enroll again |
| `RESULT_INTEGRITY_FAILED` | The result was damaged before it was signed | A bug on the node. Repeated failures lower the node's trust and end in automatic revocation |
| `RESULT_NOT_ASSIGNED` | The task is not assigned to this node (or does not exist) | Only send results for tasks you were given |
| `TASK_INVALID_STATE` | The task already has a result, or is not waiting for one | Nothing; do not resend |
| `PAYLOAD_TOO_LARGE` / `VALIDATION_ERROR` / `MALFORMED_REQUEST` | The message is too big or the wrong shape | Heartbeats are at most 2 KB, results about 48 KB of data |
| `RATE_LIMITED` | Too many requests | Slow down (heartbeats: 120 per minute per node) |

### If you think your key was stolen
Tell an administrator immediately so the node is revoked. A stolen key is a stolen identity until then.

## 2. Administrators

### The server key (once)
```bash
cd backend
python manage.py generate_server_key        # prints one line; add it to .env, then restart the server
```
- It creates the broker's private result-encryption key in a file only your account can read. **Back it up somewhere safe and never commit it.** Without it, stored results cannot be read; with it, anyone can read every stored result. There is no key rotation in this version.
- Nodes receive the matching public key when they enroll.

### Enrolling nodes
Create a one-time token (`python manage.py create_enrollment_token --label "lab node" --minutes 15`, or in the dashboard), give it to the operator over a private channel, and let it expire unused if it is not needed. Each token enrolls exactly one node.

### Settings that change how requests are judged
| Setting (policy) | Default | Effect |
|---|---|---|
| `timestamp_window_s` | 30 | How far a node's clock may differ. Larger forgives clock drift but accepts a delayed message for longer |
| `heartbeat_interval_s` | 10 | How often nodes are told to send heartbeats |

Every change is recorded in the audit log with who changed it and the old and new value.

### Revoking a node
Use the dashboard or `POST /api/v1/nodes/{id}/revoke/` with a reason and confirmation. The node's next request is refused with `NODE_REVOKED`, and its assigned tasks go back to the queue.

### Reading the evidence
- **A node's heartbeat history** (`GET /api/v1/nodes/{id}/heartbeats/`, also on the dashboard's node page once the dashboard is deployed): every heartbeat from an enrolled node, accepted or refused, with the reason. Filter with `?accepted=false` or `?reason_code=...`.
- **Decisions** (`GET /api/v1/decisions/`): for each refusal, every rule that was checked and which one failed (for example: signature and timestamp passed, nonce check failed, so it was a replay).
- **A task's result** (`GET /api/v1/tasks/{id}/result/`, operators and administrators): the decrypted result and whether it is intact. Every time someone opens one, the audit log records it.

### Housekeeping
- `python manage.py purge_nonces` removes replay-defence records whose time window has passed. It also happens automatically, so this is optional.
- `python manage.py verify_audit_chain` checks that the audit log has not been edited.

### Trust and automatic revocation
A node's trust score changes only on evidence the node itself produced: a verified result raises it, a damaged result lowers it (by 25), and three damaged results revoke the node. Bad requests from strangers that merely use a node's id (wrong signature, replays, old messages) are refused but never lower its score, so nobody can ban a node from outside.

## 3. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Every heartbeat is `HEARTBEAT_STALE` | The node's clock is wrong |
| `INTERNAL_ERROR` on every result | The server key is not configured (`generate_server_key`, then restart) |
| `RESULT_NOT_ASSIGNED` for a task you can see | It is assigned to a different node |
| A node stopped receiving tasks | Its trust score is below the threshold, or it is full (capacity), or it went silent |
| Tests complain about the server key file permissions | The key file must not be readable by other users (Linux and macOS) |