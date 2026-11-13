# Demo script: Member 2's part (about 3 minutes)

Run from `backend/` with the server running (`python manage.py runserver`) and an admin signed in on the dashboard to create tokens.

| Time | Say | Do | What the audience sees |
|---|---|---|---|
| 0:00 | "An edge node must prove who it is on every request." | `python -m fogtrust_crypto.demo --server http://127.0.0.1:8000` (token in `FOGTRUST_ENROLL_TOKEN`) | The node enrolls; honest heartbeats return `200 OK` |
| 0:40 | "A spoofer uses the node's id with another key." | (same run, step 3) | `401 NODE_SIGNATURE_INVALID` |
| 1:00 | "An attacker captured a valid heartbeat and sends it again." | (steps 5 and 6) | First `200`, then `401 HEARTBEAT_REPLAYED` |
| 1:20 | "On the dashboard the reason is shown, not just 'unsafe'." | Open Evidence, then the rejected heartbeats of the node | Rules fired: `nonce_unique` failed while signature and timestamp passed |
| 1:50 | "Results are encrypted; a changed byte is detected." | Run the demo again with `--task-ids` | `422 RESULT_INTEGRITY_FAILED`; the failed attempt appears in the history |
| 2:30 | "A node crashes and the broker notices." | `python -m fogtrust_crypto.fleet ...` | The crasher stops after 3 heartbeats; Member 3's scheduler reassigns its task |

Before the demo: delete old demo nodes' keys, make sure the server key exists (`manage.py generate_server_key`), and have 1 token for the demo plus 6 for the fleet.