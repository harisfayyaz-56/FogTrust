# simulator/ (edge node simulator) — Member 2

Command-line script that pretends to be one edge node. Several copies run at once,
each with a behaviour profile:

| Profile | Purpose | Test |
|---|---|---|
| `honest` | Enrolls, sends valid signed heartbeats, returns correct encrypted results | baseline |
| `spoofer` | Uses a stolen node ID with its own key, or a fake enrollment token | T1 |
| `replayer` | Re-sends a captured heartbeat | T2 |
| `crasher` | Accepts a task and stops responding | T3 |
| `tamperer` | Modifies ciphertext after encryption | T4 |

Private keys stay in `simulator/keys/` on the node side only (git-ignored).
The server never receives or stores a private key.
