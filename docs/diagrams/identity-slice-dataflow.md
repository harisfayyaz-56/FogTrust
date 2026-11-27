# Data-flow diagram: the identity slice and its trust boundaries

Trust boundaries (TB1 to TB5) are numbered as in [identity-access-audit.md](../threat-model/identity-access-audit.md),
section 3. For Member 4 to merge into the team diagram. GitHub draws the Mermaid blocks below.

## 1. Where requests cross each boundary

```mermaid
flowchart LR
  subgraph WEB["Browser (untrusted)"]
    UI["Dashboard<br/>admin / operator / viewer"]
  end
  subgraph EDGE["New edge node (untrusted)"]
    NODE["Node program<br/>holds its own private key"]
  end
  ADMIN(["Administrator"])
  subgraph BROKER["Broker process"]
    AUTH["Session auth + CSRF<br/>accounts"]
    PERM["Capability check<br/>require(...)"]
    NAUTH["Node signature auth<br/>nodes.authentication"]
    VIEWS["API views<br/>users, tokens, enroll, revoke, audit"]
    GATES["Enrollment and revocation gates<br/>nodes.services"]
    CRYPTO["fogtrust_crypto<br/>key, proof, signature checks"]
    LOG["log_event()<br/>redaction + hash chain"]
  end
  DB[("Database<br/>User, Session, EnrollmentToken,<br/>Node, NodeNonce, Decision")]
  AUDIT[("AuditEvent<br/>append-only, hash-chained")]

  UI -- "TB1: cookie + X-CSRFToken" --> AUTH --> PERM --> VIEWS
  ADMIN -. "token handed over privately" .-> NODE
  NODE -- "TB2: token + public key + proof" --> VIEWS
  NODE -- "TB2: signed request" --> NAUTH --> VIEWS
  VIEWS -- "TB3: validated values" --> GATES --> CRYPTO
  GATES -- "TB4: ORM, one transaction" --> DB
  GATES --> LOG
  PERM -- "denied" --> LOG
  NAUTH -- "refused" --> LOG
  LOG -- "TB4: INSERT only (triggers block UPDATE/DELETE)" --> AUDIT
  ADMIN -- "TB5: role, policy, revoke (audited)" --> UI
```

## 2. What crosses each boundary, and what is never allowed to

| Boundary | Crosses | Checked by | Never crosses |
|---|---|---|---|
| TB1 Browser → API | Session cookie (HttpOnly), CSRF header, JSON ≤ 256 KB | Session expiry, CSRF, capability table, strict serializers | Password hashes, raw tokens after creation, stack traces |
| TB2 Node → API | Enrollment: token, name, public key, proof (≤ 4 KB). Later: four signed headers | Token hash lookup, proof of possession, signature, time window, nonce, status | The node's private key (stays on the node) |
| TB3 API → engine | Already-validated values | Each rule recorded in the Decision | Raw request objects |
| TB4 API → database | Parameterised ORM queries | Unique and CHECK constraints, conditional UPDATEs, audit triggers | String-built SQL |
| TB5 Admin → configuration | Role changes, revocations, token creation | Admin capability, self-lockout guard, name confirmation | Anything without an audit event |

## 3. Enrollment, step by step

```mermaid
sequenceDiagram
  participant A as Administrator
  participant B as Broker
  participant N as New node
  A->>B: POST /enrollment-tokens/
  B-->>A: raw token (shown once, only its SHA-256 is stored)
  A-->>N: token, out of band
  N->>N: generate Ed25519 key pair, sign token + name + public key
  N->>B: POST /nodes/enroll/ {token, name, public_key, proof}
  B->>B: token valid? key well formed? proof verifies? key and name unused?
  B->>B: one transaction: create Node, mark token used, audit event, Decision
  B-->>N: 201 node_id
  Note over B,N: Any failure: client sees ENROLL_TOKEN_INVALID or ENROLL_PROOF_INVALID,<br/>the precise reason goes to the audit log
```
