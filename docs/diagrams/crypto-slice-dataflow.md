# Data-flow diagram: the crypto slice and its trust boundaries

Trust boundaries use the numbering of [identity-access-audit.md](../threat-model/identity-access-audit.md) section 3. For Member 4 to merge into the team diagram. GitHub draws the Mermaid blocks below.

## 1. Where a request crosses each boundary

```mermaid
flowchart LR
  subgraph EDGE["Edge node host (untrusted)"]
    NODE["Node program<br/>node_sim / fleet"]
    KEY[("Private key file<br/>owner-only")]
  end
  subgraph WEB["Browser (untrusted)"]
    UI["Dashboard<br/>operator / admin"]
  end
  subgraph BROKER["Broker process"]
    API["API layer (Django REST)<br/>heartbeats, results, nodes"]
    ENG["Security engine<br/>fogtrust_crypto, no Django"]
    SCHED["Trust engine and scheduler"]
  end
  DB[("Database<br/>Node, NodeNonce, Heartbeat,<br/>TaskResult, Decision, AuditEvent")]
  SK[("Server result key<br/>owner-only file")]

  KEY -.signs.-> NODE
  NODE -- "TB2: signed request<br/>(+ encrypted result)" --> API
  UI -- "TB1: session cookie + CSRF" --> API
  API -- "TB3: raw bytes + node record" --> ENG
  ENG -- "VerificationResult<br/>(rules fired, evidence)" --> API
  SK -.decrypts.-> ENG
  API -- "TB4: ORM, parameterised" --> DB
  API -- "authenticated evidence only" --> SCHED
  SCHED --> DB
  UI -. "TB5: policy and revocation<br/>(admin, confirmed, audited)" .-> API
```

## 2. What the engine checks, in order

```mermaid
flowchart TD
  A["Request arrives (TB2)"] --> S{"Body within size limit?"}
  S -- no --> X1["413 PAYLOAD_TOO_LARGE"]
  S -- yes --> H{"Signed headers present?"}
  H -- no --> X2["NODE_SIGNATURE_MISSING"]
  H -- yes --> N{"Node enrolled?"}
  N -- no --> X3["NODE_UNKNOWN"]
  N -- yes --> R{"Node active?"}
  R -- revoked --> X4["NODE_REVOKED"]
  R -- yes --> G{"Ed25519 signature valid?"}
  G -- no --> X5["NODE_SIGNATURE_INVALID"]
  G -- yes --> T{"Timestamp within window?"}
  T -- no --> X6["HEARTBEAT_STALE"]
  T -- yes --> O{"Nonce unused? (atomic)"}
  O -- no --> X7["HEARTBEAT_REPLAYED"]
  O -- yes --> B{"Heartbeat: body valid and counter higher?<br/>Result: assigned to this node, AES-GCM tag OK?"}
  B -- no --> X8["VALIDATION_ERROR / COUNTER_REGRESSED /<br/>RESULT_NOT_ASSIGNED / RESULT_INTEGRITY_FAILED"]
  B -- yes --> OK["Accepted: store, update node, evidence"]
```

## 3. Boundary table (for the team diagram)

| Boundary | Crossing | Controls | Threat model entries |
|---|---|---|---|
| TB1 | Browser to API (result view) | Session, CSRF, `results.view` role, `no-store`, every view audited | CR-19 |
| TB2 | Node to API (heartbeat, result) | Signature over method, path, query, time, nonce and body hash; time window; nonce; counter; size limits; rate limits | CR-1 to CR-3, CR-6 to CR-10, CR-12, CR-14 to CR-18, CR-20, CR-21 |
| TB3 | API to engine | The engine gets the raw bytes and a node record, never a framework object; it returns an explainable result | CR-8, CR-13 |
| TB4 | API to database | ORM only; unique constraints decide nonce and one-valid-result-per-task; only ciphertext stored | CR-9, CR-11, CR-18 |
| TB5 | Admin to configuration | Admin role, audit event per change | `timestamp_window_s` is set here |