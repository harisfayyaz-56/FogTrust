export type UserRole = 'admin' | 'operator' | 'viewer';

export type NodeStatus = 'active' | 'revoked';
export type NodeDisplayStatus = 'enrolled' | 'active' | 'revoked';

export interface User {
  id: number | string;
  username: string;
  role: UserRole;
  is_active: boolean;
  date_joined?: string;
  last_login?: string | null;
}

export interface AuthMeResponse {
  username: string;
  role: UserRole;
  permissions: string[];
  session_idle_timeout: number;
}

export interface NodeItem {
  id: string;
  name: string;
  status: NodeStatus;
  key_fingerprint: string;
  capacity: number;
  current_load: number;
  trust_score: number;
  last_seen_at: string | null;
  enrolled_at: string;
  revoked_at: string | null;
  revoke_reason?: string | null;
  revoke_source?: 'manual' | 'automatic' | null;
  revoked_by?: string | null;
}

export interface EnrollmentToken {
  id: string;
  label: string;
  created_at: string;
  expires_at: string;
  used_at: string | null;
  cancelled_at: string | null;
  used_by_node?: string | null;
  token?: string; // only present in creation response!
}

export interface RuleFired {
  rule: string;
  passed: boolean;
  detail: string;
  weight?: number;
  value?: number | string;
  contribution?: number;
  reason?: string;
}

/** One rule evaluation stored with a trust-score snapshot (docs/data-model.md 3.7). */
export interface TrustRuleFired {
  rule: string;
  weight: number;
  value: number;
  contribution: number;
  reason: string;
}

export interface TrustScoreRecord {
  id: number;
  node: string;
  node_name: string;
  score: number;
  previous_score: number;
  rules_fired: TrustRuleFired[];
  policy_version: number;
  computed_at: string;
  /** Human explanation supplied by the mock/API layer when available. */
  explanation?: string;
}

export type HeartbeatRejectionCode =
  | 'NODE_SIGNATURE_INVALID'
  | 'NODE_SIGNATURE_MISSING'
  | 'HEARTBEAT_STALE'
  | 'HEARTBEAT_REPLAYED'
  | 'HEARTBEAT_COUNTER_REGRESSED'
  | 'NODE_REVOKED'
  | 'NODE_UNKNOWN'
  | '';

/** A stored heartbeat attempt, including rejected attempts (docs/data-model.md 3.4). */
export interface HeartbeatRecord {
  id: number;
  node: string;
  node_name: string;
  counter: number;
  nonce_prefix: string;
  sent_at: string;
  received_at: string;
  reported_load: number;
  accepted: boolean;
  reason_code: HeartbeatRejectionCode;
  /** Plain-language detail for the evidence view (never contains raw signature material). */
  rejection_detail?: string;
}

export interface Decision {
  decision_id: string;
  subject_type: 'enrollment' | 'node' | 'heartbeat' | 'task' | 'result' | 'policy';
  subject_id: string;
  decision: 'allow' | 'deny' | 'flag' | 'assign' | 'revoke' | 'score';
  reason_code: string;
  explanation: string;
  rules_fired: RuleFired[];
  evidence: Record<string, unknown>;
  engine_name: string;
  engine_version: string;
  policy_version: number;
  thresholds?: Record<string, unknown>;
  request_id?: string;
  decided_at: string;
  latency_ms: number;
}

export interface AuditEvent {
  sequence: number;
  event_id: string;
  timestamp: string;
  actor_type: 'user' | 'node' | 'system' | 'anonymous';
  actor_id: string;
  actor_role: string;
  action: string;
  target_type: string;
  target_id: string;
  outcome: 'success' | 'failure' | 'denied';
  reason_code: string;
  request_id: string;
  source_ip: string;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface AuditVerifyReport {
  valid: boolean;
  events_checked: number;
  first_broken_sequence: number | null;
  problem: 'sequence_gap' | 'link_mismatch' | 'hash_mismatch' | null;
  checked_at: string;
}

export interface Task {
  id: string;
  task_type: 'checksum' | 'word_count' | 'sensor_average';
  payload: Record<string, unknown>;
  priority: number;
  status: 'queued' | 'assigned' | 'completed' | 'failed' | 'cancelled';
  assigned_node: string | null;
  attempts: number;
  max_attempts: number;
  idempotency_key: string;
  created_by?: string;
  created_at: string;
  assigned_at?: string | null;
  deadline_at?: string | null;
  completed_at?: string | null;
}

export interface TaskResult {
  id: string;
  task_id: string;
  node_id: string;
  integrity_valid: boolean;
  plaintext_sha256?: string | null;
  received_at: string;
  reason_code?: string;
}

export interface PolicyConfig {
  version: number;
  values: {
    trust_threshold: number;
    missed_heartbeat_limit?: number;
    timestamp_window_s?: number;
    heartbeat_interval_s?: number;
    auto_revoke_below?: number;
    weights?: Record<string, number>;
    [key: string]: unknown;
  };
  changed_by?: string;
  changed_at: string;
  change_reason: string;
}

export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
    request_id: string;
    details?: {
      fields?: Record<string, string[]>;
      retry_after_seconds?: number;
      [key: string]: unknown;
    };
  };
}

export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  database: string;
}

