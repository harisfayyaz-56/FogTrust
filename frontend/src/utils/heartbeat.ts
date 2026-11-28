import { HeartbeatRejectionCode } from '../types/api';

/** Exact rejection codes come from backend/core/errors.py; never rename them here. */
const REJECTION_LABELS: Record<Exclude<HeartbeatRejectionCode, ''>, string> = {
  NODE_SIGNATURE_INVALID: 'Bad signature',
  NODE_SIGNATURE_MISSING: 'Missing signature',
  HEARTBEAT_STALE: 'Old timestamp',
  HEARTBEAT_REPLAYED: 'Reused nonce',
  HEARTBEAT_COUNTER_REGRESSED: 'Counter went backwards',
  NODE_REVOKED: 'Node revoked',
  NODE_UNKNOWN: 'Unknown node',
};

const REJECTION_EXPLANATIONS: Record<Exclude<HeartbeatRejectionCode, ''>, string> = {
  NODE_SIGNATURE_INVALID:
    'The Ed25519 signature did not verify with the public key enrolled for this node.',
  NODE_SIGNATURE_MISSING:
    'One or more signed-request headers were absent or empty, so the request was never authenticated.',
  HEARTBEAT_STALE:
    'The heartbeat timestamp was outside the configured acceptance window (clock skew or replay attempt).',
  HEARTBEAT_REPLAYED:
    'The nonce had already been accepted inside the timestamp window, so the heartbeat is a duplicate.',
  HEARTBEAT_COUNTER_REGRESSED:
    'The heartbeat counter was not strictly greater than the last accepted counter.',
  NODE_REVOKED:
    'The node is permanently revoked, so every later signed request is rejected.',
  NODE_UNKNOWN:
    'The node ID is not enrolled; rejected heartbeats from unknown IDs are only recorded in the audit log.',
};

export function heartbeatRejectionLabel(code: HeartbeatRejectionCode): string {
  if (!code) return 'Unknown rejection';
  return REJECTION_LABELS[code] || code;
}

export function heartbeatRejectionExplanation(code: HeartbeatRejectionCode): string {
  if (!code) return 'No rejection reason was recorded.';
  return REJECTION_EXPLANATIONS[code] || 'The security engine rejected this heartbeat.';
}

/** The four heartbeat-specific reasons required by the evidence view. */
export const HEARTBEAT_REJECTION_CODES: HeartbeatRejectionCode[] = [
  'NODE_SIGNATURE_INVALID',
  'HEARTBEAT_STALE',
  'HEARTBEAT_REPLAYED',
  'HEARTBEAT_COUNTER_REGRESSED',
];
