import { Decision, NodeItem } from '../types/api';
import { getNodeDisplayStatus } from '../utils/nodeStatus';

/**
 * Export sanitization is deliberately allow-list based: the report builder maps
 * every object field explicitly, then a second defensive pass removes any key
 * that looks like key material, a credential, a token or a signature.
 *
 * This module is pure TypeScript (no React/DOM access) so it can be unit tested
 * with Vitest. See report.test.ts.
 */

export interface SanitizedNode {
  id: string;
  name: string;
  status: 'enrolled' | 'active' | 'revoked';
  trust_score: number;
  capacity: number;
  current_load: number;
  last_seen_at: string | null;
  enrolled_at: string;
}

export interface SanitizedDecision {
  decision_id: string;
  subject_type: string;
  decision: string;
  reason_code: string;
  explanation: string;
  latency_ms: number;
  decided_at: string;
}

export interface SanitizedReport {
  export_version: number;
  generated_at: string;
  generated_by: string;
  scope: string;
  summary: {
    total_nodes: number;
    enrolled_nodes: number;
    active_nodes: number;
    revoked_nodes: number;
    average_trust_score: number;
    total_decisions_analyzed: number;
    audit_chain_verified: boolean;
  };
  nodes: SanitizedNode[];
  recent_decisions: SanitizedDecision[];
}

const SENSITIVE_KEY_FRAGMENTS = [
  'password',
  'passwd',
  'passphrase',
  'secret',
  'token',
  'privatekey',
  'publickey',
  'signingkey',
  'encryptionkey',
  'apikey',
  'accesskey',
  'keyfingerprint',
  'rawsignature',
  'signature',
  'ciphertext',
  'plaintext',
  'nonce',
  'cookie',
  'sessionid',
  'csrf',
  'credential',
  'salt',
  'hmac',
  'authorization',
  'sourceip',
  'ipaddress',
  'clientip',
  'remoteip',
];

const SECRET_VALUE_PATTERNS = [
  /-----BEGIN [A-Z ]*(?:PRIVATE|PUBLIC) KEY-----/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./,
  /\bBearer\s+[A-Za-z0-9._~+/-]{16,}/i,
  /\bfogtrust_[A-Za-z0-9_-]{16,}/,
  /^\$(?:2[aby]|argon2)[^ ]{20,}$/,
];

export function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
  return SENSITIVE_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment));
}

function isSecretValue(value: string): boolean {
  return SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(value));
}

/**
 * Recursively remove sensitive keys and redact values that look like raw
 * secrets. Arrays are preserved; primitive values are preserved.
 */
export function stripSensitiveFields<T>(input: T): T {
  if (Array.isArray(input)) {
    return input.map((entry) => stripSensitiveFields(entry)) as unknown as T;
  }

  if (input !== null && typeof input === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      if (isSensitiveKey(key)) continue;
      output[key] = stripSensitiveFields(value);
    }
    return output as T;
  }

  if (typeof input === 'string' && isSecretValue(input)) {
    return '[REDACTED]' as unknown as T;
  }

  return input;
}

export function buildSanitizedReportData(
  currentUser: string,
  nodes: NodeItem[],
  decisions: Decision[],
  auditValid: boolean
): SanitizedReport {
  const enrolledCount = nodes.filter((node) => getNodeDisplayStatus(node) === 'enrolled').length;
  const activeCount = nodes.filter((node) => getNodeDisplayStatus(node) === 'active').length;
  const revokedCount = nodes.filter((node) => getNodeDisplayStatus(node) === 'revoked').length;
  const avgTrust =
    nodes.length > 0
      ? Math.round(nodes.reduce((total, node) => total + node.trust_score, 0) / nodes.length)
      : 0;

  const report: SanitizedReport = {
    export_version: 1,
    generated_at: new Date().toISOString(),
    generated_by: currentUser,
    scope: 'FogTrust System Sanitized Operational & Security Summary',
    summary: {
      total_nodes: nodes.length,
      enrolled_nodes: enrolledCount,
      active_nodes: activeCount,
      revoked_nodes: revokedCount,
      average_trust_score: avgTrust,
      total_decisions_analyzed: decisions.length,
      audit_chain_verified: auditValid,
    },
    nodes: nodes.map((node) => ({
      id: node.id,
      name: node.name,
      status: getNodeDisplayStatus(node),
      trust_score: node.trust_score,
      capacity: node.capacity,
      current_load: node.current_load,
      last_seen_at: node.last_seen_at,
      enrolled_at: node.enrolled_at,
    })),
    recent_decisions: decisions.slice(0, 50).map((decision) => ({
      decision_id: decision.decision_id,
      subject_type: decision.subject_type,
      decision: decision.decision,
      reason_code: decision.reason_code,
      explanation: decision.explanation,
      latency_ms: decision.latency_ms,
      decided_at: decision.decided_at,
    })),
  };

  // Defence in depth: even if a field is added above by mistake, key material
  // and secret-looking values are removed before the report leaves the browser.
  return stripSensitiveFields(report);
}

function csvEscape(value: unknown): string {
  if (value === null || value === undefined) return '';
  const text = String(value);
  if (/[",\r\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

/** Deterministic CSV representation of the sanitized report. */
export function reportToCSV(report: SanitizedReport): string {
  const lines: string[] = [
    '--- FOGTRUST SANITIZED AUDIT REPORT ---',
    `Export Version,${csvEscape(report.export_version)}`,
    `Generated At,${csvEscape(report.generated_at)}`,
    `Generated By,${csvEscape(report.generated_by)}`,
    `Scope,${csvEscape(report.scope)}`,
    '',
    '--- SUMMARY ---',
    'Total Nodes,Enrolled Nodes,Active Nodes,Revoked Nodes,Average Trust Score,Decisions Analyzed,Audit Chain Verified',
    [
      report.summary.total_nodes,
      report.summary.enrolled_nodes,
      report.summary.active_nodes,
      report.summary.revoked_nodes,
      report.summary.average_trust_score,
      report.summary.total_decisions_analyzed,
      report.summary.audit_chain_verified,
    ]
      .map(csvEscape)
      .join(','),
    '',
    '--- NODES (SANITIZED) ---',
    'ID,Name,Status,Trust Score,Capacity,Current Load,Last Seen,Enrolled At',
  ];

  for (const node of report.nodes) {
    lines.push(
      [
        node.id,
        node.name,
        node.status,
        node.trust_score,
        node.capacity,
        node.current_load,
        node.last_seen_at || 'Never',
        node.enrolled_at,
      ]
        .map(csvEscape)
        .join(',')
    );
  }

  lines.push('', '--- RECENT DECISIONS (SANITIZED) ---');
  lines.push('Decision ID,Subject Type,Decision,Reason Code,Explanation,Latency ms,Decided At');
  for (const decision of report.recent_decisions) {
    lines.push(
      [
        decision.decision_id,
        decision.subject_type,
        decision.decision,
        decision.reason_code,
        decision.explanation,
        decision.latency_ms,
        decision.decided_at,
      ]
        .map(csvEscape)
        .join(',')
    );
  }

  return lines.join('\n');
}

export function reportToJSON(report: SanitizedReport): string {
  return JSON.stringify(report, null, 2);
}

/** Serializable string form used by the export tests. */
export function serializeReport(report: SanitizedReport, format: 'json' | 'csv'): string {
  return format === 'csv' ? reportToCSV(report) : reportToJSON(report);
}
