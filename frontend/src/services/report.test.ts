import { describe, expect, it } from 'vitest';
import { Decision, NodeItem } from '../types/api';
import {
  buildSanitizedReportData,
  isSensitiveKey,
  reportToCSV,
  reportToJSON,
  serializeReport,
  stripSensitiveFields,
} from './report';

const UNSAFE_VALUES = {
  publicKey: 'PUBLIC-KEY-MATERIAL-4f8a',
  fingerprint: 'KEY-FINGERPRINT-9b1c',
  token: 'fogtrust_tok_abcdefghijklmnop123456',
  tokenHash: 'TOKEN-HASH-d41d8cd9',
  rawSignature: 'RAW-SIGNATURE-7e2f',
  privateKey: 'PRIVATE-KEY-MATERIAL-11aa',
  passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$PASSWORD-HASH-22bb',
  sourceIp: '10.9.8.7',
  nonce: 'NONCE-33cc',
  ciphertext: 'CIPHERTEXT-44dd',
};

const unsafeNode = {
  id: 'a7f3c2d1-0b9e-4c8d-9e1f-2a3b4c5d6e7f',
  name: 'gateway-01',
  status: 'active',
  key_fingerprint: UNSAFE_VALUES.fingerprint,
  capacity: 4,
  current_load: 1,
  trust_score: 93,
  last_seen_at: '2026-11-08T01:30:15Z',
  enrolled_at: '2026-11-07T09:00:00Z',
  public_key: UNSAFE_VALUES.publicKey,
  token: UNSAFE_VALUES.token,
  token_hash: UNSAFE_VALUES.tokenHash,
  raw_signature: UNSAFE_VALUES.rawSignature,
  private_key: UNSAFE_VALUES.privateKey,
  password_hash: UNSAFE_VALUES.passwordHash,
  source_ip: UNSAFE_VALUES.sourceIp,
  nonce: UNSAFE_VALUES.nonce,
  ciphertext: UNSAFE_VALUES.ciphertext,
} as unknown as NodeItem;

const unsafeDecision = {
  decision_id: 'd1010001-0000-0000-0000-000000000001',
  subject_type: 'heartbeat',
  subject_id: 'a7f3c2d1-0b9e-4c8d-9e1f-2a3b4c5d6e7f',
  decision: 'deny',
  reason_code: 'NODE_SIGNATURE_INVALID',
  explanation: 'Signature verification failed, therefore the heartbeat was rejected.',
  rules_fired: [
    { rule: 'signature_valid', passed: false, detail: 'Ed25519 verification failed' },
  ],
  evidence: {
    raw_signature: UNSAFE_VALUES.rawSignature,
    nonce: UNSAFE_VALUES.nonce,
    ciphertext: UNSAFE_VALUES.ciphertext,
    token: UNSAFE_VALUES.token,
  },
  engine_name: 'node_auth',
  engine_version: '1.0.0',
  policy_version: 1,
  request_id: 'req-hb-1004',
  decided_at: '2026-11-08T01:11:00.090Z',
  latency_ms: 0.44,
} as unknown as Decision;

describe('sanitized report export', () => {
  it('strips every sensitive value from JSON and CSV output', () => {
    const report = buildSanitizedReportData('admin1', [unsafeNode], [unsafeDecision], true);
    const json = reportToJSON(report);
    const csv = reportToCSV(report);
    const combined = `${json}\n${csv}`;

    for (const value of Object.values(UNSAFE_VALUES)) {
      expect(combined).not.toContain(value);
    }

    // Key names are not present either, so an auditor cannot infer where secrets lived.
    for (const key of [
      'public_key',
      'key_fingerprint',
      'token_hash',
      'raw_signature',
      'private_key',
      'password_hash',
      'source_ip',
      'nonce',
      'ciphertext',
      'evidence',
    ]) {
      expect(combined).not.toContain(key);
    }
  });

  it('keeps the safe operational fields an auditor needs', () => {
    const report = buildSanitizedReportData('admin1', [unsafeNode], [unsafeDecision], true);
    const json = reportToJSON(report);

    expect(json).toContain('gateway-01');
    expect(json).toContain(unsafeNode.id);
    expect(json).toContain('NODE_SIGNATURE_INVALID');
    expect(json).toContain('Signature verification failed');
    expect(json).toContain('"trust_score": 93');
    expect(report.summary.total_nodes).toBe(1);
    expect(report.summary.active_nodes).toBe(1);
    expect(report.summary.revoked_nodes).toBe(0);
    expect(report.summary.enrolled_nodes).toBe(0);
    expect(report.summary.audit_chain_verified).toBe(true);
  });

  it('recursively strips sensitive keys and redacts secret-looking values', () => {
    const dirty = {
      user: { username: 'admin1', password: 'not-for-export', apiKey: 'abc123' },
      items: [{ token_hash: 'hash', safe: 'keep-me' }],
      source_ip: '192.0.2.10',
      authorization: 'Bearer abcdefghijklmnopqrstuvwxyz',
      note: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----',
      ok: true,
    };

    expect(stripSensitiveFields(dirty)).toEqual({
      user: { username: 'admin1' },
      items: [{ safe: 'keep-me' }],
      note: '[REDACTED]',
      ok: true,
    });
  });

  it('recognises sensitive keys regardless of case or separators', () => {
    for (const key of ['PUBLIC_KEY', 'api-key', 'rawSignature', 'TokenHash', 'sourceIp', 'PassWord']) {
      expect(isSensitiveKey(key)).toBe(true);
    }
    for (const key of ['id', 'name', 'trust_score', 'decided_at', 'status', 'explanation']) {
      expect(isSensitiveKey(key)).toBe(false);
    }
  });

  it('escapes CSV fields without allowing formula or quote injection', () => {
    const quotedDecision = {
      ...unsafeDecision,
      explanation: 'Rejected "quoted", comma value',
    } as Decision;
    const report = buildSanitizedReportData('admin1', [unsafeNode], [quotedDecision], false);
    const csv = reportToCSV(report);

    expect(csv).toContain('"Rejected ""quoted"", comma value"');
  });

  it('serializes both supported export formats', () => {
    const report = buildSanitizedReportData('admin1', [unsafeNode], [unsafeDecision], true);

    expect(serializeReport(report, 'json')).toBe(reportToJSON(report));
    expect(serializeReport(report, 'csv')).toBe(reportToCSV(report));
    expect(JSON.parse(serializeReport(report, 'json')).export_version).toBe(1);
  });
});
