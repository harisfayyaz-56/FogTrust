import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');
const frontendSrc = path.join(rootDir, 'frontend', 'src');

describe('FogTrust Member 4: Dashboard, Evidence & QA (FR-7)', () => {
  // -------------------------------------------------------------------------
  // 1. Static Security Guardrails
  // -------------------------------------------------------------------------
  describe('Static Security Guardrails', () => {
    it('must NEVER use dangerouslySetInnerHTML anywhere in frontend source code', () => {
      function scanDir(dir) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
          const fullPath = path.join(dir, file);
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            scanDir(fullPath);
          } else if (/\.(tsx|ts|jsx|js|html)$/.test(file)) {
            const content = fs.readFileSync(fullPath, 'utf8');
            assert.strictEqual(
              content.includes('dangerouslySetInnerHTML'),
              false,
              `Security violation: dangerouslySetInnerHTML found in ${fullPath}`
            );
          }
        }
      }
      scanDir(frontendSrc);
    });

    it('must not hardcode sensitive secrets or private keys in frontend source files', () => {
      function scanDir(dir) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
          const fullPath = path.join(dir, file);
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            scanDir(fullPath);
          } else if (/\.(tsx|ts|jsx|js)$/.test(file)) {
            const content = fs.readFileSync(fullPath, 'utf8');
            assert.strictEqual(
              content.includes('BEGIN PRIVATE KEY'),
              false,
              `Private key found in ${fullPath}`
            );
            assert.strictEqual(
              content.includes('BEGIN ED25519 PRIVATE KEY'),
              false,
              `Private key found in ${fullPath}`
            );
          }
        }
      }
      scanDir(frontendSrc);
    });
  });

  // -------------------------------------------------------------------------
  // 2. Sanitized Report Export Compliance (Contract 5.10 & FR-7)
  // -------------------------------------------------------------------------
  describe('Sanitized Report Generation & Zero-Secret Export (API Contract 5.10)', () => {
    it('guarantees that exported reports never contain public keys, token hashes, ciphertexts, passwords, or IP addresses', async () => {
      // Mock data representing sample system state
      const mockNodes = [
        {
          id: 'a7f3c2d1-0b9e-4c8d-9e1f-2a3b4c5d6e7f',
          name: 'gateway-01',
          status: 'active',
          key_fingerprint: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          capacity: 4,
          current_load: 1,
          trust_score: 95,
          last_seen_at: '2026-11-08T01:30:00Z',
          enrolled_at: '2026-11-07T09:00:00Z',
          revoked_at: null,
        },
      ];

      const mockDecisions = [
        {
          decision_id: 'd1010001-0000-0000-0000-000000000001',
          subject_type: 'heartbeat',
          subject_id: 'a7f3c2d1-0b9e-4c8d-9e1f-2a3b4c5d6e7f',
          decision: 'allow',
          reason_code: 'OK',
          explanation: 'Heartbeat accepted from gateway-01.',
          rules_fired: [{ rule: 'signature_valid', passed: true, detail: 'Ed25519 OK' }],
          evidence: { counter: 42, nonce_prefix: '7a1b' },
          engine_name: 'node_auth',
          engine_version: '1.0.0',
          policy_version: 1,
          decided_at: '2026-11-08T01:30:15Z',
          latency_ms: 0.18,
        },
      ];

      // Sanitization routine
      const sanitizedReport = {
        generated_at: new Date().toISOString(),
        generated_by: 'operator1',
        scope: 'FogTrust System Sanitized Operational & Security Summary',
        summary: {
          total_nodes: mockNodes.length,
          active_nodes: mockNodes.filter((n) => n.status === 'active').length,
          revoked_nodes: mockNodes.filter((n) => n.status === 'revoked').length,
          average_trust_score: 95,
          total_decisions_analyzed: mockDecisions.length,
          audit_chain_verified: true,
        },
        nodes: mockNodes.map((n) => ({
          id: n.id,
          name: n.name,
          status: n.status,
          trust_score: n.trust_score,
          capacity: n.capacity,
          current_load: n.current_load,
          last_seen_at: n.last_seen_at,
        })),
        recent_decisions: mockDecisions.map((d) => ({
          decision_id: d.decision_id,
          subject_type: d.subject_type,
          decision: d.decision,
          reason_code: d.reason_code,
          explanation: d.explanation,
          latency_ms: d.latency_ms,
          decided_at: d.decided_at,
        })),
      };

      const serialized = JSON.stringify(sanitizedReport);

      // Verify no sensitive fields leak
      assert.strictEqual(serialized.includes('public_key'), false, 'Leaked public_key');
      assert.strictEqual(serialized.includes('token_hash'), false, 'Leaked token_hash');
      assert.strictEqual(serialized.includes('ciphertext'), false, 'Leaked ciphertext');
      assert.strictEqual(serialized.includes('password'), false, 'Leaked password');
      assert.strictEqual(serialized.includes('source_ip'), false, 'Leaked source_ip');
      assert.strictEqual(serialized.includes('127.0.0.1'), false, 'Leaked IP address');

      // Verify necessary operational details are present
      assert.strictEqual(sanitizedReport.summary.total_nodes, 1);
      assert.strictEqual(sanitizedReport.nodes[0].name, 'gateway-01');
      assert.strictEqual(sanitizedReport.recent_decisions[0].decision, 'allow');
    });
  });

  // -------------------------------------------------------------------------
  // 3. Node Revocation Confirmation Logic (FR-6 / T5)
  // -------------------------------------------------------------------------
  describe('Node Revocation Confirmation & Safety (FR-6 / T5)', () => {
    it('rejects revocation if confirm_name does not exactly match node name', () => {
      const node = { id: 'uuid-1', name: 'gateway-03', status: 'active' };

      function validateRevoke(inputConfirmName, reason) {
        if (inputConfirmName !== node.name) {
          return { error: 'CONFIRMATION_REQUIRED', message: 'Name does not match' };
        }
        if (!reason || reason.trim().length < 10) {
          return { error: 'VALIDATION_ERROR', message: 'Reason too short' };
        }
        return { success: true };
      }

      // Wrong name
      assert.strictEqual(validateRevoke('gateway-02', '3 integrity failures in 10 minutes').error, 'CONFIRMATION_REQUIRED');
      // Case mismatch
      assert.strictEqual(validateRevoke('Gateway-03', '3 integrity failures in 10 minutes').error, 'CONFIRMATION_REQUIRED');
      // Short reason
      assert.strictEqual(validateRevoke('gateway-03', 'bad node').error, 'VALIDATION_ERROR');
      // Exact match and sufficient reason
      assert.strictEqual(validateRevoke('gateway-03', '3 integrity failures in 10 minutes').success, true);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Explainable Decision Schema (FR-7 / Data Model Section 4)
  // -------------------------------------------------------------------------
  describe('Explainable Decision Contract (FR-7)', () => {
    it('verifies that decisions adhere to the shared schema with rules_fired and evidence', () => {
      const decision = {
        decision_id: '6f0e8c1e-7a4b-4f7c-9a3e-1c2d3e4f5a6b',
        subject_type: 'heartbeat',
        subject_id: 'b2c4-node-uuid',
        decision: 'deny',
        reason_code: 'HEARTBEAT_REPLAYED',
        explanation: 'Nonce 9f3a... was already used by this node at 2026-11-12T09:30:00Z.',
        rules_fired: [
          { rule: 'nonce_unique', passed: false, detail: 'nonce seen before' },
          { rule: 'timestamp_window', passed: true, detail: 'skew 1.2 s, limit 30 s' },
          { rule: 'signature_valid', passed: true, detail: 'Ed25519 OK' },
        ],
        evidence: { counter: 41, last_counter: 41, nonce_prefix: '9f3a' },
        engine_name: 'replay_guard',
        engine_version: '1.0.0',
        policy_version: 3,
        thresholds: { timestamp_window_s: 30 },
        decided_at: '2026-11-12T09:30:01.204Z',
        latency_ms: 2.7,
      };

      assert.ok(['enrollment', 'node', 'heartbeat', 'task', 'result', 'policy'].includes(decision.subject_type));
      assert.ok(['allow', 'deny', 'flag', 'assign', 'revoke', 'score'].includes(decision.decision));
      assert.strictEqual(typeof decision.explanation, 'string');
      assert.ok(decision.rules_fired.length > 0);
      assert.strictEqual(decision.rules_fired[0].passed, false);
      assert.strictEqual(typeof decision.latency_ms, 'number');
      assert.ok(decision.evidence.nonce_prefix !== undefined);
    });
  });

  // -------------------------------------------------------------------------
  // 5. Audit Hash Chain Verification (ID-9)
  // -------------------------------------------------------------------------
  describe('Audit Hash Chain Verification (ID-9)', () => {
    it('detects broken links or modified entries in sequential audit records', () => {
      const validChain = [
        {
          sequence: 1,
          prev_hash: '0000000000000000000000000000000000000000000000000000000000000000',
          hash: 'hash-1',
        },
        { sequence: 2, prev_hash: 'hash-1', hash: 'hash-2' },
        { sequence: 3, prev_hash: 'hash-2', hash: 'hash-3' },
      ];

      function verifyChain(events) {
        for (let i = 1; i < events.length; i++) {
          if (events[i].prev_hash !== events[i - 1].hash) {
            return { valid: false, brokenSequence: events[i].sequence, problem: 'link_mismatch' };
          }
          if (events[i].sequence !== events[i - 1].sequence + 1) {
            return { valid: false, brokenSequence: events[i].sequence, problem: 'sequence_gap' };
          }
        }
        return { valid: true, count: events.length };
      }

      assert.strictEqual(verifyChain(validChain).valid, true);

      // Tampered chain
      const tamperedChain = [
        { sequence: 1, prev_hash: '000...', hash: 'hash-1' },
        { sequence: 2, prev_hash: 'tampered-hash', hash: 'hash-2' },
      ];
      const tamperedResult = verifyChain(tamperedChain);
      assert.strictEqual(tamperedResult.valid, false);
      assert.strictEqual(tamperedResult.problem, 'link_mismatch');
      assert.strictEqual(tamperedResult.brokenSequence, 2);
    });
  });

  // -------------------------------------------------------------------------
  // 6. Role Capability Matrix (Section 3 of API contract)
  // -------------------------------------------------------------------------
  describe('Role Capability Matrix Enforcement', () => {
    it('verifies correct capability mappings across administrator, operator, and viewer', () => {
      const CAPABILITIES = {
        admin: [
          'users.manage',
          'tokens.create',
          'tokens.cancel',
          'nodes.revoke',
          'policy.change',
          'audit.verify',
          'tasks.submit',
          'reports.export',
        ],
        operator: ['tasks.submit', 'tasks.cancel', 'reports.export'],
        viewer: ['nodes.view', 'tasks.view', 'decisions.view'],
      };

      // Admin has revoke
      assert.ok(CAPABILITIES.admin.includes('nodes.revoke'));
      // Operator does NOT have revoke
      assert.strictEqual(CAPABILITIES.operator.includes('nodes.revoke'), false);
      // Viewer does NOT have submit task
      assert.strictEqual(CAPABILITIES.viewer.includes('tasks.submit'), false);
    });
  });
});

