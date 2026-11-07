import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  FileCheck2,
  Filter,
  Layers,
  Link as LinkIcon,
  Lock,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import {
  getAllRejectedHeartbeats,
  getAuditEvents,
  getDecisions,
  verifyAuditChain,
} from '../../services/api';
import {
  AuditEvent,
  AuditVerifyReport,
  Decision,
  HeartbeatRecord,
  HeartbeatRejectionCode,
} from '../../types/api';
import { Badge } from '../common/Badge';
import { Modal } from '../common/Modal';
import { EmptyState, ErrorState, LoadingState } from '../common/ViewState';
import { formatDateTime, formatRelativeTime } from '../../utils/nodeStatus';
import {
  HEARTBEAT_REJECTION_CODES,
  heartbeatRejectionExplanation,
  heartbeatRejectionLabel,
} from '../../utils/heartbeat';

interface EvidenceViewProps {
  onNavigate?: (tab: string) => void;
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({ onNavigate }) => {
  const { isDemoMode, role, hasPermission } = useAuth();
  const canViewAudit = role === 'admin' || hasPermission('audit.view');
  const canVerify = role === 'admin' || hasPermission('audit.verify');

  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [isLoadingDecisions, setIsLoadingDecisions] = useState<boolean>(true);
  const [decisionError, setDecisionError] = useState<string | null>(null);

  const [heartbeats, setHeartbeats] = useState<HeartbeatRecord[]>([]);
  const [isLoadingHeartbeats, setIsLoadingHeartbeats] = useState<boolean>(true);
  const [heartbeatError, setHeartbeatError] = useState<string | null>(null);

  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [isLoadingAudit, setIsLoadingAudit] = useState<boolean>(false);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [chainReport, setChainReport] = useState<AuditVerifyReport | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);

  // Decision filters
  const [subjectFilter, setSubjectFilter] = useState<string>('');
  const [decisionFilter, setDecisionFilter] = useState<string>('');
  const [reasonCodeFilter, setReasonCodeFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Heartbeat filter
  const [heartbeatCodeFilter, setHeartbeatCodeFilter] = useState<HeartbeatRejectionCode | ''>('');

  const [selectedDecision, setSelectedDecision] = useState<Decision | null>(null);

  const fetchDecisions = async () => {
    setIsLoadingDecisions(true);
    setDecisionError(null);
    try {
      const res = await getDecisions(
        {
          subject_type: subjectFilter || undefined,
          decision: decisionFilter || undefined,
          reason_code: reasonCodeFilter || undefined,
        },
        isDemoMode
      );
      setDecisions(res.results || []);
    } catch (err: unknown) {
      setDecisions([]);
      setDecisionError(err instanceof Error ? err.message : 'Could not load security decisions.');
    } finally {
      setIsLoadingDecisions(false);
    }
  };

  const fetchHeartbeats = async () => {
    setIsLoadingHeartbeats(true);
    setHeartbeatError(null);
    try {
      const rejected = await getAllRejectedHeartbeats(isDemoMode);
      setHeartbeats(rejected);
    } catch (err: unknown) {
      setHeartbeats([]);
      setHeartbeatError(err instanceof Error ? err.message : 'Could not load rejected heartbeats.');
    } finally {
      setIsLoadingHeartbeats(false);
    }
  };

  const fetchAudit = async () => {
    if (!canViewAudit) {
      setAuditEvents([]);
      return;
    }

    setIsLoadingAudit(true);
    setAuditError(null);
    setChainError(null);
    setIsVerifying(true);

    try {
      const events = await getAuditEvents({}, isDemoMode);
      setAuditEvents(events.results || []);
    } catch (err: unknown) {
      setAuditEvents([]);
      setAuditError(err instanceof Error ? err.message : 'Could not load audit events.');
    }

    if (!canVerify) {
      setChainError('Hash-chain verification requires the audit.verify permission.');
      setIsVerifying(false);
      setIsLoadingAudit(false);
      return;
    }

    try {
      const report = await verifyAuditChain(isDemoMode);
      setChainReport(report);
    } catch (err: unknown) {
      setChainReport(null);
      setChainError(err instanceof Error ? err.message : 'Could not verify the audit hash chain.');
    } finally {
      setIsVerifying(false);
      setIsLoadingAudit(false);
    }
  };

  useEffect(() => {
    fetchDecisions();
  }, [isDemoMode, subjectFilter, decisionFilter, reasonCodeFilter]);

  useEffect(() => {
    fetchHeartbeats();
  }, [isDemoMode]);

  useEffect(() => {
    fetchAudit();
  }, [isDemoMode, canViewAudit, canVerify]);

  const setQuickScenario = (code: string) => {
    setReasonCodeFilter((current) => (current === code ? '' : code));
  };

  const filteredDecisions = decisions.filter((decision) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      decision.explanation.toLowerCase().includes(query) ||
      decision.reason_code.toLowerCase().includes(query) ||
      decision.subject_id.toLowerCase().includes(query) ||
      decision.decision_id.toLowerCase().includes(query)
    );
  });

  const filteredHeartbeats = useMemo(
    () =>
      heartbeats.filter(
        (heartbeat) => !heartbeatCodeFilter || heartbeat.reason_code === heartbeatCodeFilter
      ),
    [heartbeats, heartbeatCodeFilter]
  );

  const refreshAll = () => {
    fetchDecisions();
    fetchHeartbeats();
    fetchAudit();
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-teal-400" />
            Evidence, Rejected Heartbeats & Audit Trail
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Every authorization decision records the exact rules and non-secret evidence; rejected heartbeats
            keep their precise error code, and the audit ledger proves the record was not edited.
          </p>
        </div>

        <button
          onClick={refreshAll}
          disabled={isLoadingDecisions || isLoadingHeartbeats}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium disabled:opacity-50"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isLoadingDecisions || isLoadingHeartbeats ? 'animate-spin' : ''}`} />
          <span>Refresh Evidence</span>
        </button>
      </div>

      {/* Hash-chain integrity indicator */}
      {!canViewAudit ? (
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-3 text-xs text-slate-400">
          <Lock className="w-5 h-5 text-slate-500 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-slate-300">Audit hash chain is administrator-managed</p>
            <p className="mt-0.5">
              Your role can inspect signed decisions and rejected heartbeats, but audit events and chain
              verification require the <code className="font-mono text-slate-300">audit.view</code> permission.
              The server still enforces the append-only chain for every action.
            </p>
          </div>
        </div>
      ) : chainError ? (
        <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-800/80 flex items-start gap-3 text-amber-200">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs">
            <p className="font-bold">Hash-chain status unavailable</p>
            <p className="mt-0.5 opacity-90">{chainError}</p>
          </div>
        </div>
      ) : isVerifying && !chainReport ? (
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center gap-3 text-xs text-slate-400">
          <RotateCcw className="w-4 h-4 text-teal-400 animate-spin" />
          <span>Recomputing SHA-256 hash-chain links…</span>
        </div>
      ) : chainReport ? (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${
            chainReport.valid
              ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
              : 'bg-rose-950/60 border-rose-800 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-3">
            {chainReport.valid ? (
              <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0" />
            ) : (
              <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0" />
            )}
            <div>
              <p className="font-bold text-sm font-mono">
                {chainReport.valid ? 'HASH CHAIN VERIFIED INTACT' : 'AUDIT INTEGRITY BREACH DETECTED'}
              </p>
              <p className="text-xs mt-0.5 opacity-90">
                {chainReport.valid
                  ? `${chainReport.events_checked} SHA-256 links match exactly; no deletions or edits.`
                  : `Verification failed at sequence #${chainReport.first_broken_sequence} (${chainReport.problem}).`}
              </p>
            </div>
          </div>
          <div className="hidden sm:block text-right text-[11px] font-mono opacity-80">
            Checked {formatRelativeTime(chainReport.checked_at)}
          </div>
        </div>
      ) : null}

      {/* ---------------------------------------------------------------- */}
      {/* Decisions                                                         */}
      {/* ---------------------------------------------------------------- */}
      <section className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
            <Layers className="w-4 h-4 text-teal-400" />
            Security decisions
          </h2>
          <span className="text-[11px] font-mono text-slate-500">{filteredDecisions.length} records</span>
        </div>

        {/* Demo scenario chips */}
        <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400 font-mono text-[11px] uppercase mr-1">Demo Scenarios:</span>
          {[
            { code: 'OK', label: 'Normal Operation (OK)', tone: 'emerald' },
            { code: 'HEARTBEAT_REPLAYED', label: 'T2 Replayed Nonce', tone: 'rose' },
            { code: 'RESULT_INTEGRITY_FAILED', label: 'T4 Ciphertext Tampering', tone: 'rose' },
            { code: 'CONFIRMED_REVOCATION', label: 'T5 Revocation Evidence', tone: 'amber' },
          ].map((scenario) => (
            <button
              key={scenario.code}
              onClick={() => setQuickScenario(scenario.code)}
              className={`px-2.5 py-1 rounded-md border text-xs font-mono transition-colors ${
                reasonCodeFilter === scenario.code
                  ? scenario.tone === 'emerald'
                    ? 'bg-emerald-950 border-emerald-700 text-emerald-300'
                    : scenario.tone === 'amber'
                    ? 'bg-amber-950 border-amber-700 text-amber-300'
                    : 'bg-rose-950 border-rose-700 text-rose-300'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {scenario.label}
            </button>
          ))}
          {reasonCodeFilter && (
            <button
              onClick={() => setReasonCodeFilter('')}
              className="text-[11px] text-teal-400 hover:underline ml-2"
            >
              Clear scenario filter
            </button>
          )}
        </div>

        {/* Filters */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search explanations, reason codes, subject IDs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-teal-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Layers className="w-3.5 h-3.5" />
              <span>Subject:</span>
              <select
                value={subjectFilter}
                onChange={(e) => setSubjectFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-teal-500"
              >
                <option value="">All Subjects</option>
                <option value="heartbeat">Heartbeats</option>
                <option value="node">Nodes</option>
                <option value="task">Tasks</option>
                <option value="result">Results</option>
                <option value="enrollment">Enrollment</option>
                <option value="policy">Policy</option>
              </select>
            </div>

            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Filter className="w-3.5 h-3.5" />
              <span>Decision:</span>
              <select
                value={decisionFilter}
                onChange={(e) => setDecisionFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-teal-500"
              >
                <option value="">All Outcomes</option>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
                <option value="assign">Assign</option>
                <option value="revoke">Revoke</option>
                <option value="score">Score</option>
                <option value="flag">Flag</option>
              </select>
            </div>
          </div>
        </div>

        {decisionError ? (
          <ErrorState title="Could not load security decisions" message={decisionError} onRetry={fetchDecisions} />
        ) : isLoadingDecisions ? (
          <LoadingState label="Loading security decisions…" />
        ) : filteredDecisions.length === 0 ? (
          <EmptyState
            title="No decision records found"
            description="No decision matches the current subject, outcome, reason, or search filters."
            icon={<FileCheck2 className="w-5 h-5" />}
          />
        ) : (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Decision</th>
                    <th className="py-3 px-4">Subject</th>
                    <th className="py-3 px-4">Reason Code</th>
                    <th className="py-3 px-4">Plain Text Explanation</th>
                    <th className="py-3 px-4">Rules Fired</th>
                    <th className="py-3 px-4">Latency</th>
                    <th className="py-3 px-4 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {filteredDecisions.map((decision) => (
                    <tr
                      key={decision.decision_id}
                      onClick={() => setSelectedDecision(decision)}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                    >
                      <td className="py-3.5 px-4">
                        <Badge label={decision.decision} />
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] uppercase text-slate-300">
                        {decision.subject_type}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        {decision.reason_code}
                      </td>
                      <td className="py-3.5 px-4 max-w-md font-sans text-slate-200">
                        <span className="line-clamp-2">{decision.explanation}</span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                          {decision.rules_fired.filter((rule) => rule.passed).length}/{decision.rules_fired.length} passed
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        {decision.latency_ms.toFixed(2)} ms
                      </td>
                      <td className="py-3.5 px-4 text-right text-teal-400 group-hover:text-teal-300">
                        <span className="text-xs font-mono flex items-center justify-end gap-1">
                          Inspect <ArrowRight className="w-3 h-3" />
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      {/* ---------------------------------------------------------------- */}
      {/* Rejected heartbeats                                               */}
      {/* ---------------------------------------------------------------- */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Rejected heartbeats
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Exact rejection code and plain-language reason; raw signatures and nonces are never shown.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <select
              value={heartbeatCodeFilter}
              onChange={(e) => setHeartbeatCodeFilter(e.target.value as HeartbeatRejectionCode | '')}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-teal-500"
            >
              <option value="">All rejection reasons</option>
              {HEARTBEAT_REJECTION_CODES.map((code) => (
                <option key={code} value={code}>
                  {heartbeatRejectionLabel(code)} ({code})
                </option>
              ))}
            </select>
          </div>
        </div>

        {heartbeatError ? (
          <ErrorState title="Could not load rejected heartbeats" message={heartbeatError} onRetry={fetchHeartbeats} />
        ) : isLoadingHeartbeats ? (
          <LoadingState label="Loading rejected heartbeats…" />
        ) : filteredHeartbeats.length === 0 ? (
          <EmptyState
            title="No rejected heartbeats"
            description={
              heartbeats.length === 0
                ? 'No heartbeat has been rejected since the node fleet started reporting.'
                : 'No rejected heartbeat matches the selected rejection reason.'
            }
            icon={<ShieldCheck className="w-5 h-5" />}
          />
        ) : (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Received</th>
                    <th className="py-3 px-4">Node</th>
                    <th className="py-3 px-4">Counter</th>
                    <th className="py-3 px-4">Rejection</th>
                    <th className="py-3 px-4">Exact reason</th>
                    <th className="py-3 px-4">Sent at</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {filteredHeartbeats.map((heartbeat) => (
                    <tr key={heartbeat.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        <span title={formatDateTime(heartbeat.received_at)}>
                          {formatRelativeTime(heartbeat.received_at)}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="font-medium text-slate-200">{heartbeat.node_name}</span>
                        <span className="block text-[10px] font-mono text-slate-500">
                          {heartbeat.node.slice(0, 16)}…
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-300">{heartbeat.counter}</td>
                      <td className="py-3.5 px-4">
                        <span className="font-mono text-[11px] text-rose-300">
                          {heartbeat.reason_code || 'UNKNOWN'}
                        </span>
                        <span className="block text-[11px] text-slate-400 mt-0.5">
                          {heartbeatRejectionLabel(heartbeat.reason_code)}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 max-w-xl">
                        {heartbeat.rejection_detail || heartbeatRejectionExplanation(heartbeat.reason_code)}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-500">
                        {formatDateTime(heartbeat.sent_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      {/* ---------------------------------------------------------------- */}
      {/* Audit trail                                                       */}
      {/* ---------------------------------------------------------------- */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-teal-400" />
              Audit trail
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Append-only hash-chained events. Each entry links to the previous SHA-256 hash.
            </p>
          </div>

          {canViewAudit && onNavigate && (
            <button
              onClick={() => onNavigate('audit')}
              className="flex items-center gap-1.5 text-xs text-teal-400 hover:text-teal-300 font-medium"
            >
              Open full audit log <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {!canViewAudit ? (
          <EmptyState
            title="Audit entries are restricted"
            description="The audit log requires the audit.view permission. Ask an administrator if you need access."
            icon={<Lock className="w-5 h-5" />}
          />
        ) : auditError ? (
          <ErrorState title="Could not load audit events" message={auditError} onRetry={fetchAudit} />
        ) : isLoadingAudit ? (
          <LoadingState label="Loading audit events…" />
        ) : auditEvents.length === 0 ? (
          <EmptyState title="No audit events" description="The audit ledger has no events yet." />
        ) : (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Seq</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">Actor</th>
                    <th className="py-3 px-4">Outcome</th>
                    <th className="py-3 px-4">Link</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {auditEvents.slice(0, 8).map((event) => (
                    <tr key={event.sequence} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono font-bold text-teal-400">#{event.sequence}</td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                        <span title={formatDateTime(event.timestamp)}>{formatRelativeTime(event.timestamp)}</span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-200">{event.action}</td>
                      <td className="py-3 px-4 font-mono text-[11px]">
                        <span className="text-slate-300">{event.actor_id}</span>
                        <span className="text-slate-500 ml-1">({event.actor_role})</span>
                      </td>
                      <td className="py-3 px-4">
                        <Badge label={event.outcome} />
                        {event.reason_code && (
                          <span className="block text-[10px] font-mono text-rose-400 mt-0.5">
                            {event.reason_code}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-[10px] text-slate-500">
                        <span className="flex items-center gap-1" title={event.hash}>
                          <LinkIcon className="w-3 h-3" />
                          {event.hash.slice(0, 10)}…
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {auditEvents.length > 8 && (
              <div className="px-4 py-2 border-t border-slate-800 text-[11px] font-mono text-slate-500">
                Showing the 8 most recent of {auditEvents.length} events.
              </div>
            )}
          </div>
        )}
      </section>

      {/* Decision Deep-Dive Inspector Modal */}
      {selectedDecision && (
        <Modal
          isOpen={!!selectedDecision}
          onClose={() => setSelectedDecision(null)}
          title={`Security Decision Evidence: ${selectedDecision.decision.toUpperCase()}`}
          maxWidth="2xl"
        >
          <div className="space-y-5 text-xs">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-4 font-mono">
              <div className="flex items-center gap-3">
                <Badge label={selectedDecision.decision} size="md" />
                <span className="text-slate-400 uppercase text-xs">{selectedDecision.subject_type}</span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-300">{selectedDecision.reason_code}</span>
              </div>
              <div className="text-slate-400 text-[11px]">
                Engine Latency:{' '}
                <strong className="text-teal-400">{selectedDecision.latency_ms.toFixed(2)} ms</strong>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-850/70 border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block mb-1">
                Plain-Text Human Explanation (Safe for Display)
              </span>
              <p className="text-sm font-sans text-slate-100 leading-relaxed">
                {selectedDecision.explanation}
              </p>
            </div>

            <div>
              <span className="text-slate-400 text-xs font-mono uppercase tracking-wider block mb-2">
                Rules Evaluated by Security Engine ({selectedDecision.rules_fired.length})
              </span>
              <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
                {selectedDecision.rules_fired.map((rule, index) => (
                  <div key={index} className="p-2.5 flex items-start gap-3">
                    {rule.passed ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-medium text-slate-200">{rule.rule}</span>
                        <span
                          className={`text-[10px] font-mono uppercase ${
                            rule.passed ? 'text-emerald-400' : 'text-rose-400'
                          }`}
                        >
                          {rule.passed ? 'PASSED' : 'VIOLATION / FAILED'}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5 font-sans">{rule.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <span className="text-slate-400 text-xs font-mono uppercase tracking-wider block mb-2">
                Supporting Evidence (Zero Secrets / Non-Sensitive)
              </span>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <pre className="font-mono text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap select-all">
                  {JSON.stringify(selectedDecision.evidence, null, 2)}
                </pre>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 grid grid-cols-2 sm:grid-cols-3 gap-3 text-[11px] font-mono text-slate-400">
              <div>
                <span className="text-slate-500 block text-[10px]">ENGINE</span>
                {selectedDecision.engine_name} v{selectedDecision.engine_version}
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">POLICY VERSION</span>
                v{selectedDecision.policy_version}
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">DECIDED AT</span>
                {formatDateTime(selectedDecision.decided_at)}
              </div>
              <div className="col-span-2 sm:col-span-3">
                <span className="text-slate-500 block text-[10px]">DECISION UUID</span>
                <span className="select-all text-slate-300">{selectedDecision.decision_id}</span>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
