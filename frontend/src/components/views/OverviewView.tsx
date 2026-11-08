import React, { useEffect, useState } from 'react';
import {
  Server,
  ShieldCheck,
  ShieldAlert,
  Activity,
  FileCheck,
  ListTodo,
  TrendingUp,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getNodes, getDecisions, getAuditEvents, getTasks, verifyAuditChain } from '../../services/api';
import { NodeItem, Decision, AuditEvent, Task, AuditVerifyReport } from '../../types/api';
import { Badge } from '../common/Badge';
import { TrustScoreBar } from '../common/TrustScoreBar';
import { EmptyState, ErrorState, LoadingState } from '../common/ViewState';
import { getNodeDisplayStatus } from '../../utils/nodeStatus';

export const OverviewView: React.FC<{ onNavigate: (tab: string) => void }> = ({ onNavigate }) => {
  const { isDemoMode, role } = useAuth();
  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [chainReport, setChainReport] = useState<AuditVerifyReport | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  // A single unavailable endpoint (for example tasks before the backend routes
  // it) must not hide the data that did load. It becomes a warning instead.
  const [partialWarning, setPartialWarning] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState<number>(0);

  useEffect(() => {
    let mounted = true;
    setIsLoading(true);
    setLoadError(null);
    setPartialWarning(null);

    Promise.allSettled([
      getNodes({}, isDemoMode),
      getDecisions({}, isDemoMode),
      role === 'admin' ? getAuditEvents({}, isDemoMode) : Promise.resolve({ results: [] }),
      getTasks({}, isDemoMode),
      role === 'admin' ? verifyAuditChain(isDemoMode) : Promise.resolve(null),
    ]).then(([nodesRes, decisionsRes, auditRes, tasksRes, verifyRes]) => {
      if (!mounted) return;
      if (nodesRes.status === 'fulfilled') setNodes(nodesRes.value.results || []);
      if (decisionsRes.status === 'fulfilled') setDecisions(decisionsRes.value.results || []);
      if (auditRes.status === 'fulfilled') setAuditEvents(auditRes.value.results || []);
      if (tasksRes.status === 'fulfilled') setTasks(tasksRes.value.results || []);
      if (verifyRes.status === 'fulfilled') setChainReport(verifyRes.value);

      const coreFailures = [nodesRes, decisionsRes, tasksRes].filter((res) => res.status === 'rejected');
      if (coreFailures.length === 3) {
        const first = coreFailures[0] as PromiseRejectedResult;
        setLoadError(
          first.reason instanceof Error
            ? first.reason.message
            : 'Could not load dashboard data from the FogTrust broker.'
        );
      } else if (coreFailures.length > 0) {
        const failedNames = [
          nodesRes.status === 'rejected' ? 'nodes' : null,
          decisionsRes.status === 'rejected' ? 'decisions' : null,
          tasksRes.status === 'rejected' ? 'tasks' : null,
        ]
          .filter(Boolean)
          .join(', ');
        const firstFailure = coreFailures[0] as PromiseRejectedResult;
        const reason =
          firstFailure.reason instanceof Error ? firstFailure.reason.message : 'Request failed.';
        setPartialWarning(`Some dashboard data could not be loaded (${failedNames}): ${reason}`);
      }
      setIsLoading(false);
    });

    return () => {
      mounted = false;
    };
  }, [isDemoMode, role, refreshKey]);

  const refresh = () => setRefreshKey((key) => key + 1);

  const activeNodes = nodes.filter((n) => getNodeDisplayStatus(n) === 'active');
  const enrolledNodes = nodes.filter((n) => n.status !== 'revoked');
  const awaitingHeartbeat = enrolledNodes.length - activeNodes.length;
  const revokedNodes = nodes.filter((n) => n.status === 'revoked');
  const avgTrust =
    nodes.length > 0 ? Math.round(nodes.reduce((acc, n) => acc + n.trust_score, 0) / nodes.length) : 0;
  const recentDenials = decisions.filter((d) => d.decision === 'deny');
  const isEmpty = nodes.length === 0 && decisions.length === 0 && tasks.length === 0;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-6 rounded-xl bg-gradient-to-r from-slate-900 via-slate-850 to-teal-950/40 border border-slate-800 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            FogTrust Broker Security Dashboard
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Real-time monitoring for edge node enrollment, cryptographic heartbeat verification,
            rule-based trust scoring (0–100), task scheduling, and hash-chained audit integrity.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onNavigate('evidence')}
            className="px-4 py-2 bg-teal-600 hover:bg-teal-500 text-white rounded-lg text-sm font-medium transition-colors shadow-sm flex items-center gap-2"
          >
            <FileCheck className="w-4 h-4" />
            <span>Open Evidence View (FR-7)</span>
          </button>
        </div>
      </div>

      {partialWarning && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-200">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{partialWarning}</span>
        </div>
      )}

      {loadError ? (
        <ErrorState title="Could not load the security dashboard" message={loadError} onRetry={refresh} />
      ) : isLoading ? (
        <LoadingState label="Loading fleet, decisions, tasks, and audit status…" />
      ) : isEmpty ? (
        <EmptyState
          title="No operational data yet"
          description="The broker has no enrolled nodes, security decisions, or tasks. Enroll an edge node to start seeing live dashboard metrics."
          icon={<Activity className="w-5 h-5" />}
          action={
            <button
              onClick={() => onNavigate('nodes')}
              className="mt-1 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700 text-xs font-medium"
            >
              Open Edge Nodes
            </button>
          }
        />
      ) : (
        <>
      {/* Key Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Active Nodes */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase font-mono">Active Nodes</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-100">{activeNodes.length}</span>
            <span className="text-xs text-slate-500 font-mono">/ {enrolledNodes.length} enrolled</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
            <span className="text-emerald-400 font-medium">
              {enrolledNodes.length > 0 ? Math.round((activeNodes.length / enrolledNodes.length) * 100) : 0}%
            </span>
            <span>fleet availability</span>
          </div>
          <div className="mt-1 text-[11px] text-slate-500">
            {awaitingHeartbeat > 0
              ? `${awaitingHeartbeat} awaiting first heartbeat`
              : 'All enrolled nodes reporting'}
          </div>
        </div>

        {/* Average Trust Score */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase font-mono">Avg Fleet Trust</span>
            <div className="w-8 h-8 rounded-lg bg-teal-500/10 text-teal-400 flex items-center justify-center">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-100">{avgTrust}</span>
            <span className="text-xs text-slate-500 font-mono">/ 100 max</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Admission threshold: <span className="text-teal-400 font-mono font-medium">&gt;= 70</span>
          </div>
        </div>

        {/* Security Decider Interventions */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase font-mono">Security Interventions</span>
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 text-rose-400 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-rose-400">{recentDenials.length}</span>
            <span className="text-xs text-slate-500 font-mono">denials recorded</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            {revokedNodes.length} nodes revoked for violations
          </div>
        </div>

        {/* Audit Chain Status */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase font-mono">Audit Hash Chain</span>
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            {role === 'admin' ? (
              chainReport?.valid ? (
                <span className="text-lg font-bold text-emerald-400 font-mono">VERIFIED OK</span>
              ) : chainReport ? (
                <span className="text-lg font-bold text-rose-400 font-mono">TAMPER DETECTED</span>
              ) : (
                <span className="text-lg font-bold text-slate-400 font-mono">Active</span>
              )
            ) : (
              <span className="text-sm font-medium text-slate-400">Admin Managed</span>
            )}
          </div>
          <div className="mt-2 text-xs text-slate-400">
            {role === 'admin' && chainReport
              ? `${chainReport.events_checked} SHA-256 links verified`
              : 'Immutable append-only ledger'}
          </div>
        </div>
      </div>

      {/* Main Grid: Fleet Status & Recent Explainable Decisions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Node Fleet Overview Card */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-teal-400" />
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                  Enrolled Edge Nodes
                </h2>
              </div>
              <button
                onClick={() => onNavigate('nodes')}
                className="text-xs text-teal-400 hover:text-teal-300 font-medium"
              >
                View all &rarr;
              </button>
            </div>

            <div className="divide-y divide-slate-800">
              {nodes.slice(0, 4).map((node) => (
                <div key={node.id} className="py-3 flex items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-200">{node.name}</span>
                      <Badge label={getNodeDisplayStatus(node)} size="sm" />
                    </div>
                    <p className="text-[11px] text-slate-500 font-mono mt-0.5 truncate max-w-xs">
                      Key: {node.key_fingerprint.slice(0, 16)}...
                    </p>
                  </div>

                  <div className="flex items-center gap-4">
                    <TrustScoreBar score={node.trust_score} />
                    <div className="text-right text-xs">
                      <div className="text-slate-300 font-mono">
                        {node.current_load}/{node.capacity}
                      </div>
                      <div className="text-[10px] text-slate-500">load</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Scheduling Rule: Nodes with Trust &gt;= 70 receive priority dispatch</span>
            <button
              onClick={() => onNavigate('tasks')}
              className="text-teal-400 hover:text-teal-300 font-medium"
            >
              Task Queue ({tasks.length}) &rarr;
            </button>
          </div>
        </div>

        {/* Explainable Security Decisions (FR-7 Highlight) */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-teal-400" />
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                  Explainable Decisions (FR-7)
                </h2>
              </div>
              <button
                onClick={() => onNavigate('evidence')}
                className="text-xs text-teal-400 hover:text-teal-300 font-medium"
              >
                Inspect all &rarr;
              </button>
            </div>

            <div className="space-y-3">
              {decisions.slice(0, 3).map((d) => (
                <div
                  key={d.decision_id}
                  className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Badge label={d.decision} />
                      <span className="text-xs font-mono text-slate-400 uppercase">
                        {d.subject_type}
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">
                      {d.latency_ms.toFixed(2)} ms
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 mt-2 font-sans line-clamp-2">
                    {d.explanation}
                  </p>

                  <div className="mt-2 flex items-center gap-2 text-[10px] font-mono text-slate-500">
                    <span>Reason: {d.reason_code}</span>
                    <span>•</span>
                    <span>Rules evaluated: {d.rules_fired.length}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Every admission or denial stores exact rules and non-secret evidence</span>
            <button
              onClick={() => onNavigate('evidence')}
              className="text-teal-400 hover:text-teal-300 font-medium"
            >
              Full Evidence Table &rarr;
            </button>
          </div>
        </div>
      </div>
        </>
      )}
    </div>
  );
};

