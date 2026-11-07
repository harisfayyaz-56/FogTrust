import React, { useEffect, useMemo, useState } from 'react';
import { Sliders, ShieldCheck, Cog, RotateCcw, Lock, Info } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getPolicy } from '../../services/api';
import { PolicyConfig } from '../../types/api';
import { EmptyState, ErrorState, LoadingState } from '../common/ViewState';
import { formatDateTime } from '../../utils/nodeStatus';

interface PolicyViewProps {
  onNavigate?: (tab: string, nodeId?: string) => void;
}

interface WeightRow {
  key: string;
  label: string;
  help: string;
  value: number;
}

const WEIGHT_META: Record<string, { label: string; help: string }> = {
  missed_heartbeat: {
    label: 'Missed heartbeat',
    help: 'Penalty per unacknowledged heartbeat interval.',
  },
  signature_failure: {
    label: 'Signature failure',
    help: 'Penalty when an Ed25519 signature does not verify.',
  },
  task_failure: {
    label: 'Task failure',
    help: 'Penalty for a failed or stalled task execution.',
  },
  integrity_failure: {
    label: 'Integrity failure',
    help: 'Penalty when an encrypted result fails AES-GCM tag verification (T4).',
  },
  load_inconsistency: {
    label: 'Load inconsistency',
    help: 'Penalty when reported load disagrees with active assignments.',
  },
  task_success: {
    label: 'Task success',
    help: 'Reward for a successfully completed and verified task.',
  },
  heartbeat_success: {
    label: 'Heartbeat success',
    help: 'Reward for each accepted signed heartbeat.',
  },
};

const formatWeight = (value: number): string => (value > 0 ? `+${value}` : `${value}`);

export const PolicyView: React.FC<PolicyViewProps> = ({ onNavigate }) => {
  const { isDemoMode, role } = useAuth();
  const [policy, setPolicy] = useState<PolicyConfig | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const fetchPolicy = async () => {
    setIsLoading(true);
    setLoadError(null);
    try {
      const p = await getPolicy(isDemoMode);
      setPolicy(p);
    } catch (err: unknown) {
      setPolicy(null);
      setLoadError(err instanceof Error ? err.message : 'Could not load the trust policy.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicy();
  }, [isDemoMode]);

  const isAdmin = role === 'admin';

  const weightRows = useMemo<WeightRow[]>(() => {
    const weights = (policy?.values.weights || {}) as Record<string, number>;
    return Object.entries(weights).map(([key, value]) => ({
      key,
      label: WEIGHT_META[key]?.label || key.replace(/_/g, ' '),
      help: WEIGHT_META[key]?.help || 'Rule weight applied by the trust engine.',
      value: typeof value === 'number' ? value : 0,
    }));
  }, [policy]);

  const threshold = policy?.values.trust_threshold;
  const autoRevokeBelow = policy?.values.auto_revoke_below;
  const timestampWindow = policy?.values.timestamp_window_s;
  const heartbeatInterval = policy?.values.heartbeat_interval_s;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Sliders className="w-5 h-5 text-teal-400" />
            Security & Trust Scoring Policy
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Read-only view of the immutable, versioned policy regulating rule weights, clock skew windows,
            and task scheduling thresholds.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchPolicy}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium disabled:opacity-50"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          {isAdmin && (
            <button
              onClick={() => onNavigate?.('settings')}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors shadow-sm"
            >
              <Cog className="w-4 h-4" />
              <span>Edit in Admin Settings</span>
            </button>
          )}
        </div>
      </div>

      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-3 text-xs text-slate-300">
        <Info className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
        <p>
          This page is informational for every role. Policy changes are restricted to Administrators and
          are performed from <span className="font-mono text-teal-300">Admin Settings</span> with numeric
          validation, an explicit confirm step, and a mandatory audited change reason.
        </p>
      </div>

      {loadError ? (
        <ErrorState title="Could not load the trust policy" message={loadError} onRetry={fetchPolicy} />
      ) : isLoading ? (
        <LoadingState label="Loading active policy…" />
      ) : !policy ? (
        <EmptyState
          title="No policy published"
          description="The broker returned no active policy document. An Administrator must publish the first policy version before trust evaluation can run."
          icon={<Sliders className="w-5 h-5" />}
        />
      ) : (
        <div className="space-y-6">
          {/* Active Policy Version Badge */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono uppercase text-slate-400">Active Version</span>
                <span className="px-2 py-0.5 rounded-md bg-teal-950 border border-teal-800 text-teal-300 font-mono text-sm font-bold">
                  v{policy.version}
                </span>
                <span className="text-xs text-slate-500">•</span>
                <span className="text-xs text-slate-400 font-mono">
                  Changed by: {policy.changed_by || 'system'}
                </span>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-950 border border-slate-700 text-[10px] font-mono uppercase text-slate-400">
                  <Lock className="w-3 h-3" />
                  Read-only
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-2 font-sans italic">
                “{policy.change_reason || 'No change reason recorded'}”
              </p>
            </div>

            <div className="text-xs text-slate-500 font-mono">
              Published: {formatDateTime(policy.changed_at)}
            </div>
          </div>

          {/* Thresholds Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400 text-xs font-mono uppercase">
                Scheduler Trust Threshold
              </span>
              <div className="text-2xl font-bold font-mono text-teal-400 mt-2">
                &gt;= {threshold ?? '—'}
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Nodes with a score below this threshold are disqualified from receiving new tasks (ST-6).
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400 text-xs font-mono uppercase">
                Auto-Revocation Cutoff
              </span>
              <div className="text-2xl font-bold font-mono text-rose-400 mt-2">
                &lt; {autoRevokeBelow ?? '—'}
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Severely misbehaving nodes are revoked automatically by the trust engine (T3 stall).
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400 text-xs font-mono uppercase">
                Anti-Replay Window (s)
              </span>
              <div className="text-2xl font-bold font-mono text-slate-200 mt-2">
                {timestampWindow ?? '—'} seconds
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Heartbeats outside this window return HEARTBEAT_STALE (T2 clock skew protection).
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400 text-xs font-mono uppercase">
                Heartbeat Frequency
              </span>
              <div className="text-2xl font-bold font-mono text-slate-200 mt-2">
                Every {heartbeatInterval ?? '—'}s
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Interval expected between consecutive signed Ed25519 node heartbeats.
              </p>
            </div>
          </div>

          {/* Rule Weights Breakdown */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-teal-400" />
                Rule Weights
              </h2>
              <span className="text-[11px] font-mono text-slate-500">
                Negative = penalty · Positive = reward
              </span>
            </div>

            {weightRows.length === 0 ? (
              <EmptyState
                title="No rule weights configured"
                description="This policy version does not define any trust rule weights."
                icon={<Sliders className="w-5 h-5" />}
              />
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono text-xs">
                {weightRows.map((row) => (
                  <div key={row.key} className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                    <span className="text-slate-400 block text-[11px] uppercase">{row.label}</span>
                    <span
                      className={`font-bold text-base ${
                        row.value > 0 ? 'text-emerald-400' : row.value < 0 ? 'text-rose-400' : 'text-slate-300'
                      }`}
                    >
                      {formatWeight(row.value)} pts
                    </span>
                    <span className="text-[10px] text-slate-500 block">{row.help}</span>
                    <span className="text-[10px] text-slate-600 block mt-1">{row.key}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
