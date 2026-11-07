import React, { useEffect, useState } from 'react';
import { Sliders, ShieldCheck, History, Edit3, RotateCcw } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getPolicy, updatePolicy } from '../../services/api';
import { PolicyConfig } from '../../types/api';
import { Modal } from '../common/Modal';

export const PolicyView: React.FC = () => {
  const { isDemoMode, role } = useAuth();
  const [policy, setPolicy] = useState<PolicyConfig | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Edit policy modal
  const [isEditOpen, setIsEditOpen] = useState<boolean>(false);
  const [trustThreshold, setTrustThreshold] = useState<number>(70);
  const [autoRevokeBelow, setAutoRevokeBelow] = useState<number>(25);
  const [heartbeatInterval, setHeartbeatInterval] = useState<number>(10);
  const [timestampWindow, setTimestampWindow] = useState<number>(30);
  const [changeReason, setChangeReason] = useState<string>('');
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchPolicy = async () => {
    setIsLoading(true);
    try {
      const p = await getPolicy(isDemoMode);
      setPolicy(p);
      if (p.values) {
        setTrustThreshold(p.values.trust_threshold || 70);
        setAutoRevokeBelow(p.values.auto_revoke_below || 25);
        setHeartbeatInterval(p.values.heartbeat_interval_s || 10);
        setTimestampWindow(p.values.timestamp_window_s || 30);
      }
    } catch (err) {
      console.error('Failed to load policy:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicy();
  }, [isDemoMode]);

  const handleUpdatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!changeReason.trim()) {
      setErrorMsg('Mandatory change_reason must be provided for the audit log.');
      return;
    }

    setIsSaving(true);
    setErrorMsg(null);

    const newValues = {
      ...(policy?.values || {}),
      trust_threshold: trustThreshold,
      auto_revoke_below: autoRevokeBelow,
      heartbeat_interval_s: heartbeatInterval,
      timestamp_window_s: timestampWindow,
    };

    try {
      if (isDemoMode) {
        setPolicy({
          version: (policy?.version || 1) + 1,
          values: newValues,
          changed_by: 'admin1',
          changed_at: new Date().toISOString(),
          change_reason: changeReason,
        });
      } else {
        await updatePolicy(newValues, changeReason);
        await fetchPolicy();
      }

      setIsEditOpen(false);
      setChangeReason('');
    } catch (err: any) {
      setErrorMsg(err.message || 'Policy update failed');
    } finally {
      setIsSaving(false);
    }
  };

  const isAdmin = role === 'admin';

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
            Immutable, versioned policy regulating rule weights, clock skew windows, and task scheduling thresholds.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchPolicy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          {isAdmin && (
            <button
              onClick={() => {
                setIsEditOpen(true);
                setErrorMsg(null);
              }}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors shadow-sm"
            >
              <Edit3 className="w-4 h-4" />
              <span>Update Policy (Admin)</span>
            </button>
          )}
        </div>
      </div>

      {policy && (
        <div className="space-y-6">
          {/* Active Policy Version Badge */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono uppercase text-slate-400">Active Version</span>
                <span className="px-2 py-0.5 rounded-md bg-teal-950 border border-teal-800 text-teal-300 font-mono text-sm font-bold">
                  v{policy.version}
                </span>
                <span className="text-xs text-slate-500">•</span>
                <span className="text-xs text-slate-400 font-mono">
                  Changed by: {policy.changed_by || 'admin1'}
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-2 font-sans italic">
                "{policy.change_reason}"
              </p>
            </div>

            <div className="text-xs text-slate-500 font-mono">
              Timestamp: {new Date(policy.changed_at).toLocaleString()}
            </div>
          </div>

          {/* Thresholds Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400 text-xs font-mono uppercase">
                Scheduler Trust Threshold
              </span>
              <div className="text-2xl font-bold font-mono text-teal-400 mt-2">
                &gt;= {policy.values.trust_threshold}
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Nodes with score below this threshold are disqualified from receiving new tasks (ST-6).
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400 text-xs font-mono uppercase">
                Auto-Revocation Cutoff
              </span>
              <div className="text-2xl font-bold font-mono text-rose-400 mt-2">
                &lt; {policy.values.auto_revoke_below || 25}
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
                {policy.values.timestamp_window_s || 30} seconds
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
                Every {policy.values.heartbeat_interval_s || 10}s
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Interval expected between consecutive signed Ed25519 node heartbeats.
              </p>
            </div>
          </div>

          {/* Rule Weights Breakdown */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono mb-4">
              Rule-Based Penalty Deductions
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono text-xs">
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                <span className="text-slate-400 block text-[11px]">MISSED HEARTBEATS</span>
                <span className="text-rose-400 font-bold text-base">-15 pts</span>
                <span className="text-[10px] text-slate-500 block">per unacknowledged interval</span>
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                <span className="text-slate-400 block text-[11px]">STALE HEARTBEATS</span>
                <span className="text-rose-400 font-bold text-base">-10 pts</span>
                <span className="text-[10px] text-slate-500 block">clock skew violation</span>
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                <span className="text-slate-400 block text-[11px]">LOAD INCONSISTENCIES</span>
                <span className="text-rose-400 font-bold text-base">-20 pts</span>
                <span className="text-[10px] text-slate-500 block">reported vs observed load</span>
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                <span className="text-slate-400 block text-[11px]">FAILED TASK TIMEOUT</span>
                <span className="text-rose-400 font-bold text-base">-25 pts</span>
                <span className="text-[10px] text-slate-500 block">worker stall detection (T3)</span>
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg sm:col-span-2">
                <span className="text-slate-400 block text-[11px]">RESULT INTEGRITY FAILURE</span>
                <span className="text-rose-400 font-bold text-base">-50 pts</span>
                <span className="text-[10px] text-slate-500 block">AES-GCM tag verification failure (T4 tamper)</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Edit Policy Modal (Admin Only) */}
      {isEditOpen && (
        <Modal
          isOpen={isEditOpen}
          onClose={() => setIsEditOpen(false)}
          title="Publish New Policy Version"
        >
          <form onSubmit={handleUpdatePolicy} className="space-y-4">
            {errorMsg && (
              <div className="p-2.5 rounded bg-rose-900/50 border border-rose-700 text-rose-200 text-xs">
                {errorMsg}
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Scheduler Trust Admission Threshold (0–100):
              </label>
              <input
                type="number"
                min="0"
                max="100"
                value={trustThreshold}
                onChange={(e) => setTrustThreshold(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-teal-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Auto-Revocation Cutoff Score:
              </label>
              <input
                type="number"
                min="0"
                max="50"
                value={autoRevokeBelow}
                onChange={(e) => setAutoRevokeBelow(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-teal-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Timestamp Window (Seconds):
              </label>
              <input
                type="number"
                min="5"
                max="300"
                value={timestampWindow}
                onChange={(e) => setTimestampWindow(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-teal-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Mandatory Change Reason (Audited to Hash Chain):
              </label>
              <textarea
                required
                rows={3}
                value={changeReason}
                onChange={(e) => setChangeReason(e.target.value)}
                placeholder="e.g. Tightening trust threshold to 75 following perimeter stress test"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-teal-500"
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsEditOpen(false)}
                className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSaving}
                className="px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors"
              >
                {isSaving ? 'Publishing...' : 'Publish Policy v' + ((policy?.version || 1) + 1)}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

