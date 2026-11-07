import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Cog,
  Lock,
  RotateCcw,
  ShieldCheck,
  Sliders,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getPolicy, updatePolicy } from '../../services/api';
import { PolicyConfig } from '../../types/api';
import { Modal } from '../common/Modal';
import { EmptyState, ErrorState, LoadingState } from '../common/ViewState';
import { formatDateTime } from '../../utils/nodeStatus';

interface WeightField {
  key: string;
  label: string;
  min: number;
  max: number;
  defaultValue: number;
  help: string;
}

const WEIGHT_FIELDS: WeightField[] = [
  {
    key: 'missed_heartbeat',
    label: 'Missed heartbeat',
    min: -100,
    max: 0,
    defaultValue: -10,
    help: 'Penalty per unacknowledged heartbeat interval.',
  },
  {
    key: 'signature_failure',
    label: 'Signature failure',
    min: -100,
    max: 0,
    defaultValue: -20,
    help: 'Penalty when an Ed25519 signature does not verify.',
  },
  {
    key: 'task_failure',
    label: 'Task failure',
    min: -100,
    max: 0,
    defaultValue: -15,
    help: 'Penalty for a failed or stalled task execution.',
  },
  {
    key: 'integrity_failure',
    label: 'Integrity failure',
    min: -100,
    max: 0,
    defaultValue: -25,
    help: 'Penalty when an encrypted result fails AES-GCM tag verification.',
  },
  {
    key: 'load_inconsistency',
    label: 'Load inconsistency',
    min: -100,
    max: 0,
    defaultValue: -5,
    help: 'Penalty when reported load disagrees with active assignments.',
  },
  {
    key: 'task_success',
    label: 'Task success',
    min: 0,
    max: 50,
    defaultValue: 5,
    help: 'Reward for a successfully completed and verified task.',
  },
  {
    key: 'heartbeat_success',
    label: 'Heartbeat success',
    min: 0,
    max: 50,
    defaultValue: 2,
    help: 'Reward for each accepted signed heartbeat.',
  },
];

interface ChangeRow {
  key: string;
  label: string;
  before: number;
  after: number;
}

export const AdminSettingsView: React.FC = () => {
  const { isDemoMode, role, currentUser } = useAuth();
  const isAdmin = role === 'admin';

  const [policy, setPolicy] = useState<PolicyConfig | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [threshold, setThreshold] = useState<number>(70);
  const [weights, setWeights] = useState<Record<string, number>>({});
  const [changeReason, setChangeReason] = useState<string>('');
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);

  const [isConfirmOpen, setIsConfirmOpen] = useState<boolean>(false);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const applyPolicyToForm = (nextPolicy: PolicyConfig) => {
    setThreshold(Number(nextPolicy.values.trust_threshold ?? 70));
    const sourceWeights = (nextPolicy.values.weights || {}) as Record<string, number>;
    const resolved: Record<string, number> = {};
    for (const field of WEIGHT_FIELDS) {
      const value = sourceWeights[field.key];
      resolved[field.key] = typeof value === 'number' ? value : field.defaultValue;
    }
    setWeights(resolved);
  };

  const loadPolicy = async () => {
    if (!isAdmin) {
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setLoadError(null);
    setFormErrors({});
    setFormError(null);
    try {
      const fresh = await getPolicy(isDemoMode);
      setPolicy(fresh);
      applyPolicyToForm(fresh);
    } catch (err: unknown) {
      setLoadError(err instanceof Error ? err.message : 'Could not load the trust policy.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadPolicy();
  }, [isAdmin, isDemoMode]);

  const changes = useMemo<ChangeRow[]>(() => {
    if (!policy) return [];
    const rows: ChangeRow[] = [];
    const previousThreshold = Number(policy.values.trust_threshold ?? 0);
    if (threshold !== previousThreshold) {
      rows.push({
        key: 'trust_threshold',
        label: 'Scheduler trust threshold',
        before: previousThreshold,
        after: threshold,
      });
    }

    const previousWeights = (policy.values.weights || {}) as Record<string, number>;
    for (const field of WEIGHT_FIELDS) {
      const before = typeof previousWeights[field.key] === 'number' ? previousWeights[field.key] : field.defaultValue;
      const after = weights[field.key];
      if (typeof after === 'number' && after !== before) {
        rows.push({ key: field.key, label: field.label, before, after });
      }
    }

    return rows;
  }, [policy, threshold, weights]);

  const validate = (): boolean => {
    const errors: Record<string, string> = {};

    if (!Number.isFinite(threshold) || !Number.isInteger(threshold) || threshold < 0 || threshold > 100) {
      errors.trust_threshold = 'Threshold must be a whole number between 0 and 100.';
    }

    for (const field of WEIGHT_FIELDS) {
      const value = weights[field.key];
      if (
        typeof value !== 'number' ||
        !Number.isFinite(value) ||
        !Number.isInteger(value) ||
        value < field.min ||
        value > field.max
      ) {
        errors[field.key] = `${field.label} must be a whole number between ${field.min} and ${field.max}.`;
      }
    }

    if (changeReason.trim().length < 10) {
      errors.change_reason = 'A mandatory audit reason of at least 10 characters is required.';
    }

    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleReview = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSaveError(null);
    setSuccessMessage(null);

    if (!validate()) return;
    if (changes.length === 0) {
      setFormError('No changes to publish. Adjust the threshold, a rule weight, or the change reason.');
      return;
    }
    setIsConfirmOpen(true);
  };

  const buildNextValues = (): Record<string, unknown> => ({
    ...(policy?.values || {}),
    trust_threshold: threshold,
    weights: {
      ...((policy?.values.weights || {}) as Record<string, number>),
      ...weights,
    },
  });

  const handleConfirmPublish = async () => {
    if (!policy) return;
    setIsSaving(true);
    setSaveError(null);

    const nextValues = buildNextValues();
    const nextVersion = (policy.version || 0) + 1;

    try {
      if (isDemoMode) {
        setPolicy({
          version: nextVersion,
          values: nextValues as PolicyConfig['values'],
          changed_by: currentUser?.username || 'admin1',
          changed_at: new Date().toISOString(),
          change_reason: changeReason.trim(),
        });
      } else {
        const updated = await updatePolicy(nextValues, changeReason.trim());
        setPolicy(updated);
        applyPolicyToForm(updated);
      }

      setSuccessMessage(
        `Policy v${nextVersion} published. ${changes.length} change${
          changes.length === 1 ? '' : 's'
        } audited to the hash chain.`
      );
      setIsConfirmOpen(false);
      setChangeReason('');
      setFormErrors({});
    } catch (err: unknown) {
      setSaveError(err instanceof Error ? err.message : 'Policy update failed.');
    } finally {
      setIsSaving(false);
    }
  };

  if (!isAdmin) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Cog className="w-5 h-5 text-teal-400" />
            Administrator Settings
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">Trust threshold and rule-weight administration.</p>
        </div>
        <div className="p-8 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col items-center text-center gap-3">
          <div className="w-12 h-12 rounded-full bg-rose-950/70 border border-rose-800 flex items-center justify-center">
            <Lock className="w-6 h-6 text-rose-400" />
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-100">Administrator access required</p>
            <p className="text-xs text-slate-400 mt-1 max-w-md">
              The server rejects policy changes from viewers and operators. Your current role is{' '}
              <span className="font-mono text-slate-300">{role}</span>.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Cog className="w-5 h-5 text-teal-400" />
            Administrator Settings
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Edit the scheduler trust threshold and rule weights with numeric-range validation and an explicit
            confirm step. Every publish creates a new immutable policy version.
          </p>
        </div>

        <button
          onClick={loadPolicy}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium disabled:opacity-50"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Reload policy</span>
        </button>
      </div>

      <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/60 flex items-start gap-3 text-xs text-amber-200">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <p className="font-semibold text-amber-300">High-impact security configuration</p>
          <p className="mt-0.5 text-amber-200/80">
            Lowering the threshold admits less-trusted nodes to task scheduling. Penalties and rewards are applied
            by the trust engine on the next evaluation. The server validates the same ranges and records the change
            reason in the append-only audit log.
          </p>
        </div>
      </div>

      {loadError ? (
        <ErrorState title="Could not load the trust policy" message={loadError} onRetry={loadPolicy} />
      ) : isLoading ? (
        <LoadingState label="Loading current policy…" />
      ) : !policy ? (
        <EmptyState
          title="No policy document available"
          description="The broker returned no active policy. Publish the initial policy version before changing threshold or rule weights."
          icon={<Cog className="w-5 h-5" />}
          action={
            <button
              onClick={loadPolicy}
              className="mt-1 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700 text-xs font-medium"
            >
              Retry
            </button>
          }
        />
      ) : (
        <>
          {successMessage && (
            <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800 flex items-start justify-between gap-3 text-xs text-emerald-200">
              <div className="flex items-start gap-2.5">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-emerald-300">Settings published</p>
                  <p className="mt-0.5">{successMessage}</p>
                </div>
              </div>
              <button onClick={() => setSuccessMessage(null)} className="text-emerald-300/80 hover:text-emerald-200 text-[11px] underline">
                dismiss
              </button>
            </div>
          )}

          {/* Current version */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase text-slate-400">Active version</span>
              <span className="px-2 py-0.5 rounded-md bg-teal-950 border border-teal-800 text-teal-300 font-mono text-sm font-bold">
                v{policy.version}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                changed by {policy.changed_by || 'admin1'} · {formatDateTime(policy.changed_at)}
              </span>
            </div>
            <p className="text-xs text-slate-400 italic max-w-xl">“{policy.change_reason}”</p>
          </div>

          <form onSubmit={handleReview} noValidate className="space-y-5">
            <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-teal-400" />
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                  Scheduler trust threshold
                </h2>
              </div>
              <div className="flex flex-wrap items-end gap-4">
                <div>
                  <label htmlFor="trust-threshold" className="block text-xs font-medium text-slate-300 mb-1">
                    Minimum score to receive tasks (0–100)
                  </label>
                  <input
                    id="trust-threshold"
                    type="number"
                    min="0"
                    max="100"
                    step="1"
                    value={threshold}
                    onChange={(e) => setThreshold(Number(e.target.value))}
                    className={`w-32 bg-slate-950 border rounded-lg px-3 py-2 text-sm text-slate-100 font-mono focus:outline-none ${
                      formErrors.trust_threshold ? 'border-rose-600 focus:border-rose-500' : 'border-slate-700 focus:border-teal-500'
                    }`}
                  />
                </div>
                <input
                  type="range"
                  min="0"
                  max="100"
                  step="1"
                  value={Number.isFinite(threshold) ? threshold : 0}
                  onChange={(e) => setThreshold(Number(e.target.value))}
                  className="flex-1 min-w-[200px] accent-teal-500 cursor-pointer"
                  aria-label="Trust threshold slider"
                />
                <span className="text-xs text-slate-400 font-mono">
                  Nodes scoring &gt;= {Number.isFinite(threshold) ? threshold : '—'} are eligible
                </span>
              </div>
              {formErrors.trust_threshold && (
                <p className="text-[11px] text-rose-400">{formErrors.trust_threshold}</p>
              )}
            </div>

            <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                  Rule weights
                </h2>
                <span className="text-[11px] font-mono text-slate-500">
                  Negative = penalty · Positive = reward
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {WEIGHT_FIELDS.map((field) => (
                  <div key={field.key} className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <label htmlFor={`weight-${field.key}`} className="block text-xs font-medium text-slate-200">
                          {field.label}
                        </label>
                        <span className="text-[10px] font-mono text-slate-500">
                          {field.key} · {field.min} to {field.max}
                        </span>
                      </div>
                      <input
                        id={`weight-${field.key}`}
                        type="number"
                        min={field.min}
                        max={field.max}
                        step="1"
                        value={weights[field.key] ?? field.defaultValue}
                        onChange={(e) =>
                          setWeights((current) => ({ ...current, [field.key]: Number(e.target.value) }))
                        }
                        className={`w-24 bg-slate-900 border rounded-lg px-2.5 py-1.5 text-sm text-slate-100 font-mono text-right focus:outline-none ${
                          formErrors[field.key] ? 'border-rose-600 focus:border-rose-500' : 'border-slate-700 focus:border-teal-500'
                        }`}
                      />
                    </div>
                    <p className="text-[11px] text-slate-500 mt-2">{field.help}</p>
                    {formErrors[field.key] && <p className="text-[11px] text-rose-400 mt-1">{formErrors[field.key]}</p>}
                  </div>
                ))}
              </div>
            </div>

            <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <label htmlFor="change-reason" className="block text-xs font-medium text-slate-300">
                Mandatory change reason (audited, at least 10 characters)
              </label>
              <textarea
                id="change-reason"
                rows={3}
                value={changeReason}
                onChange={(e) => setChangeReason(e.target.value)}
                placeholder="e.g. Raise the integrity penalty after the T4 tamper simulation"
                className={`w-full bg-slate-950 border rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none ${
                  formErrors.change_reason ? 'border-rose-600 focus:border-rose-500' : 'border-slate-700 focus:border-teal-500'
                }`}
              />
              <div className="flex items-center justify-between">
                {formErrors.change_reason ? (
                  <p className="text-[11px] text-rose-400">{formErrors.change_reason}</p>
                ) : (
                  <span className="text-[10px] text-slate-500">The reason is stored with the new policy version.</span>
                )}
                <span className="text-[10px] font-mono text-slate-500">{changeReason.trim().length}/10</span>
              </div>
            </div>

            {formError && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-xs text-rose-200">
                {formError}
              </div>
            )}

            <div className="flex items-center justify-between gap-3 pt-1">
              <span className="text-[11px] font-mono text-slate-500">
                {changes.length} pending change{changes.length === 1 ? '' : 's'}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    if (policy) applyPolicyToForm(policy);
                    setChangeReason('');
                    setFormErrors({});
                    setFormError(null);
                  }}
                  className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-medium"
                >
                  Reset form
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors flex items-center gap-1.5"
                >
                  <ShieldCheck className="w-4 h-4" />
                  <span>Review changes</span>
                </button>
              </div>
            </div>
          </form>
        </>
      )}

      {/* Confirmation step */}
      {isConfirmOpen && policy && (
        <Modal
          isOpen={isConfirmOpen}
          onClose={() => {
            if (!isSaving) setIsConfirmOpen(false);
          }}
          title="Confirm & publish new policy version"
          maxWidth="lg"
        >
          <div className="space-y-4 text-xs">
            <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/80 flex items-start gap-3 text-amber-200">
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <p>
                This publishes <strong>v{(policy.version || 0) + 1}</strong>. The current policy remains immutable
                in history, and this change is audited with your username and reason.
              </p>
            </div>

            <div className="rounded-lg border border-slate-800 overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px]">
                  <tr>
                    <th className="py-2 px-3">Setting</th>
                    <th className="py-2 px-3">Current</th>
                    <th className="py-2 px-3">New</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {changes.map((change) => (
                    <tr key={change.key} className="text-slate-300">
                      <td className="py-2 px-3">
                        <span className="text-slate-200">{change.label}</span>
                        <span className="block text-[10px] font-mono text-slate-500">{change.key}</span>
                      </td>
                      <td className="py-2 px-3 font-mono text-slate-400">{change.before}</td>
                      <td className="py-2 px-3 font-mono font-bold text-teal-300">{change.after}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 text-[10px] font-mono uppercase block mb-1">Change reason</span>
              <p className="text-slate-300">{changeReason.trim()}</p>
            </div>

            {saveError && (
              <div className="p-2.5 rounded bg-rose-900/50 border border-rose-700 text-rose-200 text-xs">
                {saveError}
              </div>
            )}

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsConfirmOpen(false)}
                disabled={isSaving}
                className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-medium disabled:opacity-50"
              >
                Back to edit
              </button>
              <button
                type="button"
                onClick={handleConfirmPublish}
                disabled={isSaving}
                className="px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors flex items-center gap-1.5 disabled:opacity-50"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>{isSaving ? 'Publishing…' : `Publish v${(policy.version || 0) + 1}`}</span>
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
