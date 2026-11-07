import React, { useEffect, useState } from 'react';
import {
  KeyRound,
  Plus,
  Copy,
  Check,
  AlertTriangle,
  RotateCcw,
  Clock,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import {
  getEnrollmentTokens,
  createEnrollmentToken,
  cancelEnrollmentToken,
} from '../../services/api';
import { EnrollmentToken } from '../../types/api';
import { Badge } from '../common/Badge';
import { Modal } from '../common/Modal';

export const EnrollmentTokensView: React.FC = () => {
  const { isDemoMode } = useAuth();
  const [tokens, setTokens] = useState<EnrollmentToken[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Create token modal
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(false);
  const [label, setLabel] = useState<string>('');
  const [expiresMinutes, setExpiresMinutes] = useState<number>(15);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Raw token reveal modal (Shown ONCE only!)
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [hasCopied, setHasCopied] = useState<boolean>(false);

  const fetchTokens = async () => {
    setIsLoading(true);
    try {
      const res = await getEnrollmentTokens(statusFilter || undefined, isDemoMode);
      setTokens(res.results || []);
    } catch (err) {
      console.error('Failed to load enrollment tokens:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTokens();
  }, [isDemoMode, statusFilter]);

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setCreateError(null);

    try {
      if (isDemoMode) {
        const dummyRawToken = `fogtrust_tok_${Math.random().toString(36).substring(2, 15)}_${Math.random().toString(36).substring(2, 15)}`;
        const newToken: EnrollmentToken = {
          id: `tok-${Date.now()}`,
          label,
          created_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + expiresMinutes * 60000).toISOString(),
          used_at: null,
          cancelled_at: null,
        };
        setTokens([newToken, ...tokens]);
        setRevealedToken(dummyRawToken);
      } else {
        const created = await createEnrollmentToken(label, expiresMinutes);
        await fetchTokens();
        if (created.token) {
          setRevealedToken(created.token);
        }
      }

      setIsCreateOpen(false);
      setLabel('');
      setExpiresMinutes(15);
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create enrollment token');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancelToken = async (tokenId: string) => {
    if (!confirm('Are you sure you want to cancel this unused enrollment token?')) return;
    try {
      if (isDemoMode) {
        setTokens((prev) =>
          prev.map((t) => (t.id === tokenId ? { ...t, cancelled_at: new Date().toISOString() } : t))
        );
      } else {
        await cancelEnrollmentToken(tokenId);
        await fetchTokens();
      }
    } catch (err: any) {
      alert(err.message || 'Failed to cancel token');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setHasCopied(true);
    setTimeout(() => setHasCopied(false), 2500);
  };

  const getTokenStatus = (t: EnrollmentToken): 'used' | 'cancelled' | 'expired' | 'pending' => {
    if (t.used_at) return 'used';
    if (t.cancelled_at) return 'cancelled';
    if (new Date(t.expires_at) < new Date()) return 'expired';
    return 'pending';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-teal-400" />
            Node Enrollment Tokens (FR-1)
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Issue high-entropy, one-time enrollment secrets. Raw tokens are SHA-256 hashed and shown once.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchTokens}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => {
              setIsCreateOpen(true);
              setCreateError(null);
            }}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors shadow-sm"
          >
            <Plus className="w-4 h-4" />
            <span>Generate Token</span>
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span>Filter Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-teal-500"
          >
            <option value="">All Tokens</option>
            <option value="pending">Pending (Valid)</option>
            <option value="used">Used</option>
            <option value="cancelled">Cancelled</option>
            <option value="expired">Expired</option>
          </select>
        </div>

        <div className="text-xs text-slate-500 font-mono">
          Security: Raw tokens are never stored in the database or server logs.
        </div>
      </div>

      {/* Tokens Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Label</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Created At</th>
                <th className="py-3 px-4">Expires At</th>
                <th className="py-3 px-4">Resolution</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {tokens.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    {isLoading ? 'Loading tokens...' : 'No enrollment tokens found.'}
                  </td>
                </tr>
              ) : (
                tokens.map((token) => {
                  const status = getTokenStatus(token);
                  return (
                    <tr key={token.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3.5 px-4 font-medium text-slate-100 flex items-center gap-2">
                        <span>{token.label}</span>
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge label={status} />
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        {new Date(token.created_at).toLocaleTimeString()}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        {new Date(token.expires_at).toLocaleTimeString()}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                        {token.used_at ? (
                          <span className="text-emerald-400 flex items-center gap-1">
                            <CheckCircle className="w-3.5 h-3.5" /> Enrolled
                          </span>
                        ) : token.cancelled_at ? (
                          <span className="text-rose-400 flex items-center gap-1">
                            <XCircle className="w-3.5 h-3.5" /> Cancelled
                          </span>
                        ) : status === 'expired' ? (
                          <span className="text-slate-500 flex items-center gap-1">
                            <Clock className="w-3.5 h-3.5" /> Expired
                          </span>
                        ) : (
                          <span className="text-amber-400">Awaiting Node</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        {status === 'pending' && (
                          <button
                            onClick={() => handleCancelToken(token.id)}
                            className="px-2.5 py-1 rounded border border-rose-800/70 text-rose-400 hover:bg-rose-950 text-xs transition-colors"
                          >
                            Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Generate Token Modal */}
      {isCreateOpen && (
        <Modal
          isOpen={isCreateOpen}
          onClose={() => setIsCreateOpen(false)}
          title="Create One-Time Enrollment Token"
        >
          <form onSubmit={handleCreateSubmit} className="space-y-4">
            {createError && (
              <div className="p-2.5 rounded bg-rose-900/50 border border-rose-700 text-rose-200 text-xs">
                {createError}
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Token Label / Purpose:
              </label>
              <input
                type="text"
                required
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="e.g. gateway in lab 2"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-teal-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Expires in Minutes (default 15):
              </label>
              <div className="flex items-center gap-3">
                <input
                  type="number"
                  min="1"
                  max="1440"
                  value={expiresMinutes}
                  onChange={(e) => setExpiresMinutes(Number(e.target.value))}
                  className="w-28 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-teal-500"
                />
                <span className="text-xs text-slate-400">
                  Valid until: {new Date(Date.now() + expiresMinutes * 60000).toLocaleTimeString()}
                </span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsCreateOpen(false)}
                className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting || !label.trim()}
                className="px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors"
              >
                {isSubmitting ? 'Generating...' : 'Generate Secret'}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* ONE-TIME TOKEN REVEAL MODAL */}
      {revealedToken && (
        <Modal
          isOpen={!!revealedToken}
          onClose={() => setRevealedToken(null)}
          title="Save One-Time Enrollment Token"
        >
          <div className="space-y-4">
            <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/80 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div className="text-xs text-amber-200">
                <span className="font-bold text-amber-300 block mb-1">
                  Copy and deliver to edge node now!
                </span>
                <p>
                  This token is shown <strong>exactly once</strong> in memory and cannot be recovered
                  once this modal is dismissed. The server only stores its SHA-256 hash.
                </p>
              </div>
            </div>

            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between gap-2">
              <code className="text-xs font-mono text-teal-300 break-all select-all">
                {revealedToken}
              </code>
              <button
                onClick={() => copyToClipboard(revealedToken)}
                className="px-3 py-1.5 bg-teal-600 hover:bg-teal-500 text-white rounded text-xs font-medium shrink-0 flex items-center gap-1.5 transition-colors"
              >
                {hasCopied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-white" />
                    <span>Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Token</span>
                  </>
                )}
              </button>
            </div>

            <div className="text-[11px] text-slate-400 font-mono">
              CLI command to enroll node:
              <pre className="mt-1 p-2 bg-slate-950 border border-slate-800 rounded text-slate-300 overflow-x-auto">
                FOGTRUST_ENROLL_TOKEN={revealedToken} python -m fogtrust_crypto.node_sim enroll ...
              </pre>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setRevealedToken(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium"
              >
                I have securely saved the token
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

