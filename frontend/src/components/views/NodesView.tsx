import React, { useEffect, useMemo, useState } from 'react';
import {
  Server,
  Search,
  Filter,
  ShieldAlert,
  AlertTriangle,
  Copy,
  Check,
  Clock,
  RotateCcw,
  Activity,
  TrendingUp,
  ArrowUpRight,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getNodes, revokeNode } from '../../services/api';
import { NodeDisplayStatus, NodeItem } from '../../types/api';
import { Badge } from '../common/Badge';
import { TrustScoreBadge } from '../common/TrustScoreBadge';
import { TrustScoreBar } from '../common/TrustScoreBar';
import { Modal } from '../common/Modal';
import { EmptyState, ErrorState, LoadingState } from '../common/ViewState';
import { formatDateTime, formatRelativeTime, getNodeDisplayStatus } from '../../utils/nodeStatus';

interface NodesViewProps {
  onNavigate?: (tab: string, nodeId?: string) => void;
}

export const NodesView: React.FC<NodesViewProps> = ({ onNavigate }) => {
  const { isDemoMode, role, hasPermission, currentUser } = useAuth();
  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [search, setSearch] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<NodeDisplayStatus | ''>('');
  const [minTrust, setMinTrust] = useState<number>(0);

  // Selected node for detail modal
  const [selectedNode, setSelectedNode] = useState<NodeItem | null>(null);

  // Revocation modal state
  const [nodeToRevoke, setNodeToRevoke] = useState<NodeItem | null>(null);
  const [confirmName, setConfirmName] = useState<string>('');
  const [revokeReason, setRevokeReason] = useState<string>('');
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [isRevoking, setIsRevoking] = useState<boolean>(false);
  const [copiedFingerprint, setCopiedFingerprint] = useState<string | null>(null);

  const fetchNodeList = async () => {
    setIsLoading(true);
    setLoadError(null);
    try {
      // The API only knows active/revoked. "enrolled" is derived from
      // last_seen_at, so fetch the fleet and filter the display status locally.
      const res = await getNodes(
        {
          search: search || undefined,
          min_trust: minTrust > 0 ? minTrust : undefined,
        },
        isDemoMode
      );
      setNodes(res.results || []);
    } catch (err: unknown) {
      setNodes([]);
      setLoadError(err instanceof Error ? err.message : 'Could not load the edge node fleet.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchNodeList();
  }, [isDemoMode, minTrust]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchNodeList();
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFingerprint(text);
    setTimeout(() => setCopiedFingerprint(null), 2000);
  };

  const handleRevokeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!nodeToRevoke) return;

    if (confirmName !== nodeToRevoke.name) {
      setRevokeError(`Confirmation name does not match exact node name "${nodeToRevoke.name}".`);
      return;
    }

    if (revokeReason.trim().length < 10) {
      setRevokeError('Revocation reason must be at least 10 characters long.');
      return;
    }

    setIsRevoking(true);
    setRevokeError(null);

    try {
      if (isDemoMode) {
        setNodes((prev) =>
          prev.map((n) =>
            n.id === nodeToRevoke.id
              ? {
                  ...n,
                  status: 'revoked',
                  revoked_at: new Date().toISOString(),
                  revoke_reason: revokeReason,
                  revoked_by: currentUser?.username || `${role}1`,
                  revoke_source: 'manual',
                  current_load: 0,
                }
              : n
          )
        );
      } else {
        await revokeNode(nodeToRevoke.id, confirmName, revokeReason);
        await fetchNodeList();
      }

      setNodeToRevoke(null);
      setConfirmName('');
      setRevokeReason('');
    } catch (err: unknown) {
      setRevokeError(err instanceof Error ? err.message : 'Revocation request was rejected by server.');
    } finally {
      setIsRevoking(false);
    }
  };

  const canRevoke = role === 'admin' || hasPermission('nodes.revoke');

  const counts = useMemo(() => {
    const byStatus: Record<NodeDisplayStatus, number> = { enrolled: 0, active: 0, revoked: 0 };
    for (const node of nodes) {
      byStatus[getNodeDisplayStatus(node)] += 1;
    }
    return { ...byStatus, total: nodes.length };
  }, [nodes]);

  const visibleNodes = useMemo(
    () =>
      nodes.filter((node) => !statusFilter || getNodeDisplayStatus(node) === statusFilter),
    [nodes, statusFilter]
  );

  const summaryCards: Array<{
    key: NodeDisplayStatus | 'total';
    label: string;
    value: number;
    icon: React.ReactNode;
    tone: string;
  }> = [
    { key: 'total', label: 'Fleet total', value: counts.total, icon: <Server className="w-4 h-4" />, tone: 'text-slate-200' },
    { key: 'active', label: 'Active', value: counts.active, icon: <Activity className="w-4 h-4" />, tone: 'text-emerald-400' },
    { key: 'enrolled', label: 'Enrolled · awaiting heartbeat', value: counts.enrolled, icon: <Clock className="w-4 h-4" />, tone: 'text-sky-400' },
    { key: 'revoked', label: 'Revoked', value: counts.revoked, icon: <ShieldAlert className="w-4 h-4" />, tone: 'text-rose-400' },
  ];

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Server className="w-5 h-5 text-teal-400" />
            Edge Node Fleet Management
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Cryptographically enrolled fog nodes, live health, trust score, and server-enforced permanent revocation.
          </p>
        </div>

        <button
          onClick={fetchNodeList}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium disabled:opacity-50"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Fleet</span>
        </button>
      </div>

      {/* Fleet status summary */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {summaryCards.map((card) => (
          <button
            key={card.key}
            onClick={() => {
              if (card.key !== 'total') {
                setStatusFilter(statusFilter === card.key ? '' : card.key);
              } else {
                setStatusFilter('');
              }
            }}
            className={`text-left p-4 rounded-xl bg-slate-900/60 border transition-colors ${
              statusFilter === card.key
                ? 'border-teal-500/60 ring-1 ring-teal-500/20'
                : 'border-slate-800 hover:border-slate-700'
            }`}
            title={card.key === 'total' ? 'Show all nodes' : `Filter by ${card.label}`}
          >
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[11px] font-mono uppercase">{card.label}</span>
              <span className={card.tone}>{card.icon}</span>
            </div>
            <div className={`mt-2 text-2xl font-bold font-mono ${card.tone}`}>{card.value}</div>
          </button>
        ))}
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 flex-1 max-w-md">
          <div className="relative w-full">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by node name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-teal-500"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg font-medium border border-slate-700"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as NodeDisplayStatus | '')}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-teal-500"
            >
              <option value="">All Statuses</option>
              <option value="enrolled">Enrolled (no heartbeat)</option>
              <option value="active">Active (heartbeat seen)</option>
              <option value="revoked">Revoked</option>
            </select>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>Min Trust:</span>
            <input
              type="range"
              min="0"
              max="100"
              step="5"
              value={minTrust}
              onChange={(e) => setMinTrust(Number(e.target.value))}
              className="w-24 accent-teal-500 cursor-pointer"
            />
            <span className="font-mono text-teal-400 font-bold">{minTrust}</span>
          </div>

          <button
            onClick={() => {
              setSearch('');
              setStatusFilter('');
              setMinTrust(0);
            }}
            className="text-[11px] text-slate-400 hover:text-slate-200 underline"
          >
            Clear filters
          </button>
        </div>
      </div>

      {/* Nodes table / states */}
      {loadError ? (
        <ErrorState
          title="Could not load edge nodes"
          message={loadError}
          onRetry={fetchNodeList}
        />
      ) : isLoading ? (
        <LoadingState label="Loading edge node fleet…" />
      ) : visibleNodes.length === 0 ? (
        <EmptyState
          title="No edge nodes match your filters"
          description={
            nodes.length === 0
              ? 'No node has enrolled yet. Create an enrollment token to register the first edge node.'
              : 'Try clearing the status, trust, or search filters.'
          }
          icon={<Server className="w-5 h-5" />}
        />
      ) : (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                <tr>
                  <th className="py-3 px-4">Node Name</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Trust Score</th>
                  <th className="py-3 px-4">Load / Capacity</th>
                  <th className="py-3 px-4">Last Heartbeat</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {visibleNodes.map((node) => {
                  const displayStatus = getNodeDisplayStatus(node);
                  return (
                    <tr
                      key={node.id}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                      onClick={() => setSelectedNode(node)}
                    >
                      <td className="py-3.5 px-4 font-medium text-slate-100">
                        <div className="flex items-center gap-2">
                          <span>{node.name}</span>
                          {node.revoke_source === 'automatic' && (
                            <span
                              className="text-[10px] text-rose-400 border border-rose-900 bg-rose-950/60 px-1 rounded font-mono"
                              title="Revoked automatically by the Trust Engine"
                            >
                              auto-revoked
                            </span>
                          )}
                        </div>
                        <span className="block text-[10px] font-mono text-slate-500 mt-0.5">
                          {node.id.slice(0, 18)}…
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge label={displayStatus} />
                      </td>
                      <td className="py-3.5 px-4">
                        <TrustScoreBadge score={node.trust_score} />
                      </td>
                      <td className="py-3.5 px-4 font-mono">
                        <span className="text-slate-100 font-semibold">{node.current_load}</span>
                        <span className="text-slate-500"> / {node.capacity}</span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                        {node.last_seen_at ? (
                          <span title={formatDateTime(node.last_seen_at)}>
                            {formatRelativeTime(node.last_seen_at)}
                          </span>
                        ) : (
                          <span className="text-sky-400" title="Enrolled but no heartbeat received yet">
                            Awaiting first heartbeat
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => onNavigate?.('trust', node.id)}
                            className="px-2.5 py-1 rounded border border-slate-700 text-teal-300 hover:bg-slate-800 text-xs font-medium transition-colors"
                            title="Open trust score history and rule reasons"
                          >
                            Trust detail
                          </button>
                          {node.status === 'active' && canRevoke ? (
                            <button
                              onClick={() => {
                                setNodeToRevoke(node);
                                setConfirmName('');
                                setRevokeReason('');
                                setRevokeError(null);
                              }}
                              className="px-2.5 py-1 rounded border border-rose-800/80 text-rose-400 hover:bg-rose-950/80 text-xs font-medium transition-colors"
                            >
                              Revoke
                            </button>
                          ) : node.status === 'revoked' ? (
                            <span className="text-[11px] text-slate-500 font-mono">Permanent</span>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Node Detail Modal */}
      {selectedNode && (
        <Modal
          isOpen={!!selectedNode}
          onClose={() => setSelectedNode(null)}
          title={`Node Details: ${selectedNode.name}`}
          maxWidth="xl"
        >
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-4 p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Node UUID</span>
                <span className="text-slate-200 select-all break-all">{selectedNode.id}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Status</span>
                <Badge label={getNodeDisplayStatus(selectedNode)} />
                {getNodeDisplayStatus(selectedNode) === 'enrolled' && (
                  <p className="text-[10px] text-sky-400 mt-1 font-sans">
                    Enrolled successfully, but no heartbeat has been accepted yet.
                  </p>
                )}
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Capacity & Load</span>
                <span className="text-slate-200">
                  {selectedNode.current_load} in-flight / {selectedNode.capacity} max tasks
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Trust Score</span>
                <TrustScoreBar score={selectedNode.trust_score} />
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="flex items-center justify-between mb-1">
                <span className="text-slate-500 text-[10px] uppercase font-mono">
                  Ed25519 Public Key Fingerprint (SHA-256)
                </span>
                <button
                  onClick={() => handleCopy(selectedNode.key_fingerprint)}
                  className="flex items-center gap-1 text-[11px] text-teal-400 hover:text-teal-300 font-mono"
                >
                  {copiedFingerprint === selectedNode.key_fingerprint ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
              <p className="font-mono text-[11px] text-slate-300 break-all select-all">
                {selectedNode.key_fingerprint}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 text-slate-400 font-mono text-[11px]">
              <div>
                <span className="text-slate-500 block text-[10px]">ENROLLED AT</span>
                {formatDateTime(selectedNode.enrolled_at)}
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">LAST HEARTBEAT</span>
                {selectedNode.last_seen_at
                  ? `${formatRelativeTime(selectedNode.last_seen_at)} · ${formatDateTime(selectedNode.last_seen_at)}`
                  : 'Never'}
              </div>
            </div>

            {selectedNode.status === 'revoked' && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/60 space-y-1">
                <div className="flex items-center gap-1.5 text-rose-400 font-semibold text-xs">
                  <ShieldAlert className="w-4 h-4" />
                  <span>Permanent Revocation Record</span>
                </div>
                <p className="text-xs text-rose-200">
                  <strong>Reason:</strong> {selectedNode.revoke_reason || 'No reason specified'}
                </p>
                <div className="text-[10px] text-rose-300/80 font-mono flex flex-wrap items-center gap-3 pt-1">
                  <span>Source: {selectedNode.revoke_source || 'manual'}</span>
                  <span>Revoked by: {selectedNode.revoked_by || 'admin'}</span>
                  {selectedNode.revoked_at && <span>Date: {formatDateTime(selectedNode.revoked_at)}</span>}
                </div>
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => {
                  const nodeId = selectedNode.id;
                  setSelectedNode(null);
                  onNavigate?.('trust', nodeId);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium"
              >
                <ArrowUpRight className="w-3.5 h-3.5" />
                <span>View trust history & reasons</span>
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Revocation Confirmation Modal */}
      {nodeToRevoke && (
        <Modal
          isOpen={!!nodeToRevoke}
          onClose={() => setNodeToRevoke(null)}
          title={`Revoke Edge Node: ${nodeToRevoke.name}`}
          maxWidth="lg"
        >
          <form onSubmit={handleRevokeSubmit} className="space-y-4">
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/80 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
              <div className="text-xs text-rose-200 space-y-1">
                <span className="font-bold text-rose-300 block">Warning: Revocation is Permanent!</span>
                <p>
                  Once revoked, the broker immediately rejects all future signed heartbeats
                  (<code className="font-mono text-rose-300">NODE_REVOKED</code>), in-flight tasks
                  are reassigned, and this key pair cannot be re-enrolled.
                </p>
              </div>
            </div>

            {revokeError && (
              <div className="p-2.5 rounded bg-rose-900/50 border border-rose-700 text-rose-200 text-xs">
                {revokeError}
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Type exact node name to confirm (
                <span className="font-mono text-teal-400">{nodeToRevoke.name}</span>):
              </label>
              <input
                type="text"
                required
                value={confirmName}
                onChange={(e) => setConfirmName(e.target.value)}
                placeholder={nodeToRevoke.name}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-rose-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Revocation Reason (minimum 10 characters, audited):
              </label>
              <textarea
                required
                rows={3}
                value={revokeReason}
                onChange={(e) => setRevokeReason(e.target.value)}
                placeholder="e.g. 3 consecutive integrity failures in 10 minutes (T4 attack simulation)"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-rose-500"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Length: {revokeReason.length}/10 characters minimum
              </span>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setNodeToRevoke(null)}
                className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isRevoking || confirmName !== nodeToRevoke.name || revokeReason.length < 10}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-medium transition-colors shadow-sm flex items-center gap-1.5"
              >
                <ShieldAlert className="w-4 h-4" />
                <span>{isRevoking ? 'Revoking Node...' : 'Confirm Revocation'}</span>
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};
