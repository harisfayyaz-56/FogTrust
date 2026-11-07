import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ArrowLeft,
  ArrowUpRight,
  CheckCircle2,
  Info,
  Minus,
  RotateCcw,
  Sliders,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getNodes, getNodeTrustHistory } from '../../services/api';
import { NodeItem, TrustRuleFired, TrustScoreRecord } from '../../types/api';
import { Badge } from '../common/Badge';
import { Modal } from '../common/Modal';
import { TrustScoreBadge } from '../common/TrustScoreBadge';
import { EmptyState, ErrorState, LoadingState } from '../common/ViewState';
import { formatDateTime, formatRelativeTime, getNodeDisplayStatus } from '../../utils/nodeStatus';

interface TrustViewProps {
  initialNodeId?: string;
  onNavigate?: (tab: string, nodeId?: string) => void;
}

interface ChartPoint {
  score: number;
  computed_at: string;
}

const TrustHistoryChart: React.FC<{ points: ChartPoint[]; threshold: number }> = ({
  points,
  threshold,
}) => {
  const width = 760;
  const height = 210;
  const paddingX = 34;
  const paddingY = 24;
  const innerWidth = width - paddingX * 2;
  const innerHeight = height - paddingY * 2;

  if (points.length === 0) return null;

  const xAt = (index: number) =>
    paddingX + (points.length === 1 ? innerWidth / 2 : (index / (points.length - 1)) * innerWidth);
  const yAt = (score: number) => paddingY + innerHeight - (Math.max(0, Math.min(100, score)) / 100) * innerHeight;

  const line = points.map((point, index) => `${xAt(index)},${yAt(point.score)}`).join(' ');
  const area = `${paddingX},${paddingY + innerHeight} ${line} ${paddingX + innerWidth},${paddingY + innerHeight}`;
  const thresholdY = yAt(threshold);

  return (
    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-mono uppercase text-slate-400">Score trajectory</span>
        <span className="text-[11px] font-mono text-slate-500">
          {points.length} snapshot{points.length === 1 ? '' : 's'} · threshold {threshold}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-[210px]"
        role="img"
        aria-label="Trust score history chart"
      >
        <defs>
          <linearGradient id="trustArea" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#14b8a6" stopOpacity="0.35" />
            <stop offset="100%" stopColor="#14b8a6" stopOpacity="0" />
          </linearGradient>
        </defs>

        {[0, 25, 50, 75, 100].map((value) => (
          <g key={value}>
            <line
              x1={paddingX}
              x2={paddingX + innerWidth}
              y1={yAt(value)}
              y2={yAt(value)}
              stroke="#1e293b"
              strokeWidth="1"
            />
            <text x={4} y={yAt(value) + 3} fill="#64748b" fontSize="9" fontFamily="monospace">
              {value}
            </text>
          </g>
        ))}

        <line
          x1={paddingX}
          x2={paddingX + innerWidth}
          y1={thresholdY}
          y2={thresholdY}
          stroke="#f59e0b"
          strokeDasharray="5 5"
          strokeWidth="1.5"
        />
        <text x={paddingX + innerWidth - 74} y={thresholdY - 5} fill="#f59e0b" fontSize="9" fontFamily="monospace">
          threshold {threshold}
        </text>

        {points.length > 1 && <polygon points={area} fill="url(#trustArea)" />}
        <polyline points={line} fill="none" stroke="#2dd4bf" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />

        {points.map((point, index) => (
          <g key={`${point.computed_at}-${index}`}>
            <circle cx={xAt(index)} cy={yAt(point.score)} r="4" fill="#0f172a" stroke="#2dd4bf" strokeWidth="2" />
            <title>
              {point.score}/100 · {formatDateTime(point.computed_at)}
            </title>
          </g>
        ))}
      </svg>
      <div className="flex justify-between text-[10px] font-mono text-slate-500 mt-1">
        <span>{formatDateTime(points[0]?.computed_at)}</span>
        <span>{formatDateTime(points[points.length - 1]?.computed_at)}</span>
      </div>
    </div>
  );
};

const RuleTable: React.FC<{ rules: TrustRuleFired[] }> = ({ rules }) => {
  if (rules.length === 0) {
    return (
      <p className="text-xs text-slate-500 p-3 rounded-lg bg-slate-950 border border-slate-800">
        No rule fired for this snapshot — the score was carried forward or assigned at enrollment.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="w-full text-left text-xs">
        <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px]">
          <tr>
            <th className="py-2 px-3">Rule fired</th>
            <th className="py-2 px-3">Weight</th>
            <th className="py-2 px-3">Value</th>
            <th className="py-2 px-3">Contribution</th>
            <th className="py-2 px-3">Why</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {rules.map((rule, index) => (
            <tr key={`${rule.rule}-${index}`} className="text-slate-300">
              <td className="py-2 px-3 font-mono text-slate-200">{rule.rule}</td>
              <td className="py-2 px-3 font-mono">{rule.weight > 0 ? `+${rule.weight}` : rule.weight}</td>
              <td className="py-2 px-3 font-mono">{rule.value}</td>
              <td
                className={`py-2 px-3 font-mono font-bold ${
                  rule.contribution > 0
                    ? 'text-emerald-400'
                    : rule.contribution < 0
                    ? 'text-rose-400'
                    : 'text-slate-400'
                }`}
              >
                {rule.contribution > 0 ? `+${rule.contribution}` : rule.contribution}
              </td>
              <td className="py-2 px-3 text-slate-400">{rule.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export const TrustView: React.FC<TrustViewProps> = ({ initialNodeId, onNavigate }) => {
  const { isDemoMode } = useAuth();
  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string>(initialNodeId || '');
  const [history, setHistory] = useState<TrustScoreRecord[]>([]);
  const [isLoadingNodes, setIsLoadingNodes] = useState<boolean>(true);
  const [isLoadingHistory, setIsLoadingHistory] = useState<boolean>(false);
  const [nodesError, setNodesError] = useState<string | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<TrustScoreRecord | null>(null);
  const [refreshKey, setRefreshKey] = useState<number>(0);

  useEffect(() => {
    if (initialNodeId) setSelectedNodeId(initialNodeId);
  }, [initialNodeId]);

  useEffect(() => {
    let mounted = true;
    setIsLoadingNodes(true);
    setNodesError(null);

    getNodes({}, isDemoMode)
      .then((res) => {
        if (!mounted) return;
        const list = res.results || [];
        setNodes(list);
        setSelectedNodeId((prev) => prev || list[0]?.id || '');
      })
      .catch((err: unknown) => {
        if (!mounted) return;
        setNodesError(err instanceof Error ? err.message : 'Could not load the node fleet.');
      })
      .finally(() => {
        if (mounted) setIsLoadingNodes(false);
      });

    return () => {
      mounted = false;
    };
  }, [isDemoMode, refreshKey]);

  useEffect(() => {
    if (!selectedNodeId) {
      setHistory([]);
      return;
    }

    let mounted = true;
    setIsLoadingHistory(true);
    setHistoryError(null);

    getNodeTrustHistory(selectedNodeId, isDemoMode)
      .then((records) => {
        if (mounted) setHistory(records || []);
      })
      .catch((err: unknown) => {
        if (!mounted) return;
        setHistory([]);
        setHistoryError(err instanceof Error ? err.message : 'Could not load trust history.');
      })
      .finally(() => {
        if (mounted) setIsLoadingHistory(false);
      });

    return () => {
      mounted = false;
    };
  }, [selectedNodeId, isDemoMode, refreshKey]);

  const selectedNode = nodes.find((node) => node.id === selectedNodeId) || null;
  const latest = history[0] || null;
  const chronological = useMemo(() => [...history].reverse(), [history]);
  const delta = latest ? latest.score - latest.previous_score : 0;

  const refresh = () => setRefreshKey((key) => key + 1);

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-teal-400" />
            Trust Score Detail
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Score history with the exact rule, weight, contribution, and plain-language reason for every change.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onNavigate?.('nodes')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Fleet</span>
          </button>
          <button
            onClick={refresh}
            disabled={isLoadingNodes || isLoadingHistory}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium disabled:opacity-50"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isLoadingHistory ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {nodesError ? (
        <ErrorState title="Could not load nodes" message={nodesError} onRetry={refresh} />
      ) : isLoadingNodes ? (
        <LoadingState label="Loading node fleet…" />
      ) : nodes.length === 0 ? (
        <EmptyState
          title="No nodes to score"
          description="Enroll an edge node first; its trust history will appear here after enrollment."
          icon={<Activity className="w-5 h-5" />}
        />
      ) : (
        <>
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-3 text-xs">
              <Sliders className="w-4 h-4 text-teal-400" />
              <label htmlFor="trust-node-select" className="text-slate-400">
                Node:
              </label>
              <select
                id="trust-node-select"
                value={selectedNodeId}
                onChange={(e) => setSelectedNodeId(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-teal-500 min-w-[220px]"
              >
                {nodes.map((node) => (
                  <option key={node.id} value={node.id}>
                    {node.name} · {getNodeDisplayStatus(node)} · {node.trust_score}/100
                  </option>
                ))}
              </select>
              {selectedNode && (
                <>
                  <Badge label={getNodeDisplayStatus(selectedNode)} />
                  <span className="text-[11px] font-mono text-slate-500">
                    Last heartbeat: {formatRelativeTime(selectedNode.last_seen_at)}
                  </span>
                </>
              )}
            </div>

            {selectedNode && (
              <button
                onClick={() => onNavigate?.('nodes', selectedNode.id)}
                className="flex items-center gap-1.5 text-xs text-teal-400 hover:text-teal-300 font-medium"
              >
                Node details <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {historyError ? (
            <ErrorState title="Could not load trust history" message={historyError} onRetry={refresh} />
          ) : isLoadingHistory ? (
            <LoadingState label="Loading trust score history…" />
          ) : history.length === 0 ? (
            <EmptyState
              title="No trust history yet"
              description="This node has not had a trust evaluation recorded. The initial score is assigned at enrollment."
              icon={<Activity className="w-5 h-5" />}
            />
          ) : (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                  <span className="text-[11px] font-mono uppercase text-slate-400">Current score</span>
                  <div className="mt-2 flex items-center gap-3">
                    <span className="text-2xl font-bold font-mono text-slate-100">
                      {latest?.score ?? selectedNode?.trust_score ?? 0}
                      <span className="text-sm text-slate-500">/100</span>
                    </span>
                    {latest && (
                      <Badge
                        label={latest.score >= 70 ? 'eligible' : 'below threshold'}
                        variant={latest.score >= 70 ? 'green' : 'red'}
                      />
                    )}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                  <span className="text-[11px] font-mono uppercase text-slate-400">Last change</span>
                  <div
                    className={`mt-2 flex items-center gap-2 text-2xl font-bold font-mono ${
                      delta > 0 ? 'text-emerald-400' : delta < 0 ? 'text-rose-400' : 'text-slate-300'
                    }`}
                  >
                    {delta > 0 ? (
                      <TrendingUp className="w-5 h-5" />
                    ) : delta < 0 ? (
                      <TrendingDown className="w-5 h-5" />
                    ) : (
                      <Minus className="w-5 h-5" />
                    )}
                    <span>{delta > 0 ? `+${delta}` : delta}</span>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-1 font-mono">
                    {latest ? `${latest.previous_score} → ${latest.score}` : '—'}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                  <span className="text-[11px] font-mono uppercase text-slate-400">Evaluations</span>
                  <div className="mt-2 text-2xl font-bold font-mono text-slate-100">{history.length}</div>
                  <p className="text-[11px] text-slate-500 mt-1 font-mono">
                    Latest {latest ? formatRelativeTime(latest.computed_at) : '—'}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                  <span className="text-[11px] font-mono uppercase text-slate-400">Policy version</span>
                  <div className="mt-2 text-2xl font-bold font-mono text-slate-100">
                    v{latest?.policy_version ?? '—'}
                  </div>
                  <p className="text-[11px] text-slate-500 mt-1 font-mono">
                    {latest ? formatDateTime(latest.computed_at) : '—'}
                  </p>
                </div>
              </div>

              <TrustHistoryChart points={chronological} threshold={70} />

              <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                    <Info className="w-4 h-4 text-teal-400" />
                    Latest evaluation reasons
                  </h2>
                  {latest && <TrustScoreBadge score={latest.score} />}
                </div>
                {latest ? (
                  <>
                    <p className="text-xs text-slate-300 p-3 rounded-lg bg-slate-950 border border-slate-800">
                      {latest.explanation || 'No explanation text supplied for this evaluation.'}
                    </p>
                    <RuleTable rules={latest.rules_fired} />
                  </>
                ) : null}
              </div>

              <div className="rounded-xl bg-slate-900/60 border border-slate-800 overflow-hidden">
                <div className="px-5 py-3 border-b border-slate-800">
                  <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                    Score history ({history.length})
                  </h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px]">
                      <tr>
                        <th className="py-2.5 px-4">Computed at</th>
                        <th className="py-2.5 px-4">Score</th>
                        <th className="py-2.5 px-4">Previous</th>
                        <th className="py-2.5 px-4">Delta</th>
                        <th className="py-2.5 px-4">Rules fired</th>
                        <th className="py-2.5 px-4">Policy</th>
                        <th className="py-2.5 px-4 text-right">Reasons</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {history.map((record) => {
                        const recordDelta = record.score - record.previous_score;
                        return (
                          <tr
                            key={record.id}
                            className="text-slate-300 hover:bg-slate-800/40 transition-colors cursor-pointer"
                            onClick={() => setSelectedRecord(record)}
                          >
                            <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                              <span title={formatDateTime(record.computed_at)}>
                                {formatRelativeTime(record.computed_at)}
                              </span>
                            </td>
                            <td className="py-3 px-4 font-mono font-bold text-slate-100">{record.score}</td>
                            <td className="py-3 px-4 font-mono text-slate-400">{record.previous_score}</td>
                            <td
                              className={`py-3 px-4 font-mono font-bold ${
                                recordDelta > 0
                                  ? 'text-emerald-400'
                                  : recordDelta < 0
                                  ? 'text-rose-400'
                                  : 'text-slate-400'
                              }`}
                            >
                              {recordDelta > 0 ? `+${recordDelta}` : recordDelta}
                            </td>
                            <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                              {record.rules_fired.length}
                            </td>
                            <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                              v{record.policy_version}
                            </td>
                            <td className="py-3 px-4 text-right">
                              <span className="inline-flex items-center gap-1 text-teal-400 text-[11px] font-mono">
                                Inspect <ArrowUpRight className="w-3 h-3" />
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </>
      )}

      {selectedRecord && (
        <Modal
          isOpen={!!selectedRecord}
          onClose={() => setSelectedRecord(null)}
          title={`Trust evaluation #${selectedRecord.id}`}
          maxWidth="2xl"
        >
          <div className="space-y-4 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono">
              <div className="flex items-center gap-3">
                <TrustScoreBadge score={selectedRecord.score} size="md" />
                <span className="text-slate-400">
                  {selectedRecord.previous_score} → {selectedRecord.score}
                </span>
              </div>
              <span className="text-slate-500">{formatDateTime(selectedRecord.computed_at)}</span>
            </div>

            <p className="text-slate-300 p-3 rounded-lg bg-slate-950 border border-slate-800">
              {selectedRecord.explanation || 'No explanation text supplied for this evaluation.'}
            </p>

            <div>
              <span className="text-slate-400 text-[11px] font-mono uppercase block mb-2">
                Rules fired ({selectedRecord.rules_fired.length})
              </span>
              <RuleTable rules={selectedRecord.rules_fired} />
            </div>

            <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-800">
              <CheckCircle2 className="w-3.5 h-3.5 text-teal-400" />
              <span>Policy version v{selectedRecord.policy_version}</span>
              <span>·</span>
              <span>Node: {selectedRecord.node_name}</span>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
