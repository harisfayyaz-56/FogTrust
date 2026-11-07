import React, { useEffect, useState } from 'react';
import {
  FileCheck2,
  Filter,
  Search,
  CheckCircle2,
  XCircle,
  Clock,
  Cpu,
  Layers,
  RotateCcw,
  ShieldAlert,
  ArrowRight,
  ExternalLink,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getDecisions } from '../../services/api';
import { Decision, RuleFired } from '../../types/api';
import { Badge } from '../common/Badge';
import { Modal } from '../common/Modal';

export const EvidenceView: React.FC = () => {
  const { isDemoMode } = useAuth();
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Filters
  const [subjectFilter, setSubjectFilter] = useState<string>('');
  const [decisionFilter, setDecisionFilter] = useState<string>('');
  const [reasonCodeFilter, setReasonCodeFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected decision for detailed examination
  const [selectedDecision, setSelectedDecision] = useState<Decision | null>(null);

  const fetchDecisions = async () => {
    setIsLoading(true);
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
    } catch (err) {
      console.error('Failed to load decisions:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDecisions();
  }, [isDemoMode, subjectFilter, decisionFilter, reasonCodeFilter]);

  // Quick preset test scenario filter (T1 - T5)
  const setQuickScenario = (code: string) => {
    if (reasonCodeFilter === code) {
      setReasonCodeFilter('');
    } else {
      setReasonCodeFilter(code);
    }
  };

  const filteredDecisions = decisions.filter((d) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      d.explanation.toLowerCase().includes(q) ||
      d.reason_code.toLowerCase().includes(q) ||
      d.subject_id.toLowerCase().includes(q) ||
      d.decision_id.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-teal-400" />
            Explainable Security Decisions & Evidence (FR-7)
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Every authorization, scheduling, or revocation decision provides full rule evaluations and non-secret audit evidence.
          </p>
        </div>

        <button
          onClick={fetchDecisions}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Refresh Evidence</span>
        </button>
      </div>

      {/* Quick Test Scenario Preset Chips (For easy testing & university demo!) */}
      <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center gap-2 text-xs">
        <span className="text-slate-400 font-mono text-[11px] uppercase mr-1">Demo Scenarios:</span>
        <button
          onClick={() => setQuickScenario('OK')}
          className={`px-2.5 py-1 rounded-md border text-xs font-mono transition-colors ${
            reasonCodeFilter === 'OK'
              ? 'bg-emerald-950 border-emerald-700 text-emerald-300'
              : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          Normal Operation (OK)
        </button>
        <button
          onClick={() => setQuickScenario('HEARTBEAT_REPLAYED')}
          className={`px-2.5 py-1 rounded-md border text-xs font-mono transition-colors ${
            reasonCodeFilter === 'HEARTBEAT_REPLAYED'
              ? 'bg-rose-950 border-rose-700 text-rose-300'
              : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          T2 Replayed Nonce
        </button>
        <button
          onClick={() => setQuickScenario('RESULT_INTEGRITY_FAILED')}
          className={`px-2.5 py-1 rounded-md border text-xs font-mono transition-colors ${
            reasonCodeFilter === 'RESULT_INTEGRITY_FAILED'
              ? 'bg-rose-950 border-rose-700 text-rose-300'
              : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          T4 Ciphertext Tampering
        </button>
        <button
          onClick={() => setQuickScenario('CONFIRMED_REVOCATION')}
          className={`px-2.5 py-1 rounded-md border text-xs font-mono transition-colors ${
            reasonCodeFilter === 'CONFIRMED_REVOCATION'
              ? 'bg-amber-950 border-amber-700 text-amber-300'
              : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          T5 Revocation Evidence
        </button>
        {reasonCodeFilter && (
          <button
            onClick={() => setReasonCodeFilter('')}
            className="text-[11px] text-teal-400 hover:underline ml-2"
          >
            Clear scenario filter
          </button>
        )}
      </div>

      {/* Advanced Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        {/* Search */}
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
          {/* Subject Type Filter */}
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

          {/* Decision Outcome Filter */}
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

      {/* Decisions Evidence Table */}
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
              {filteredDecisions.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    {isLoading ? 'Loading security decisions...' : 'No decision records found.'}
                  </td>
                </tr>
              ) : (
                filteredDecisions.map((d) => (
                  <tr
                    key={d.decision_id}
                    onClick={() => setSelectedDecision(d)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4">
                      <Badge label={d.decision} />
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] uppercase text-slate-300">
                      {d.subject_type}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                      {d.reason_code}
                    </td>
                    <td className="py-3.5 px-4 max-w-md font-sans text-slate-200">
                      {/* RENDER SERVER TEXT AS SAFE PLAIN TEXT */}
                      <span className="line-clamp-2">{d.explanation}</span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                      <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                        {d.rules_fired.filter((r) => r.passed).length}/{d.rules_fired.length} passed
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                      {d.latency_ms.toFixed(2)} ms
                    </td>
                    <td className="py-3.5 px-4 text-right text-teal-400 group-hover:text-teal-300">
                      <span className="text-xs font-mono flex items-center justify-end gap-1">
                        Inspect <ArrowRight className="w-3 h-3" />
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Decision Deep-Dive Inspector Modal */}
      {selectedDecision && (
        <Modal
          isOpen={!!selectedDecision}
          onClose={() => setSelectedDecision(null)}
          title={`Security Decision Evidence: ${selectedDecision.decision.toUpperCase()}`}
          maxWidth="2xl"
        >
          <div className="space-y-5 text-xs">
            {/* Top overview row */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-4 font-mono">
              <div className="flex items-center gap-3">
                <Badge label={selectedDecision.decision} size="md" />
                <span className="text-slate-400 uppercase text-xs">
                  {selectedDecision.subject_type}
                </span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-300">{selectedDecision.reason_code}</span>
              </div>
              <div className="text-slate-400 text-[11px]">
                Engine Latency: <strong className="text-teal-400">{selectedDecision.latency_ms.toFixed(2)} ms</strong>
              </div>
            </div>

            {/* Plain text explanation */}
            <div className="p-3.5 rounded-lg bg-slate-850/70 border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block mb-1">
                Plain-Text Human Explanation (Safe for Display)
              </span>
              <p className="text-sm font-sans text-slate-100 leading-relaxed">
                {selectedDecision.explanation}
              </p>
            </div>

            {/* Rules evaluated checklist */}
            <div>
              <span className="text-slate-400 text-xs font-mono uppercase tracking-wider block mb-2">
                Rules Evaluated by Security Engine ({selectedDecision.rules_fired.length})
              </span>
              <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
                {selectedDecision.rules_fired.map((r, idx) => (
                  <div key={idx} className="p-2.5 flex items-start gap-3">
                    {r.passed ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-medium text-slate-200">{r.rule}</span>
                        <span
                          className={`text-[10px] font-mono uppercase ${
                            r.passed ? 'text-emerald-400' : 'text-rose-400'
                          }`}
                        >
                          {r.passed ? 'PASSED' : 'VIOLATION / FAILED'}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5 font-sans">{r.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Non-secret Evidence Details */}
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

            {/* Metadata Footer */}
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
                <span className="text-slate-500 block text-[10px]">DECIDED AT (UTC)</span>
                {new Date(selectedDecision.decided_at).toLocaleTimeString()}
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
