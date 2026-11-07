import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Search,
  Filter,
  Link,
  Layers,
  ArrowRight,
  Bug,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getAuditEvents, verifyAuditChain } from '../../services/api';
import { AuditEvent, AuditVerifyReport } from '../../types/api';
import { Badge } from '../common/Badge';
import { Modal } from '../common/Modal';

export const AuditLogView: React.FC = () => {
  const { isDemoMode } = useAuth();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [verifyReport, setVerifyReport] = useState<AuditVerifyReport | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);

  // Filters
  const [actionFilter, setActionFilter] = useState<string>('');
  const [outcomeFilter, setOutcomeFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected event for detail inspection
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const fetchAuditEvents = async () => {
    setIsLoading(true);
    try {
      const res = await getAuditEvents(
        {
          action: actionFilter || undefined,
          outcome: outcomeFilter || undefined,
        },
        isDemoMode
      );
      setEvents(res.results || []);
    } catch (err) {
      console.error('Failed to load audit events:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyChain = async () => {
    setIsVerifying(true);
    try {
      const report = await verifyAuditChain(isDemoMode);
      setVerifyReport(report);
    } catch (err: any) {
      alert(err.message || 'Audit verification request failed');
    } finally {
      setIsVerifying(false);
    }
  };

  useEffect(() => {
    fetchAuditEvents();
    handleVerifyChain();
  }, [isDemoMode, actionFilter, outcomeFilter]);

  // Demo helper: simulate tampering with an audit block (ID-9 test)
  const simulateTampering = () => {
    setVerifyReport({
      valid: false,
      events_checked: 4,
      first_broken_sequence: 3,
      problem: 'hash_mismatch',
      checked_at: new Date().toISOString(),
    });
  };

  const filteredEvents = events.filter((e) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      e.action.toLowerCase().includes(q) ||
      e.actor_id.toLowerCase().includes(q) ||
      e.target_id.toLowerCase().includes(q) ||
      e.reason_code.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-teal-400" />
            Append-Only Hash-Chained Audit Log
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Cryptographic ledger tracking all security events. Tampering breaks SHA-256 pointers (ID-9).
          </p>
        </div>

        <div className="flex items-center gap-2">
          {isDemoMode && (
            <button
              onClick={simulateTampering}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-800 bg-amber-950/40 text-amber-300 hover:bg-amber-900/40 text-xs font-medium"
              title="Simulate detecting modified database row"
            >
              <Bug className="w-3.5 h-3.5" />
              <span>Simulate Tamper (ID-9)</span>
            </button>
          )}

          <button
            onClick={handleVerifyChain}
            disabled={isVerifying}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors shadow-sm disabled:opacity-50"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>{isVerifying ? 'Recomputing Hashes...' : 'Verify Hash Chain'}</span>
          </button>
        </div>
      </div>

      {/* Verification Banner */}
      {verifyReport && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${
            verifyReport.valid
              ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
              : 'bg-rose-950/60 border-rose-800 text-rose-200 animate-pulse'
          }`}
        >
          <div className="flex items-center gap-3">
            {verifyReport.valid ? (
              <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-6 h-6 text-rose-400 shrink-0" />
            )}
            <div>
              <div className="font-bold text-sm flex items-center gap-2 font-mono">
                <span>{verifyReport.valid ? 'AUDIT LOG VERIFIED INTACT' : 'INTEGRITY BREACH DETECTED!'}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-black/40 border border-current font-mono">
                  {verifyReport.events_checked} SHA-256 nodes verified
                </span>
              </div>
              <p className="text-xs mt-0.5 opacity-90 font-sans">
                {verifyReport.valid
                  ? 'All event hash linkages (prev_hash -> current_hash) match exactly. No deletions or edits.'
                  : `Chain verification failed at sequence #${verifyReport.first_broken_sequence} with defect: "${verifyReport.problem}". Database triggers or log file was modified.`}
              </p>
            </div>
          </div>

          <div className="text-right text-[11px] font-mono opacity-80 shrink-0 hidden sm:block">
            Checked: {new Date(verifyReport.checked_at).toLocaleTimeString()}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search action, actor, target, reason code..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-teal-500"
          />
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Outcome:</span>
            <select
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-teal-500"
            >
              <option value="">All Outcomes</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="denied">Denied</option>
            </select>
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4"># Seq</th>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Target</th>
                <th className="py-3 px-4">Outcome</th>
                <th className="py-3 px-4">Hash Link</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    {isLoading ? 'Loading audit records...' : 'No audit events found.'}
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt) => (
                  <tr
                    key={evt.sequence}
                    onClick={() => setSelectedEvent(evt)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-teal-400">
                      #{evt.sequence}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3.5 px-4 font-mono font-medium text-slate-200">
                      {evt.action}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px]">
                      <span className="text-slate-300">{evt.actor_id}</span>
                      <span className="text-slate-500 ml-1">({evt.actor_role})</span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                      {evt.target_type}: {evt.target_id.slice(0, 10)}...
                    </td>
                    <td className="py-3.5 px-4">
                      <Badge label={evt.outcome} />
                      {evt.reason_code && (
                        <span className="block text-[10px] font-mono text-rose-400 mt-0.5">
                          {evt.reason_code}
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[10px] text-slate-500">
                      <div className="flex items-center gap-1" title={`Hash: ${evt.hash}`}>
                        <Link className="w-3 h-3 text-slate-500" />
                        <span>{evt.hash.slice(0, 8)}...</span>
                      </div>
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

      {/* Audit Event Detail Modal */}
      {selectedEvent && (
        <Modal
          isOpen={!!selectedEvent}
          onClose={() => setSelectedEvent(null)}
          title={`Audit Record #${selectedEvent.sequence}: ${selectedEvent.action}`}
          maxWidth="xl"
        >
          <div className="space-y-4 text-xs font-mono">
            <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Sequence & Event ID</span>
                <span className="text-slate-200">#{selectedEvent.sequence}</span>
                <span className="text-slate-500 text-[10px] block truncate">{selectedEvent.event_id}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Outcome</span>
                <Badge label={selectedEvent.outcome} />
                {selectedEvent.reason_code && (
                  <span className="text-rose-400 block text-[10px]">{selectedEvent.reason_code}</span>
                )}
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Actor</span>
                <span className="text-slate-200">{selectedEvent.actor_id} ({selectedEvent.actor_role})</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Timestamp (UTC)</span>
                <span className="text-slate-300">{selectedEvent.timestamp}</span>
              </div>
            </div>

            {/* Redacted Details JSON */}
            <div>
              <span className="text-slate-400 text-xs uppercase block mb-1">
                Redacted Event Details (Never Logs Passwords or Secrets)
              </span>
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 text-[11px] overflow-x-auto select-all">
                {JSON.stringify(selectedEvent.details, null, 2)}
              </pre>
            </div>

            {/* SHA-256 Hash Chain Pointers */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <span className="text-slate-400 text-[10px] uppercase block font-semibold text-teal-400">
                Cryptographic Hash Chain Linkage
              </span>
              <div>
                <span className="text-slate-500 block text-[10px]">PREVIOUS HASH (prev_hash)</span>
                <code className="text-slate-300 break-all select-all text-[10px]">
                  {selectedEvent.prev_hash}
                </code>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">CURRENT BLOCK HASH</span>
                <code className="text-teal-300 break-all select-all text-[10px]">
                  {selectedEvent.hash}
                </code>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

