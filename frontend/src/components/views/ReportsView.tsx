import React, { useEffect, useMemo, useState } from 'react';
import {
  FileSpreadsheet,
  Download,
  ShieldCheck,
  Check,
  FileJson,
  FileText,
  ShieldAlert,
  Info,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getNodes, getDecisions, verifyAuditChain } from '../../services/api';
import { buildSanitizedReportData, reportToCSV, reportToJSON } from '../../services/report';
import { AuditVerifyReport, Decision, NodeItem } from '../../types/api';
import { EmptyState, ErrorState, LoadingState } from '../common/ViewState';

type ChainStatus = 'verified' | 'failed' | 'unverified' | 'checking';

export const ReportsView: React.FC = () => {
  const { isDemoMode, currentUser, hasPermission } = useAuth();
  const [format, setFormat] = useState<'json' | 'csv'>('json');
  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [chainStatus, setChainStatus] = useState<ChainStatus>('checking');
  const [chainReport, setChainReport] = useState<AuditVerifyReport | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [downloadSuccess, setDownloadSuccess] = useState<boolean>(false);
  const [refreshKey, setRefreshKey] = useState<number>(0);

  const canVerifyAudit = hasPermission('audit.verify');

  useEffect(() => {
    let mounted = true;
    setIsLoading(true);
    setLoadError(null);
    setChainStatus(canVerifyAudit ? 'checking' : 'unverified');
    setChainReport(null);

    Promise.allSettled([
      getNodes({}, isDemoMode),
      getDecisions({}, isDemoMode),
      canVerifyAudit ? verifyAuditChain(isDemoMode) : Promise.resolve(null),
    ]).then(([nodesRes, decisionsRes, auditRes]) => {
      if (!mounted) return;

      if (nodesRes.status === 'fulfilled') {
        setNodes(nodesRes.value.results || []);
      } else {
        setNodes([]);
      }

      if (decisionsRes.status === 'fulfilled') {
        setDecisions(decisionsRes.value.results || []);
      } else {
        setDecisions([]);
      }

      if (auditRes.status === 'fulfilled' && auditRes.value) {
        setChainReport(auditRes.value);
        setChainStatus(auditRes.value.valid ? 'verified' : 'failed');
      } else if (canVerifyAudit) {
        // Verification is a best-effort integrity signal; failure to verify does
        // not block the sanitized export, but it must never be reported as valid.
        setChainStatus('unverified');
      }

      if (nodesRes.status === 'rejected' && decisionsRes.status === 'rejected') {
        setLoadError(
          nodesRes.reason instanceof Error
            ? nodesRes.reason.message
            : 'Could not load the data required to build the report.'
        );
      } else if (nodesRes.status === 'rejected') {
        setLoadError('Could not load the node fleet for the report.');
      } else if (decisionsRes.status === 'rejected') {
        setLoadError('Could not load security decisions for the report.');
      }

      setIsLoading(false);
    });

    return () => {
      mounted = false;
    };
  }, [isDemoMode, canVerifyAudit, refreshKey]);

  const reportData = useMemo(
    () =>
      buildSanitizedReportData(
        currentUser?.username || 'anonymous',
        nodes,
        decisions,
        chainStatus === 'verified'
      ),
    [currentUser, nodes, decisions, chainStatus]
  );

  const serialized = useMemo(
    () => (format === 'json' ? reportToJSON(reportData) : reportToCSV(reportData)),
    [format, reportData]
  );

  const canExport = hasPermission('reports.export');

  if (!canExport) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileSpreadsheet className="w-5 h-5 text-teal-400" />
            Sanitized Report Generator (FR-7 / M4)
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">Zero-secret exports for auditors and stakeholders.</p>
        </div>
        <div className="p-8 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col items-center text-center gap-3">
          <div className="w-12 h-12 rounded-full bg-rose-950/70 border border-rose-800 flex items-center justify-center">
            <ShieldAlert className="w-6 h-6 text-rose-400" />
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-100">Export permission required</p>
            <p className="text-xs text-slate-400 mt-1 max-w-md">
              Your role does not include <code className="font-mono text-slate-300">reports.export</code>.
              Ask an Administrator to export the sanitized report for you.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const handleDownload = () => {
    const content = format === 'json' ? reportToJSON(reportData) : reportToCSV(reportData);
    const mimeType = format === 'json' ? 'application/json' : 'text/csv';
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `fogtrust-sanitized-report-${new Date().toISOString().split('T')[0]}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setDownloadSuccess(true);
    setTimeout(() => setDownloadSuccess(false), 3000);
  };

  const refresh = () => setRefreshKey((key) => key + 1);
  const hasReportContent = nodes.length > 0 || decisions.length > 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileSpreadsheet className="w-5 h-5 text-teal-400" />
            Sanitized Report Generator (FR-7 / M4)
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Export compliance-ready summaries for auditors and stakeholders. Strictly strips all cryptographic
            secrets.
          </p>
        </div>

        <button
          onClick={handleDownload}
          disabled={isLoading || !!loadError || !hasReportContent}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {downloadSuccess ? (
            <>
              <Check className="w-4 h-4 text-white" />
              <span>Downloaded Successfully</span>
            </>
          ) : (
            <>
              <Download className="w-4 h-4" />
              <span>Export {format.toUpperCase()} Report</span>
            </>
          )}
        </button>
      </div>

      {/* Security Assurance Banner */}
      <div className="p-4 rounded-xl bg-teal-950/30 border border-teal-800/60 text-xs text-teal-200">
        <div className="flex items-center gap-2 font-bold text-sm text-teal-300 mb-1">
          <ShieldCheck className="w-4 h-4 text-teal-400" />
          <span>Strict Redaction Guarantees (API Contract 5.10)</span>
        </div>
        <p className="text-teal-300/80 mb-3">
          The exporter is allow-list based and runs a defensive secret scan before download. The resulting
          document never contains:
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 font-mono text-[11px]">
          <div className="flex items-center gap-1.5 p-2 bg-slate-950/60 rounded border border-teal-900/40">
            <Check className="w-3.5 h-3.5 text-teal-400" />
            <span>No Public Keys</span>
          </div>
          <div className="flex items-center gap-1.5 p-2 bg-slate-950/60 rounded border border-teal-900/40">
            <Check className="w-3.5 h-3.5 text-teal-400" />
            <span>No Token Hashes</span>
          </div>
          <div className="flex items-center gap-1.5 p-2 bg-slate-950/60 rounded border border-teal-900/40">
            <Check className="w-3.5 h-3.5 text-teal-400" />
            <span>No Ciphertexts</span>
          </div>
          <div className="flex items-center gap-1.5 p-2 bg-slate-950/60 rounded border border-teal-900/40">
            <Check className="w-3.5 h-3.5 text-teal-400" />
            <span>No Passwords</span>
          </div>
          <div className="flex items-center gap-1.5 p-2 bg-slate-950/60 rounded border border-teal-900/40">
            <Check className="w-3.5 h-3.5 text-teal-400" />
            <span>No Raw Signatures</span>
          </div>
        </div>
      </div>

      {/* Audit chain status */}
      <div
        className={`p-4 rounded-xl border flex items-start gap-3 text-xs ${
          chainStatus === 'verified'
            ? 'bg-emerald-950/30 border-emerald-800/70 text-emerald-200'
            : chainStatus === 'failed'
            ? 'bg-rose-950/40 border-rose-800/80 text-rose-200'
            : 'bg-slate-900/60 border-slate-800 text-slate-300'
        }`}
      >
        {chainStatus === 'verified' ? (
          <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
        ) : chainStatus === 'failed' ? (
          <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
        ) : (
          <Info className="w-5 h-5 text-slate-400 shrink-0 mt-0.5" />
        )}
        <div>
          <p className="font-semibold">
            {chainStatus === 'verified'
              ? 'Audit hash chain verified intact'
              : chainStatus === 'failed'
              ? 'Audit hash chain integrity breach detected'
              : chainStatus === 'checking'
              ? 'Checking audit hash chain…'
              : 'Audit hash chain not verified'}
          </p>
          <p className="mt-0.5 opacity-90">
            {chainStatus === 'verified' && chainReport
              ? `${chainReport.events_checked} SHA-256 links recomputed successfully. The export records audit_chain_verified = true.`
              : chainStatus === 'failed' && chainReport
              ? `Verification failed at sequence #${chainReport.first_broken_sequence} (${chainReport.problem}). The export records audit_chain_verified = false.`
              : canVerifyAudit
              ? 'Verification could not be completed. The export will record audit_chain_verified = false.'
              : 'Your role cannot verify the hash chain (audit.verify). The export records audit_chain_verified = false; an Administrator can verify it separately.'}
          </p>
        </div>
      </div>

      {/* Format Selector */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs font-medium text-slate-300 font-mono">Select Export Format:</span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setFormat('json')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              format === 'json'
                ? 'bg-teal-600 text-white border-teal-500 font-bold'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileJson className="w-3.5 h-3.5" />
            <span>JSON Document</span>
          </button>
          <button
            onClick={() => setFormat('csv')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              format === 'csv'
                ? 'bg-teal-600 text-white border-teal-500 font-bold'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>CSV Spreadsheet</span>
          </button>
        </div>
      </div>

      {loadError ? (
        <ErrorState title="Could not build the sanitized report" message={loadError} onRetry={refresh} />
      ) : isLoading ? (
        <LoadingState label="Collecting nodes, decisions, and audit status…" />
      ) : !hasReportContent ? (
        <EmptyState
          title="Nothing to export yet"
          description="No nodes or security decisions are available. Enroll a node and run a few operations, then refresh to generate a sanitized report."
          icon={<FileSpreadsheet className="w-5 h-5" />}
          action={
            <button
              onClick={refresh}
              className="mt-1 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700 text-xs font-medium"
            >
              Refresh data
            </button>
          }
        />
      ) : (
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs font-mono uppercase text-slate-400">
              Live Sanitized Data Preview ({format.toUpperCase()})
            </span>
            <span className="text-[11px] text-slate-500 font-mono">
              {nodes.length} node{nodes.length === 1 ? '' : 's'} · {decisions.length} decision
              {decisions.length === 1 ? '' : 's'} · generated {new Date(reportData.generated_at).toLocaleTimeString()}
            </span>
          </div>

          <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg overflow-x-auto max-h-[420px]">
            <pre className="font-mono text-[11px] text-slate-300 whitespace-pre-wrap select-all">
              {serialized}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
