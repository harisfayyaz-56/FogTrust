import React from 'react';
import { AlertTriangle, Inbox, Loader2, RefreshCw } from 'lucide-react';

interface LoadingStateProps {
  label?: string;
}

/** Consistent loading panel used by every Phase 2 view. */
export const LoadingState: React.FC<LoadingStateProps> = ({ label = 'Loading…' }) => (
  <div
    className="p-10 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col items-center justify-center gap-3 text-slate-400"
    role="status"
    aria-live="polite"
  >
    <Loader2 className="w-5 h-5 text-teal-400 animate-spin" />
    <p className="text-xs font-mono">{label}</p>
  </div>
);

interface EmptyStateProps {
  title?: string;
  description?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
}

/** Empty result panel. Explains why nothing is shown and how to recover. */
export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'Nothing to show',
  description = 'No records match the current filters.',
  icon,
  action,
}) => (
  <div className="p-10 rounded-xl bg-slate-900/60 border border-dashed border-slate-700 flex flex-col items-center justify-center gap-3 text-center">
    <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center text-slate-500">
      {icon || <Inbox className="w-5 h-5" />}
    </div>
    <div>
      <p className="text-sm font-medium text-slate-200">{title}</p>
      <p className="text-xs text-slate-500 mt-1 max-w-md">{description}</p>
    </div>
    {action}
  </div>
);

interface ErrorStateProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
}

/** Error panel with an optional retry action. Never renders raw server secrets. */
export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Something went wrong',
  message = 'The request failed. Check the connection to the FogTrust broker and try again.',
  onRetry,
}) => (
  <div
    className="p-8 rounded-xl bg-rose-950/30 border border-rose-900/70 flex flex-col items-center justify-center gap-3 text-center"
    role="alert"
  >
    <div className="w-10 h-10 rounded-full bg-rose-950/80 border border-rose-800 flex items-center justify-center">
      <AlertTriangle className="w-5 h-5 text-rose-400" />
    </div>
    <div>
      <p className="text-sm font-semibold text-rose-200">{title}</p>
      <p className="text-xs text-rose-300/80 mt-1 max-w-md">{message}</p>
    </div>
    {onRetry && (
      <button
        onClick={onRetry}
        className="mt-1 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rose-800 bg-rose-950/60 text-rose-200 hover:bg-rose-900/50 text-xs font-medium transition-colors"
      >
        <RefreshCw className="w-3.5 h-3.5" />
        <span>Retry</span>
      </button>
    )}
  </div>
);
