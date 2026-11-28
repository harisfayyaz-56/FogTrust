import React from 'react';

interface BadgeProps {
  label: string;
  variant?: 'green' | 'red' | 'amber' | 'blue' | 'purple' | 'slate';
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({ label, variant, size = 'sm' }) => {
  let color = 'bg-slate-800/80 text-slate-300 border-slate-700/80';

  const lower = label.toLowerCase();
  if (variant) {
    if (variant === 'green') color = 'bg-emerald-950/50 text-emerald-400 border-emerald-800/60';
    if (variant === 'red') color = 'bg-rose-950/50 text-rose-400 border-rose-800/60';
    if (variant === 'amber') color = 'bg-amber-950/50 text-amber-400 border-amber-800/60';
    if (variant === 'blue') color = 'bg-sky-950/50 text-sky-400 border-sky-800/60';
    if (variant === 'purple') color = 'bg-purple-950/50 text-purple-400 border-purple-800/60';
  } else {
    // Auto-detect based on common words
    if (['active', 'success', 'allow', 'ok', 'completed'].includes(lower)) {
      color = 'bg-emerald-950/50 text-emerald-400 border-emerald-800/60';
    } else if (['revoked', 'failure', 'deny', 'failed', 'tampered', 'cancelled'].includes(lower)) {
      color = 'bg-rose-950/50 text-rose-400 border-rose-800/60';
    } else if (['operator', 'assigned', 'pending', 'flag'].includes(lower)) {
      color = 'bg-amber-950/50 text-amber-400 border-amber-800/60';
    } else if (['viewer', 'queued', 'heartbeat', 'task', 'enrolled'].includes(lower)) {
      color = 'bg-slate-800 text-slate-300 border-slate-700';
    } else if (['admin'].includes(lower)) {
      color = 'bg-slate-800 text-slate-200 border-slate-600 font-medium';
    }
  }

  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-medium';

  return (
    <span
      className={`inline-flex items-center rounded border font-medium ${sizeClass} ${color}`}
    >
      {label}
    </span>
  );
};

