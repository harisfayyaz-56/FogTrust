import React from 'react';

interface BadgeProps {
  label: string;
  variant?: 'green' | 'red' | 'amber' | 'blue' | 'purple' | 'slate';
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({ label, variant, size = 'sm' }) => {
  let color = 'bg-slate-800 text-slate-300 border-slate-700';

  const lower = label.toLowerCase();
  if (variant) {
    if (variant === 'green') color = 'bg-emerald-950/70 text-emerald-300 border-emerald-800';
    if (variant === 'red') color = 'bg-rose-950/70 text-rose-300 border-rose-800';
    if (variant === 'amber') color = 'bg-amber-950/70 text-amber-300 border-amber-800';
    if (variant === 'blue') color = 'bg-sky-950/70 text-sky-300 border-sky-800';
    if (variant === 'purple') color = 'bg-purple-950/70 text-purple-300 border-purple-800';
  } else {
    // Auto-detect based on common words
    if (['active', 'success', 'allow', 'ok', 'completed', 'admin'].includes(lower)) {
      color = 'bg-emerald-950/70 text-emerald-300 border-emerald-800';
    } else if (['revoked', 'failure', 'deny', 'failed', 'tampered', 'cancelled'].includes(lower)) {
      color = 'bg-rose-950/70 text-rose-300 border-rose-800';
    } else if (['operator', 'assigned', 'pending', 'flag'].includes(lower)) {
      color = 'bg-amber-950/70 text-amber-300 border-amber-800';
    } else if (['viewer', 'queued', 'heartbeat', 'task'].includes(lower)) {
      color = 'bg-sky-950/70 text-sky-300 border-sky-800';
    }
  }

  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm font-medium';

  return (
    <span
      className={`inline-flex items-center rounded-full border font-mono tracking-wide ${sizeClass} ${color}`}
    >
      {label}
    </span>
  );
};

