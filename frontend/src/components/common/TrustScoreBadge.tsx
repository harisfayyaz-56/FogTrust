import React from 'react';

interface TrustScoreBadgeProps {
  score: number;
  threshold?: number;
  size?: 'sm' | 'md';
}

/**
 * Compact trust-score pill used in fleet and trust-history tables.
 * Colour follows the same bands as TrustScoreBar so the two never disagree.
 */
export const TrustScoreBadge: React.FC<TrustScoreBadgeProps> = ({
  score,
  threshold = 70,
  size = 'sm',
}) => {
  const safeScore = Math.max(0, Math.min(100, Math.round(score)));
  const isEligible = safeScore >= threshold;

  let colour = 'bg-rose-950/70 text-rose-300 border-rose-800';
  if (safeScore >= 80) {
    colour = 'bg-emerald-950/70 text-emerald-300 border-emerald-800';
  } else if (safeScore >= 50) {
    colour = 'bg-amber-950/70 text-amber-300 border-amber-800';
  }

  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-mono font-bold ${sizeClass} ${colour}`}
      title={`Trust ${safeScore}/100 · ${isEligible ? 'meets' : 'below'} scheduler threshold ${threshold}`}
    >
      <span>{safeScore}</span>
      <span className="text-[10px] font-normal opacity-70">{isEligible ? 'trusted' : 'degraded'}</span>
    </span>
  );
};
