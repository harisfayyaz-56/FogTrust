import React from 'react';

interface TrustScoreBarProps {
  score: number; // 0 to 100
  threshold?: number;
  showNumeric?: boolean;
}

export const TrustScoreBar: React.FC<TrustScoreBarProps> = ({
  score,
  threshold = 70,
  showNumeric = true,
}) => {
  const safeScore = Math.max(0, Math.min(100, Math.round(score)));

  let barColor = 'bg-rose-500';
  let textColor = 'text-rose-400';

  if (safeScore >= 80) {
    barColor = 'bg-emerald-500';
    textColor = 'text-emerald-400';
  } else if (safeScore >= 50) {
    barColor = 'bg-amber-500';
    textColor = 'text-amber-400';
  }

  return (
    <div className="flex flex-col gap-1 w-full max-w-[140px]">
      {showNumeric && (
        <div className="flex items-center justify-between text-xs">
          <span className={`font-mono font-medium ${textColor}`}>
            {safeScore}/100
          </span>
          <span className="text-[10px] text-slate-500">
            min {threshold}
          </span>
        </div>
      )}
      <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700/50 relative">
        <div
          className={`h-full ${barColor} transition-all duration-300 rounded-full`}
          style={{ width: `${safeScore}%` }}
        />
        <div
          className="absolute top-0 bottom-0 w-0.5 bg-slate-500/80 z-10"
          style={{ left: `${threshold}%` }}
          title={`Policy threshold: ${threshold}`}
        />
      </div>
    </div>
  );
};

