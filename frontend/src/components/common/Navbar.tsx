import React, { useEffect, useState } from 'react';
import { Shield, Activity, Clock, LogOut, ToggleLeft, ToggleRight, Sparkles } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { Badge } from './Badge';
import { getHealth } from '../../services/api';
import { HealthResponse } from '../../types/api';

export const Navbar: React.FC = () => {
  const { currentUser, role, isDemoMode, setDemoMode, switchDemoRole, secondsRemaining, logout } =
    useAuth();
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    getHealth(isDemoMode)
      .then((res) => {
        if (mounted) setHealth(res);
      })
      .catch(() => {
        if (mounted) setHealth(null);
      });
    return () => {
      mounted = false;
    };
  }, [isDemoMode]);

  const formatSeconds = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m}:${s < 10 ? '0' : ''}${s}`;
  };

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40 px-6 flex items-center justify-between">
      {/* Brand & System Health */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-teal-500/10 border border-teal-500/30 flex items-center justify-center text-teal-400">
            <Shield className="w-5 h-5 text-teal-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-100 tracking-tight text-base">FogTrust</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                FR-7
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Edge Security Broker</p>
          </div>
        </div>

        {/* Live Broker Health Indicator */}
        <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700/60 text-xs">
          <Activity
            className={`w-3.5 h-3.5 ${
              health?.status === 'ok' ? 'text-emerald-400 animate-pulse' : 'text-amber-400'
            }`}
          />
          <span className="text-slate-300">
            {health?.status === 'ok' ? 'Broker Online' : 'Broker Connecting...'}
          </span>
          <span className="text-slate-500 text-[10px]">({health?.service || 'v0.1.0'})</span>
        </div>
      </div>

      {/* Center / Right controls */}
      <div className="flex items-center gap-4">
        {/* Demo Mode Toggle */}
        <button
          onClick={() => setDemoMode(!isDemoMode)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${
            isDemoMode
              ? 'bg-amber-950/40 border-amber-600/60 text-amber-300'
              : 'bg-slate-800/60 border-slate-700 text-slate-300 hover:bg-slate-800'
          }`}
          title="Toggle between Live Server API and Offline Demo Simulation"
        >
          <Sparkles className="w-3.5 h-3.5 text-amber-400" />
          <span>Demo Data Mode:</span>
          {isDemoMode ? (
            <ToggleRight className="w-4 h-4 text-amber-400" />
          ) : (
            <ToggleLeft className="w-4 h-4 text-slate-500" />
          )}
        </button>

        {/* Demo Role Switcher Quick Pill (Visible only in demo mode) */}
        {isDemoMode && (
          <div className="hidden lg:flex items-center gap-1 p-0.5 bg-slate-950 rounded-lg border border-slate-800 text-xs">
            <span className="px-2 text-[10px] text-slate-400 uppercase font-mono">Demo Role:</span>
            {(['admin', 'operator', 'viewer'] as const).map((r) => (
              <button
                key={r}
                onClick={() => switchDemoRole(r)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                  role === r
                    ? 'bg-teal-500/20 text-teal-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        )}

        {/* Session Inactivity Countdown */}
        {currentUser && (
          <div
            className="flex items-center gap-1.5 text-xs text-slate-400 bg-slate-800/50 px-2.5 py-1 rounded-md border border-slate-800"
            title="Idle session timeout (expires after 30m inactivity)"
          >
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span className="font-mono text-slate-300">{formatSeconds(secondsRemaining)}</span>
          </div>
        )}

        {/* Current User & Role Pill */}
        {currentUser && (
          <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
            <div className="text-right">
              <div className="text-xs font-medium text-slate-200">{currentUser.username}</div>
              <div className="text-[10px] text-slate-400 flex items-center justify-end gap-1">
                <span>Role:</span>
                <Badge label={role} size="sm" />
              </div>
            </div>

            <button
              onClick={logout}
              className="p-2 text-slate-400 hover:text-rose-400 rounded-lg hover:bg-slate-800/80 transition-colors"
              title="Logout session"
              aria-label="Logout session"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

