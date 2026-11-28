import React, { useState } from 'react';
import { Shield, Lock, User, AlertTriangle, KeyRound, Sparkles } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ApiError } from '../services/api';

export const LoginModal: React.FC = () => {
  const { login, switchDemoRole } = useAuth();
  const [username, setUsername] = useState<string>('admin1');
  const [password, setPassword] = useState<string>('password123');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [retryAfter, setRetryAfter] = useState<number | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoggingIn(true);
    setErrorMsg(null);

    try {
      await login(username, password);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.code === 'RATE_LIMITED') {
          const waitTime = (err.details?.retry_after_seconds as number) || 45;
          setRetryAfter(waitTime);
          setErrorMsg(`Rate limit exceeded: 5 attempts/min per IP. Please retry in ${waitTime}s.`);
        } else if (err.code === 'AUTH_INVALID_CREDENTIALS') {
          setErrorMsg('Invalid username or password (Argon2 verified).');
        } else {
          setErrorMsg(err.message || 'Login failed. Please check credentials or start server.');
        }
      } else {
        setErrorMsg('Network error connecting to backend. (You can click "Quick Demo Login" below to test offline!)');
      }
    } finally {
      setIsLoggingIn(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 sm:p-8 space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-xl bg-teal-500/10 border border-teal-500/30 text-teal-400 mx-auto flex items-center justify-center shadow-inner">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight">FogTrust Broker Console</h1>
          <p className="text-xs text-slate-400">
            Sign in with an authenticated session to manage fog nodes and inspect audit evidence.
          </p>
        </div>

        {/* Error message banner */}
        {errorMsg && (
          <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/80 text-rose-200 text-xs flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span className="font-sans">{errorMsg}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Username:</label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin1 / operator1 / viewer1"
                className="w-full bg-slate-950 border border-slate-700/80 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-teal-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Password:</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-slate-700/80 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-teal-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoggingIn || (retryAfter !== null && retryAfter > 0)}
            className="w-full py-2.5 bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold transition-colors shadow-sm flex items-center justify-center gap-1.5"
          >
            <KeyRound className="w-4 h-4" />
            <span>{isLoggingIn ? 'Verifying Session...' : 'Sign In with Session'}</span>
          </button>
        </form>

        {/* Demo Mode Quick Buttons (For Evaluation & Demo Presentation) */}
        <div className="pt-4 border-t border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
            <span className="flex items-center gap-1 text-amber-400">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Evaluation / Offline Demo Mode:</span>
            </span>
          </div>

          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => switchDemoRole('admin')}
              className="py-1.5 px-2 rounded bg-slate-950 border border-slate-800 hover:border-teal-700 hover:text-teal-300 text-slate-300 text-[11px] font-mono transition-colors"
            >
              admin1
            </button>
            <button
              type="button"
              onClick={() => switchDemoRole('operator')}
              className="py-1.5 px-2 rounded bg-slate-950 border border-slate-800 hover:border-amber-700 hover:text-amber-300 text-slate-300 text-[11px] font-mono transition-colors"
            >
              operator1
            </button>
            <button
              type="button"
              onClick={() => switchDemoRole('viewer')}
              className="py-1.5 px-2 rounded bg-slate-950 border border-slate-800 hover:border-sky-700 hover:text-sky-300 text-slate-300 text-[11px] font-mono transition-colors"
            >
              viewer1
            </button>
          </div>
          <p className="text-[10px] text-slate-500 text-center font-sans mt-1">
            Click any demo role to simulate dashboard features offline.
          </p>
        </div>
      </div>
    </div>
  );
};

