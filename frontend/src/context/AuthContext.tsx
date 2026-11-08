import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { UserRole, AuthMeResponse } from '../types/api';
import { USE_MOCK_DEFAULT, SESSION_EXPIRED_EVENT, SESSION_ACTIVITY_EVENT } from '../config/env';
import * as api from '../services/api';

interface AuthContextType {
  currentUser: AuthMeResponse | null;
  role: UserRole;
  permissions: string[];
  isAuthenticated: boolean;
  isLoading: boolean;
  isDemoMode: boolean;
  secondsRemaining: number;
  setDemoMode: (enabled: boolean) => void;
  login: (u: string, p: string) => Promise<void>;
  logout: () => Promise<void>;
  switchDemoRole: (role: UserRole) => void;
  hasPermission: (perm: string) => boolean;
  refreshMe: () => Promise<void>;
}

/**
 * Mirrors backend accounts/permissions.py CAPABILITIES exactly. The server is
 * the authority; these lists only drive which controls the UI shows.
 */
const DEFAULT_PERMISSIONS: Record<UserRole, string[]> = {
  admin: [
    'audit.verify',
    'audit.view',
    'decisions.view',
    'nodes.revoke',
    'nodes.view',
    'policy.change',
    'policy.view',
    'reports.export',
    'results.view',
    'tasks.cancel',
    'tasks.submit',
    'tasks.view',
    'tokens.manage',
    'trust.view',
    'users.manage',
  ],
  operator: [
    'decisions.view',
    'nodes.view',
    'policy.view',
    'reports.export',
    'results.view',
    'tasks.cancel',
    'tasks.submit',
    'tasks.view',
    'trust.view',
  ],
  viewer: ['decisions.view', 'nodes.view', 'policy.view', 'tasks.view', 'trust.view'],
};

const DEFAULT_IDLE_TIMEOUT = 1800;

function buildDemoUser(role: UserRole, username?: string): AuthMeResponse {
  return {
    username: username || `${role}1`,
    role,
    permissions: DEFAULT_PERMISSIONS[role],
    session_idle_timeout: DEFAULT_IDLE_TIMEOUT,
  };
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // VITE_USE_MOCK=true starts offline; the default is real mode.
  const [isDemoMode, setIsDemoMode] = useState<boolean>(USE_MOCK_DEFAULT);
  const [currentUser, setCurrentUser] = useState<AuthMeResponse | null>(() =>
    USE_MOCK_DEFAULT ? buildDemoUser('admin') : null
  );
  const [isLoading, setIsLoading] = useState<boolean>(!USE_MOCK_DEFAULT);
  const [secondsRemaining, setSecondsRemaining] = useState<number>(
    USE_MOCK_DEFAULT ? DEFAULT_IDLE_TIMEOUT : 0
  );

  const demoModeRef = useRef(isDemoMode);
  useEffect(() => {
    demoModeRef.current = isDemoMode;
  }, [isDemoMode]);

  const role: UserRole = currentUser?.role || 'viewer';
  const permissions: string[] = currentUser?.permissions || (currentUser ? DEFAULT_PERMISSIONS[role] : []);
  const isAuthenticated = !!currentUser;

  const refreshMe = useCallback(async () => {
    try {
      const me = await api.getMe();
      setCurrentUser(me);
      setSecondsRemaining(me.session_idle_timeout || DEFAULT_IDLE_TIMEOUT);
    } catch (err: unknown) {
      // Only a genuine 401 clears the session. A network outage keeps the
      // current view instead of pretending the user was logged out.
      if (err instanceof api.ApiError && err.status === 401) {
        setCurrentUser(null);
        setSecondsRemaining(0);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Restore the real session on load and whenever demo mode is switched off.
  useEffect(() => {
    if (isDemoMode) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    refreshMe();
  }, [isDemoMode, refreshMe]);

  // A 401 from any real request means the server-side session is gone.
  useEffect(() => {
    const handleExpired = () => {
      if (demoModeRef.current) return;
      setCurrentUser(null);
      setSecondsRemaining(0);
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, handleExpired);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, handleExpired);
  }, []);

  // Every successful request resets the backend idle timeout, so mirror that
  // in the visible countdown. Without this the dashboard would sign an active
  // user out after the original timeout even though the server session is alive.
  useEffect(() => {
    const handleActivity = () => {
      if (demoModeRef.current) return;
      setSecondsRemaining(currentUser?.session_idle_timeout || DEFAULT_IDLE_TIMEOUT);
    };
    window.addEventListener(SESSION_ACTIVITY_EVENT, handleActivity);
    return () => window.removeEventListener(SESSION_ACTIVITY_EVENT, handleActivity);
  }, [currentUser]);

  // Session countdown timer
  useEffect(() => {
    if (!isAuthenticated) return;
    const interval = setInterval(() => {
      setSecondsRemaining((prev) => {
        if (prev <= 1) {
          setCurrentUser(null);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [isAuthenticated]);

  const login = async (u: string, p: string) => {
    if (isDemoMode) {
      const demoRole: UserRole = u.includes('admin')
        ? 'admin'
        : u.includes('operator')
        ? 'operator'
        : 'viewer';
      setCurrentUser(buildDemoUser(demoRole, u));
      setSecondsRemaining(DEFAULT_IDLE_TIMEOUT);
      return;
    }

    await api.login(u, p);
    const me = await api.getMe();
    setCurrentUser(me);
    setSecondsRemaining(me.session_idle_timeout || DEFAULT_IDLE_TIMEOUT);
  };

  const logout = async () => {
    if (!isDemoMode) {
      try {
        await api.logout();
      } catch (err) {
        console.warn('Logout request failed or already invalidated:', err);
      }
    }
    setCurrentUser(null);
    setSecondsRemaining(0);
  };

  const switchDemoRole = (newRole: UserRole) => {
    setIsDemoMode(true);
    setCurrentUser(buildDemoUser(newRole));
    setSecondsRemaining(DEFAULT_IDLE_TIMEOUT);
  };

  const setDemoMode = (enabled: boolean) => {
    setIsDemoMode(enabled);
    if (enabled) {
      // Keep the current role when moving from a real session into demo data.
      setCurrentUser(buildDemoUser(currentUser?.role || 'admin'));
      setSecondsRemaining(DEFAULT_IDLE_TIMEOUT);
    } else {
      // The effect above re-reads /auth/me to restore a real session, if any.
      setCurrentUser(null);
      setSecondsRemaining(0);
    }
  };

  const hasPermission = (perm: string): boolean => {
    return permissions.includes(perm);
  };

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        role,
        permissions,
        isAuthenticated,
        isLoading,
        isDemoMode,
        secondsRemaining,
        setDemoMode,
        login,
        logout,
        switchDemoRole,
        hasPermission,
        refreshMe,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
