import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { UserRole, AuthMeResponse } from '../types/api';
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

const DEFAULT_PERMISSIONS: Record<UserRole, string[]> = {
  admin: [
    'audit.verify',
    'audit.view',
    'decisions.view',
    'nodes.enroll',
    'nodes.revoke',
    'nodes.view',
    'policy.change',
    'policy.view',
    'reports.export',
    'results.view',
    'tasks.cancel',
    'tasks.submit',
    'tasks.view',
    'tokens.cancel',
    'tokens.create',
    'tokens.view',
    'trust.view',
    'users.create',
    'users.manage',
    'users.view',
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
  viewer: [
    'decisions.view',
    'nodes.view',
    'policy.view',
    'tasks.view',
    'trust.view',
  ],
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<AuthMeResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isDemoMode, setIsDemoMode] = useState<boolean>(false);
  const [secondsRemaining, setSecondsRemaining] = useState<number>(1800);

  const role: UserRole = currentUser?.role || 'viewer';
  const permissions: string[] = currentUser?.permissions || (currentUser ? DEFAULT_PERMISSIONS[role] : []);
  const isAuthenticated = !!currentUser;

  const refreshMe = useCallback(async () => {
    try {
      const me = await api.getMe();
      setCurrentUser(me);
      setSecondsRemaining(me.session_idle_timeout || 1800);
    } catch {
      // If unauthenticated or offline
      if (!isDemoMode) {
        setCurrentUser(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, [isDemoMode]);

  useEffect(() => {
    refreshMe();
  }, [refreshMe]);

  // Session countdown timer
  useEffect(() => {
    if (!isAuthenticated) return;
    const interval = setInterval(() => {
      setSecondsRemaining((prev) => {
        if (prev <= 1) {
          // Session expired
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
      const demoRole: UserRole = u.includes('admin') ? 'admin' : u.includes('operator') ? 'operator' : 'viewer';
      setCurrentUser({
        username: u,
        role: demoRole,
        permissions: DEFAULT_PERMISSIONS[demoRole],
        session_idle_timeout: 1800,
      });
      setSecondsRemaining(1800);
      return;
    }

    await api.login(u, p);
    await refreshMe();
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
  };

  const switchDemoRole = (newRole: UserRole) => {
    setIsDemoMode(true);
    setCurrentUser({
      username: `${newRole}1`,
      role: newRole,
      permissions: DEFAULT_PERMISSIONS[newRole],
      session_idle_timeout: 1800,
    });
    setSecondsRemaining(1800);
  };

  const setDemoMode = (enabled: boolean) => {
    setIsDemoMode(enabled);
    if (enabled && !currentUser) {
      switchDemoRole('admin');
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

