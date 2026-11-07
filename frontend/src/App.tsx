import React, { useEffect, useState } from 'react';
import { useAuth } from './context/AuthContext';
import { Navbar } from './components/common/Navbar';
import { Sidebar, NavTab, isTabAllowed } from './components/common/Sidebar';
import { LoginModal } from './components/LoginModal';
import { OverviewView } from './components/views/OverviewView';
import { NodesView } from './components/views/NodesView';
import { TrustView } from './components/views/TrustView';
import { EnrollmentTokensView } from './components/views/EnrollmentTokensView';
import { EvidenceView } from './components/views/EvidenceView';
import { TasksView } from './components/views/TasksView';
import { AuditLogView } from './components/views/AuditLogView';
import { PolicyView } from './components/views/PolicyView';
import { AdminSettingsView } from './components/views/AdminSettingsView';
import { UsersView } from './components/views/UsersView';
import { ReportsView } from './components/views/ReportsView';

export const AppContent: React.FC = () => {
  const { isAuthenticated, isLoading, role, hasPermission } = useAuth();
  const [currentTab, setCurrentTab] = useState<NavTab>('overview');
  const [trustNodeId, setTrustNodeId] = useState<string | undefined>(undefined);

  const handleSelectTab = (tab: NavTab) => {
    setTrustNodeId(undefined);
    setCurrentTab(tab);
  };

  const handleNavigate = (tab: string, nodeId?: string) => {
    setTrustNodeId(nodeId);
    setCurrentTab(tab as NavTab);
  };

  // If the session role changes (e.g. demo role switch, permission refresh),
  // leave any tab the new role may not access instead of rendering it.
  useEffect(() => {
    if (isAuthenticated && !isTabAllowed(currentTab, role, hasPermission)) {
      setTrustNodeId(undefined);
      setCurrentTab('overview');
    }
  }, [currentTab, role, hasPermission, isAuthenticated]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400 font-mono text-sm">
        <div className="flex items-center gap-3">
          <div className="w-4 h-4 border-2 border-teal-500 border-t-transparent rounded-full animate-spin" />
          <span>Connecting to FogTrust Broker...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginModal />;
  }

  // Never render a tab the current role cannot access, even for the single
  // render before the effect below resets `currentTab`.
  const effectiveTab: NavTab = isTabAllowed(currentTab, role, hasPermission) ? currentTab : 'overview';

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 font-sans selection:bg-teal-500/30 selection:text-teal-200">
      <Navbar />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar currentTab={effectiveTab} onSelectTab={handleSelectTab} />

        <main className="flex-1 overflow-y-auto p-6 lg:p-8 bg-slate-900/30">
          <div className="max-w-7xl mx-auto">
            {effectiveTab === 'overview' && <OverviewView onNavigate={handleNavigate} />}
            {effectiveTab === 'nodes' && <NodesView onNavigate={handleNavigate} />}
            {effectiveTab === 'trust' && (
              <TrustView initialNodeId={trustNodeId} onNavigate={handleNavigate} />
            )}
            {effectiveTab === 'tokens' && <EnrollmentTokensView />}
            {effectiveTab === 'evidence' && <EvidenceView />}
            {effectiveTab === 'tasks' && <TasksView />}
            {effectiveTab === 'audit' && <AuditLogView />}
            {effectiveTab === 'policy' && <PolicyView onNavigate={handleNavigate} />}
            {effectiveTab === 'settings' && <AdminSettingsView />}
            {effectiveTab === 'users' && <UsersView />}
            {effectiveTab === 'reports' && <ReportsView />}
          </div>
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return <AppContent />;
};

export default App;

