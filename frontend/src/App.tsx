import React, { useState } from 'react';
import { useAuth } from './context/AuthContext';
import { Navbar } from './components/common/Navbar';
import { Sidebar, NavTab } from './components/common/Sidebar';
import { LoginModal } from './components/LoginModal';
import { OverviewView } from './components/views/OverviewView';
import { NodesView } from './components/views/NodesView';
import { EnrollmentTokensView } from './components/views/EnrollmentTokensView';
import { EvidenceView } from './components/views/EvidenceView';
import { TasksView } from './components/views/TasksView';
import { AuditLogView } from './components/views/AuditLogView';
import { PolicyView } from './components/views/PolicyView';
import { UsersView } from './components/views/UsersView';
import { ReportsView } from './components/views/ReportsView';

export const AppContent: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();
  const [currentTab, setCurrentTab] = useState<NavTab>('overview');

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

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 font-sans selection:bg-teal-500/30 selection:text-teal-200">
      <Navbar />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />

        <main className="flex-1 overflow-y-auto p-6 lg:p-8 bg-slate-900/30">
          <div className="max-w-7xl mx-auto">
            {currentTab === 'overview' && <OverviewView onNavigate={(t) => setCurrentTab(t as NavTab)} />}
            {currentTab === 'nodes' && <NodesView />}
            {currentTab === 'tokens' && <EnrollmentTokensView />}
            {currentTab === 'evidence' && <EvidenceView />}
            {currentTab === 'tasks' && <TasksView />}
            {currentTab === 'audit' && <AuditLogView />}
            {currentTab === 'policy' && <PolicyView />}
            {currentTab === 'users' && <UsersView />}
            {currentTab === 'reports' && <ReportsView />}
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

