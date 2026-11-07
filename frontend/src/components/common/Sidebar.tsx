import React from 'react';
import {
  LayoutDashboard,
  Server,
  KeyRound,
  FileCheck2,
  ListTodo,
  ShieldAlert,
  Sliders,
  Users,
  FileSpreadsheet,
  Lock,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export type NavTab =
  | 'overview'
  | 'nodes'
  | 'tokens'
  | 'evidence'
  | 'tasks'
  | 'audit'
  | 'policy'
  | 'users'
  | 'reports';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const { role, hasPermission } = useAuth();

  const navItems: Array<{
    id: NavTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    permission?: string;
    adminOnly?: boolean;
    description: string;
  }> = [
    {
      id: 'overview',
      label: 'Overview',
      icon: LayoutDashboard,
      description: 'System health & operational metrics',
    },
    {
      id: 'nodes',
      label: 'Edge Nodes',
      icon: Server,
      permission: 'nodes.view',
      description: 'Enrolled nodes, load, and revocation',
    },
    {
      id: 'tokens',
      label: 'Enrollment Tokens',
      icon: KeyRound,
      permission: 'tokens.view',
      adminOnly: true,
      description: 'One-time registration tokens (FR-1)',
    },
    {
      id: 'evidence',
      label: 'Evidence & Decisions',
      icon: FileCheck2,
      permission: 'decisions.view',
      description: 'Explainable security decisions (FR-7)',
    },
    {
      id: 'tasks',
      label: 'Task Queue',
      icon: ListTodo,
      permission: 'tasks.view',
      description: 'Dispatched tasks & encrypted results',
    },
    {
      id: 'audit',
      label: 'Audit & Hash Chain',
      icon: ShieldAlert,
      permission: 'audit.view',
      adminOnly: true,
      description: 'Append-only tamper-evident log (M1)',
    },
    {
      id: 'policy',
      label: 'Trust Policy',
      icon: Sliders,
      permission: 'policy.view',
      description: 'Rule weights & admission thresholds',
    },
    {
      id: 'users',
      label: 'User Management',
      icon: Users,
      permission: 'users.view',
      adminOnly: true,
      description: 'Accounts, roles, & access levels',
    },
    {
      id: 'reports',
      label: 'Sanitized Reports',
      icon: FileSpreadsheet,
      permission: 'reports.export',
      description: 'Zero-secret exports for audits',
    },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-900/50 flex flex-col justify-between p-4 shrink-0">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500 font-mono">
          Broker Navigation
        </div>

        {navItems.map((item) => {
          const isAllowed = !item.adminOnly || role === 'admin' || (item.permission && hasPermission(item.permission));
          const isActive = currentTab === item.id;
          const Icon = item.icon;

          return (
            <button
              key={item.id}
              onClick={() => {
                if (isAllowed) {
                  onSelectTab(item.id);
                }
              }}
              disabled={!isAllowed}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-teal-500/15 text-teal-300 border border-teal-500/30 shadow-sm'
                  : isAllowed
                  ? 'text-slate-300 hover:bg-slate-800 hover:text-slate-100'
                  : 'text-slate-600 cursor-not-allowed opacity-60'
              }`}
              title={isAllowed ? item.description : 'Requires Administrator or elevated privileges'}
            >
              <div className="flex items-center gap-2.5">
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? 'text-teal-400' : isAllowed ? 'text-slate-400' : 'text-slate-600'
                  }`}
                />
                <span className="truncate">{item.label}</span>
              </div>

              {!isAllowed && (
                <span title="Server role restricted">
                  <Lock className="w-3.5 h-3.5 text-slate-600" />
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Security reminder badge at bottom */}
      <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 text-[11px] text-slate-400 space-y-1">
        <div className="flex items-center gap-1.5 text-teal-400 font-semibold font-mono text-[10px] uppercase">
          <span>Security Notice</span>
        </div>
        <p className="leading-relaxed text-slate-400">
          Server enforces all access controls. The UI hides restricted controls as a convenience only.
        </p>
      </div>
    </aside>
  );
};
