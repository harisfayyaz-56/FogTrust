import React from 'react';
import {
  LayoutDashboard,
  Server,
  Activity,
  KeyRound,
  FileCheck2,
  ListTodo,
  ShieldAlert,
  Sliders,
  Cog,
  Users,
  FileSpreadsheet,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export type NavTab =
  | 'overview'
  | 'nodes'
  | 'trust'
  | 'tokens'
  | 'evidence'
  | 'tasks'
  | 'audit'
  | 'policy'
  | 'settings'
  | 'users'
  | 'reports';

export interface NavItem {
  id: NavTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  permission?: string;
  adminOnly?: boolean;
  description: string;
}

export const NAV_ITEMS: NavItem[] = [
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
    id: 'trust',
    label: 'Trust Scores',
    icon: Activity,
    permission: 'trust.view',
    description: 'Score history and per-rule explanations',
  },
  {
    id: 'tokens',
    label: 'Enrollment Tokens',
    icon: KeyRound,
    permission: 'tokens.manage',
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
    id: 'settings',
    label: 'Admin Settings',
    icon: Cog,
    permission: 'policy.change',
    adminOnly: true,
    description: 'Edit trust threshold and rule weights',
  },
  {
    id: 'users',
    label: 'User Management',
    icon: Users,
    permission: 'users.manage',
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

/**
 * Single source of truth for tab visibility and routing guards. A tab is only
 * exposed when the current role has both the admin gate (if any) and the
 * required permission. Restricted tabs are hidden, not merely disabled.
 */
export function isTabAllowed(
  tab: NavTab,
  role: string,
  hasPermission: (permission: string) => boolean
): boolean {
  const item = NAV_ITEMS.find((entry) => entry.id === tab);
  if (!item) return false;
  if (item.adminOnly && role !== 'admin') return false;
  if (item.permission && !hasPermission(item.permission)) return false;
  return true;
}

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const { role, hasPermission } = useAuth();
  const visibleItems = NAV_ITEMS.filter((item) => isTabAllowed(item.id, role, hasPermission));

  return (
    <aside className="w-56 border-r border-slate-800 bg-slate-900/60 flex flex-col justify-between p-3 shrink-0">
      <div className="space-y-0.5">
        <div className="px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500 font-mono">
          Navigation
        </div>

        {visibleItems.map((item) => {
          const isActive = currentTab === item.id;
          const Icon = item.icon;

          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center px-2.5 py-2 rounded text-xs font-medium transition-colors ${
                isActive
                  ? 'bg-slate-800 text-slate-100 font-semibold'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 ${isActive ? 'text-slate-200' : 'text-slate-500'}`} />
                <span className="truncate">{item.label}</span>
              </div>
            </button>
          );
        })}
      </div>

      <div className="p-2.5 text-[10px] text-slate-500 border-t border-slate-800 font-mono">
        v0.1.0 • broker-ui
      </div>
    </aside>
  );
};
