import React, { useEffect, useState } from 'react';
import {
  Users,
  Plus,
  Shield,
  UserCheck,
  UserX,
  Edit2,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { getUsers, createUser, updateUser } from '../../services/api';
import { User, UserRole } from '../../types/api';
import { Badge } from '../common/Badge';
import { Modal } from '../common/Modal';
import { EmptyState, ErrorState, LoadingState } from '../common/ViewState';

export const UsersView: React.FC = () => {
  const { isDemoMode, currentUser } = useAuth();
  const [userList, setUserList] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [roleFilter, setRoleFilter] = useState<string>('');

  // Create User Modal
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(false);
  const [newUsername, setNewUsername] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [newRole, setNewRole] = useState<UserRole>('viewer');
  const [createError, setCreateError] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState<boolean>(false);

  // Edit User Modal
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [editRole, setEditRole] = useState<UserRole>('viewer');
  const [editActive, setEditActive] = useState<boolean>(true);
  const [editError, setEditError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState<boolean>(false);

  const fetchUsers = async () => {
    setIsLoading(true);
    setLoadError(null);
    try {
      const res = await getUsers(roleFilter || undefined, isDemoMode);
      setUserList(res.results || []);
    } catch (err: unknown) {
      setUserList([]);
      setLoadError(err instanceof Error ? err.message : 'Could not load user accounts.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [isDemoMode, roleFilter]);

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsCreating(true);
    setCreateError(null);

    try {
      if (isDemoMode) {
        const newUser: User = {
          id: Date.now(),
          username: newUsername,
          role: newRole,
          is_active: true,
          date_joined: new Date().toISOString(),
        };
        setUserList([...userList, newUser]);
      } else {
        await createUser({
          username: newUsername,
          password: newPassword,
          role: newRole,
        });
        await fetchUsers();
      }

      setIsCreateOpen(false);
      setNewUsername('');
      setNewPassword('');
      setNewRole('viewer');
    } catch (err: any) {
      setCreateError(err.message || 'User creation failed');
    } finally {
      setIsCreating(false);
    }
  };

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;

    // Self-lockout check (ID-14)
    if (selectedUser.username === currentUser?.username) {
      if (editRole !== 'admin' || !editActive) {
        setEditError('Lockout Protection: An administrator cannot remove their own admin role or disable themselves (409 CONFLICT).');
        return;
      }
    }

    setIsSaving(true);
    setEditError(null);

    try {
      if (isDemoMode) {
        setUserList((prev) =>
          prev.map((u) =>
            u.id === selectedUser.id ? { ...u, role: editRole, is_active: editActive } : u
          )
        );
      } else {
        await updateUser(selectedUser.id, {
          role: editRole,
          is_active: editActive,
        });
        await fetchUsers();
      }

      setSelectedUser(null);
    } catch (err: any) {
      setEditError(err.message || 'Failed to update user');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Users className="w-5 h-5 text-teal-400" />
            Human User & Role Management
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Administers console user accounts and role assignments. Server enforces capabilities per route.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchUsers}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white text-xs font-medium"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => {
              setIsCreateOpen(true);
              setCreateError(null);
            }}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors shadow-sm"
          >
            <Plus className="w-4 h-4" />
            <span>Add User</span>
          </button>
        </div>
      </div>

      {/* Filter toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span>Filter Role:</span>
          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-teal-500"
          >
            <option value="">All Roles</option>
            <option value="admin">Administrators</option>
            <option value="operator">Operators</option>
            <option value="viewer">Viewers</option>
          </select>
        </div>

        <div className="text-xs text-slate-500 font-mono">
          Lockout Rule: Self-demotion or self-disable is rejected by server with 409 CONFLICT.
        </div>
      </div>

      {/* Users Table */}
      {loadError ? (
        <ErrorState title="Could not load user accounts" message={loadError} onRetry={fetchUsers} />
      ) : isLoading ? (
        <LoadingState label="Loading user accounts…" />
      ) : userList.length === 0 ? (
        <EmptyState
          title="No user accounts found"
          description={
            roleFilter
              ? 'No accounts match this role filter. Try selecting a different role.'
              : 'Create the first console user account to grant access to the broker.'
          }
          icon={<Users className="w-5 h-5" />}
        />
      ) : (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                <tr>
                  <th className="py-3 px-4">Username</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Joined At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {userList.map((user) => {
                  const isCurrent = user.username === currentUser?.username;
                  return (
                    <tr key={user.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3.5 px-4 font-mono font-medium text-slate-200 flex items-center gap-2">
                        <span>{user.username}</span>
                        {isCurrent && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-teal-950 text-teal-400 border border-teal-800 font-mono">
                            You
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge label={user.role} />
                      </td>
                      <td className="py-3.5 px-4">
                        {user.is_active ? (
                          <span className="text-emerald-400 flex items-center gap-1 font-mono text-[11px]">
                            <UserCheck className="w-3.5 h-3.5" /> Active
                          </span>
                        ) : (
                          <span className="text-rose-400 flex items-center gap-1 font-mono text-[11px]">
                            <UserX className="w-3.5 h-3.5" /> Disabled
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        {user.date_joined ? new Date(user.date_joined).toLocaleDateString() : 'N/A'}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => {
                            setSelectedUser(user);
                            setEditRole(user.role);
                            setEditActive(user.is_active);
                            setEditError(null);
                          }}
                          className="px-2.5 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs text-slate-300 transition-colors inline-flex items-center gap-1"
                        >
                          <Edit2 className="w-3 h-3" />
                          <span>Edit</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create User Modal */}
      {isCreateOpen && (
        <Modal
          isOpen={isCreateOpen}
          onClose={() => setIsCreateOpen(false)}
          title="Create New User Account"
        >
          <form onSubmit={handleCreateSubmit} className="space-y-4">
            {createError && (
              <div className="p-2.5 rounded bg-rose-900/50 border border-rose-700 text-rose-200 text-xs">
                {createError}
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Username (3-150 alphanumeric):
              </label>
              <input
                type="text"
                required
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="e.g. operator2"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-teal-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Password:
              </label>
              <input
                type="password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-teal-500"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Must be at least 10 characters and satisfy Django password validation.
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Role (defaults to least privilege: viewer):
              </label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as UserRole)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-teal-500"
              >
                <option value="viewer">Viewer (Read-only)</option>
                <option value="operator">Operator (Task Dispatch & Report Export)</option>
                <option value="admin">Administrator (Full Access & Revocation)</option>
              </select>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsCreateOpen(false)}
                className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isCreating}
                className="px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors"
              >
                {isCreating ? 'Creating...' : 'Create User'}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* Edit User Modal */}
      {selectedUser && (
        <Modal
          isOpen={!!selectedUser}
          onClose={() => setSelectedUser(null)}
          title={`Edit Account: ${selectedUser.username}`}
        >
          <form onSubmit={handleEditSubmit} className="space-y-4">
            {editError && (
              <div className="p-2.5 rounded bg-rose-900/50 border border-rose-700 text-rose-200 text-xs">
                {editError}
              </div>
            )}

            {selectedUser.username === currentUser?.username && (
              <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800 flex items-start gap-2.5 text-xs text-amber-200">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <p>
                  You are editing your own current logged in account. Self-demotion or disabling yourself
                  is rejected with 409 CONFLICT to prevent administrator lock-out (ID-14).
                </p>
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Role Assignment:</label>
              <select
                value={editRole}
                onChange={(e) => setEditRole(e.target.value as UserRole)}
                disabled={selectedUser.username === currentUser?.username}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 disabled:opacity-50"
              >
                <option value="viewer">Viewer</option>
                <option value="operator">Operator</option>
                <option value="admin">Administrator</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Account Active Status:</label>
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 text-xs text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={editActive}
                    onChange={(e) => setEditActive(e.target.checked)}
                    disabled={selectedUser.username === currentUser?.username}
                    className="accent-teal-500 rounded"
                  />
                  <span>Active (User can log in and issue commands)</span>
                </label>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setSelectedUser(null)}
                className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSaving}
                className="px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium transition-colors"
              >
                {isSaving ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

