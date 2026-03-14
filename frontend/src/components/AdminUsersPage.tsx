import { useState, useEffect, useCallback } from 'react';
import { Users, ShieldCheck, ShieldOff, RefreshCw, AlertCircle, Search } from 'lucide-react';
import { fetchUsers, updateUser, type UserResponse } from '../api/client';
import { useAuth } from '../contexts/AuthContext';

export function AdminUsersPage() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<UserResponse[]>([]);
  const [count, setCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [updating, setUpdating] = useState<number | null>(null);

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await fetchUsers(200, 0);
      setUsers(data.users);
      setCount(data.count);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  const handleToggleRole = async (user: UserResponse) => {
    if (user.id === currentUser?.id) return;
    setUpdating(user.id);
    try {
      const newRole = user.role === 'admin' ? 'analyst' : 'admin';
      const updated = await updateUser(user.id, { role: newRole });
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role');
    } finally {
      setUpdating(null);
    }
  };

  const handleToggleActive = async (user: UserResponse) => {
    if (user.id === currentUser?.id) return;
    setUpdating(user.id);
    try {
      const updated = await updateUser(user.id, { is_active: !user.is_active });
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update status');
    } finally {
      setUpdating(null);
    }
  };

  const filtered = search
    ? users.filter(
        (u) =>
          u.username.toLowerCase().includes(search.toLowerCase()) ||
          u.email.toLowerCase().includes(search.toLowerCase()),
      )
    : users;

  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Users className="w-6 h-6" style={{ color: 'var(--accent)' }} />
          <div>
            <h2 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
              User Management
            </h2>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              {count} registered user{count !== 1 ? 's' : ''}
            </p>
          </div>
        </div>
        <button
          onClick={loadUsers}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors cursor-pointer"
          style={{
            backgroundColor: 'var(--bg-secondary)',
            color: 'var(--text-secondary)',
            border: '1px solid var(--border)',
          }}
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Search */}
      <div className="relative mb-4">
        <Search
          className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
          style={{ color: 'var(--text-secondary)' }}
        />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by name or email..."
          className="w-full pl-10 pr-4 py-2.5 rounded-lg text-sm outline-none"
          style={{
            backgroundColor: 'var(--bg-secondary)',
            color: 'var(--text-primary)',
            border: '1px solid var(--border)',
          }}
        />
      </div>

      {/* Error */}
      {error && (
        <div
          className="flex items-center gap-2 p-3 rounded-lg mb-4 text-sm"
          style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: 'var(--critical)' }}
        >
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Table */}
      <div
        className="rounded-xl overflow-hidden"
        style={{ border: '1px solid var(--border)', backgroundColor: 'var(--bg-card)' }}
      >
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['User', 'Role', 'Provider', 'Status', 'Joined', 'Actions'].map((h) => (
                <th
                  key={h}
                  className="text-left px-4 py-3 font-medium text-xs uppercase tracking-wider"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && !users.length ? (
              <tr>
                <td colSpan={6} className="text-center py-12" style={{ color: 'var(--text-secondary)' }}>
                  Loading users...
                </td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-12" style={{ color: 'var(--text-secondary)' }}>
                  {search ? 'No users match your search' : 'No users found'}
                </td>
              </tr>
            ) : (
              filtered.map((u) => {
                const isSelf = u.id === currentUser?.id;
                return (
                  <tr
                    key={u.id}
                    style={{ borderBottom: '1px solid var(--border)' }}
                  >
                    {/* User info */}
                    <td className="px-4 py-3">
                      <div>
                        <p className="font-medium" style={{ color: 'var(--text-primary)' }}>
                          {u.username}
                          {isSelf && (
                            <span
                              className="ml-2 text-xs px-1.5 py-0.5 rounded"
                              style={{ backgroundColor: 'rgba(59,130,246,0.15)', color: 'var(--accent)' }}
                            >
                              you
                            </span>
                          )}
                        </p>
                        <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                          {u.email}
                        </p>
                      </div>
                    </td>

                    {/* Role badge */}
                    <td className="px-4 py-3">
                      <span
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
                        style={{
                          backgroundColor:
                            u.role === 'admin' ? 'rgba(139,92,246,0.15)' : 'rgba(59,130,246,0.15)',
                          color: u.role === 'admin' ? '#a78bfa' : 'var(--accent)',
                        }}
                      >
                        <ShieldCheck className="w-3 h-3" />
                        {u.role === 'admin' ? 'Admin' : 'Analyst'}
                      </span>
                    </td>

                    {/* OAuth provider */}
                    <td className="px-4 py-3" style={{ color: 'var(--text-secondary)' }}>
                      {u.oauth_provider || 'local'}
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1">
                        <div>
                          <span
                            className="inline-block w-2 h-2 rounded-full mr-2"
                            style={{ backgroundColor: u.is_active ? 'var(--low)' : 'var(--critical)' }}
                          />
                          <span style={{ color: u.is_active ? 'var(--low)' : 'var(--critical)' }}>
                            {u.is_active ? 'Active' : 'Disabled'}
                          </span>
                        </div>
                        {!u.email_verified && (
                          <span className="text-xs" style={{ color: 'var(--medium)' }}>
                            Unverified email
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Joined */}
                    <td className="px-4 py-3" style={{ color: 'var(--text-secondary)' }}>
                      {new Date(u.created_at).toLocaleDateString()}
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3">
                      {isSelf ? (
                        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>—</span>
                      ) : (
                        <div className="flex gap-2">
                          <button
                            onClick={() => handleToggleRole(u)}
                            disabled={updating === u.id}
                            className="px-2 py-1 rounded text-xs transition-colors cursor-pointer"
                            style={{
                              backgroundColor: 'rgba(139,92,246,0.1)',
                              color: '#a78bfa',
                              border: 'none',
                              opacity: updating === u.id ? 0.5 : 1,
                            }}
                            title={u.role === 'admin' ? 'Demote to Analyst' : 'Promote to Admin'}
                          >
                            {u.role === 'admin' ? 'Demote' : 'Promote'}
                          </button>
                          <button
                            onClick={() => handleToggleActive(u)}
                            disabled={updating === u.id}
                            className="px-2 py-1 rounded text-xs transition-colors cursor-pointer"
                            style={{
                              backgroundColor: u.is_active
                                ? 'rgba(239,68,68,0.1)'
                                : 'rgba(34,197,94,0.1)',
                              color: u.is_active ? 'var(--critical)' : 'var(--low)',
                              border: 'none',
                              opacity: updating === u.id ? 0.5 : 1,
                            }}
                            title={u.is_active ? 'Disable account' : 'Enable account'}
                          >
                            {u.is_active ? (
                              <span className="flex items-center gap-1"><ShieldOff className="w-3 h-3" />Disable</span>
                            ) : (
                              <span className="flex items-center gap-1"><ShieldCheck className="w-3 h-3" />Enable</span>
                            )}
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
