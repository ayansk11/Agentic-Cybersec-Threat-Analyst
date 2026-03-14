import { LogOut, ShieldCheck, User } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export function UserMenu() {
  const { user, logout } = useAuth();

  if (!user) return null;

  return (
    <div
      className="p-4 mx-3 mb-3 rounded-lg"
      style={{
        backgroundColor: 'var(--bg-primary)',
        border: '1px solid var(--border)',
      }}
    >
      <div className="flex items-center gap-3 mb-3">
        <div
          className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
          style={{ backgroundColor: 'rgba(59,130,246,0.2)' }}
        >
          <User className="w-4 h-4" style={{ color: 'var(--accent)' }} />
        </div>
        <div className="min-w-0 flex-1">
          <p
            className="text-sm font-medium truncate"
            style={{ color: 'var(--text-primary)' }}
          >
            {user.username}
          </p>
          <p
            className="text-xs truncate"
            style={{ color: 'var(--text-secondary)' }}
          >
            {user.email}
          </p>
        </div>
      </div>

      <div className="flex items-center justify-between">
        <span
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
          style={{
            backgroundColor:
              user.role === 'admin'
                ? 'rgba(139,92,246,0.15)'
                : 'rgba(59,130,246,0.15)',
            color:
              user.role === 'admin' ? '#a78bfa' : 'var(--accent)',
          }}
        >
          <ShieldCheck className="w-3 h-3" />
          {user.role === 'admin' ? 'Admin' : 'Analyst'}
        </span>

        <button
          onClick={logout}
          className="flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors cursor-pointer"
          style={{
            color: 'var(--text-secondary)',
            backgroundColor: 'transparent',
            border: 'none',
          }}
          title="Sign out"
        >
          <LogOut className="w-3 h-3" />
          Sign out
        </button>
      </div>
    </div>
  );
}
