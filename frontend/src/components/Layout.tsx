import { Shield, Activity, Search, BarChart3, Users, Settings } from 'lucide-react';
import type { ReactNode } from 'react';
import { UserMenu } from './UserMenu';
import { useAuth } from '../contexts/AuthContext';

interface LayoutProps {
  children: ReactNode;
  activePage: string;
  onNavigate: (page: string) => void;
}

export function Layout({ children, activePage, onNavigate }: LayoutProps) {
  const { user } = useAuth();

  const navItems = [
    { label: 'Dashboard', icon: BarChart3, id: 'dashboard' },
    { label: 'Analyze', icon: Search, id: 'analyze' },
    { label: 'Threat Feed', icon: Activity, id: 'feed' },
    // Admin-only nav items
    ...(user?.role === 'admin'
      ? [
          { label: 'Users', icon: Users, id: 'users' },
          { label: 'Settings', icon: Settings, id: 'settings' },
        ]
      : []),
  ];

  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <aside className="w-64 flex flex-col" style={{ backgroundColor: 'var(--bg-secondary)', borderRight: '1px solid var(--border)' }}>
        <div className="p-6 flex items-center gap-3">
          <Shield className="w-8 h-8" style={{ color: 'var(--accent)' }} />
          <div>
            <h1 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
              ThreatAnalyst
            </h1>
            <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
              AI-Powered CTI
            </p>
          </div>
        </div>

        <nav className="flex-1 px-3">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className="w-full flex items-center gap-3 px-4 py-3 rounded-lg mb-1 text-sm font-medium transition-colors cursor-pointer"
              style={{
                backgroundColor: activePage === item.id ? 'rgba(59,130,246,0.15)' : 'transparent',
                color: activePage === item.id ? 'var(--accent)' : 'var(--text-secondary)',
                border: 'none',
              }}
            >
              <item.icon className="w-5 h-5" />
              {item.label}
            </button>
          ))}
        </nav>

        <UserMenu />

        <div className="p-4 mx-3 mb-3 rounded-lg text-xs" style={{ backgroundColor: 'var(--bg-primary)', color: 'var(--text-secondary)' }}>
          <p className="font-medium mb-1" style={{ color: 'var(--text-primary)' }}>Foundation-Sec-8B</p>
          <p>Reasoning Q4_K_M via Ollama</p>
          <p className="mt-1 opacity-60">v{__APP_VERSION__}</p>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto p-6" style={{ backgroundColor: 'var(--bg-primary)' }}>
        {children}
      </main>
    </div>
  );
}
