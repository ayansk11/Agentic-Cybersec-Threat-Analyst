import { useState, useCallback } from 'react';
import { Layout } from './components/Layout';
import { Dashboard } from './components/Dashboard';
import { AnalysisView } from './components/AnalysisView';
import { ThreatFeed } from './components/ThreatFeed';
import { AdminUsersPage } from './components/AdminUsersPage';
import { SettingsPage } from './components/SettingsPage';
import { LoginPage } from './components/LoginPage';
import { useAuth } from './contexts/AuthContext';
import { resendVerification } from './api/client';
import { Shield, Loader2, AlertTriangle } from 'lucide-react';

function VerificationBanner({ email }: { email: string }) {
  const [sent, setSent] = useState(false);
  const handleResend = async () => {
    await resendVerification(email);
    setSent(true);
  };
  return (
    <div
      className="flex items-center justify-between px-4 py-2 text-sm"
      style={{ backgroundColor: 'rgba(234,179,8,0.15)', color: 'var(--medium)' }}
    >
      <div className="flex items-center gap-2">
        <AlertTriangle className="w-4 h-4" />
        <span>Email not verified. Check your inbox for a verification link.</span>
      </div>
      {!sent ? (
        <button
          onClick={handleResend}
          className="px-3 py-1 rounded text-xs font-medium cursor-pointer"
          style={{ backgroundColor: 'rgba(234,179,8,0.2)', color: 'var(--medium)', border: 'none' }}
        >
          Resend
        </button>
      ) : (
        <span className="text-xs">Sent!</span>
      )}
    </div>
  );
}

function App() {
  const { isAuthenticated, isLoading, user } = useAuth();
  const [page, setPage] = useState('analyze');
  const [prefillCveId, setPrefillCveId] = useState('');

  const handleAnalyzeFromFeed = useCallback((cveId: string) => {
    setPrefillCveId(cveId);
    setPage('analyze');
  }, []);

  const handleNavigate = useCallback((newPage: string) => {
    if (newPage !== 'analyze') {
      setPrefillCveId('');
    }
    setPage(newPage);
  }, []);

  // Loading state during initial auth check
  if (isLoading) {
    return (
      <div
        className="min-h-screen flex flex-col items-center justify-center gap-4"
        style={{ backgroundColor: 'var(--bg-primary)' }}
      >
        <Shield className="w-12 h-12" style={{ color: 'var(--accent)' }} />
        <Loader2
          className="w-6 h-6 animate-spin"
          style={{ color: 'var(--text-secondary)' }}
        />
      </div>
    );
  }

  // Not authenticated: show login page
  if (!isAuthenticated) {
    return <LoginPage />;
  }

  // Authenticated: show main app
  const showVerificationBanner = user && user.id !== 0 && !user.email_verified;

  return (
    <div className="flex flex-col h-screen">
      {showVerificationBanner && <VerificationBanner email={user.email} />}
      <div className="flex-1 min-h-0">
        <Layout activePage={page} onNavigate={handleNavigate}>
          {page === 'dashboard' && <Dashboard />}
          {page === 'analyze' && <AnalysisView prefillCveId={prefillCveId} onPrefillConsumed={() => setPrefillCveId('')} />}
          {page === 'feed' && <ThreatFeed onAnalyze={handleAnalyzeFromFeed} />}
          {page === 'users' && <AdminUsersPage />}
          {page === 'settings' && <SettingsPage />}
        </Layout>
      </div>
    </div>
  );
}

export default App;
