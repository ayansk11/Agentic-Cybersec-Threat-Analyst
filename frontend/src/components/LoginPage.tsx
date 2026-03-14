import { useState, useEffect } from 'react';
import { Shield, Mail, Lock, User, AlertCircle, CheckCircle2, ArrowLeft, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { forgotPassword, resetPassword, verifyEmail, fetchAuthProviders, type AuthProvidersResponse } from '../api/client';

type Mode = 'login' | 'register' | 'forgot' | 'reset' | 'verify-email';

export function LoginPage() {
  const { login, register, oauthLogin } = useAuth();
  const [mode, setMode] = useState<Mode>('login');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [providers, setProviders] = useState<AuthProvidersResponse | null>(null);
  const [showPassword, setShowPassword] = useState(false);

  // Load available auth providers
  useEffect(() => {
    fetchAuthProviders().then(setProviders).catch(() => {});
  }, []);

  // Check URL for verify-email or reset-password tokens
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const vToken = params.get('verify_token');
    const rToken = params.get('reset_token');
    if (vToken) {
      setMode('verify-email');
      // Auto-verify
      verifyEmail(vToken)
        .then(() => setSuccess('Email verified successfully! You can now sign in.'))
        .catch((err) => setError(err instanceof Error ? err.message : 'Verification failed'));
      // Clean URL
      window.history.replaceState({}, '', window.location.pathname);
    } else if (rToken) {
      setResetToken(rToken);
      setMode('reset');
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      if (mode === 'register') {
        await register(email, username, password);
      } else if (mode === 'login') {
        await login(email, password);
      } else if (mode === 'forgot') {
        await forgotPassword(email);
        setSuccess('If an account exists with that email, a reset link has been sent. Check the server logs for the token.');
      } else if (mode === 'reset') {
        await resetPassword(resetToken, password);
        setSuccess('Password reset successfully! You can now sign in.');
        setTimeout(() => { setMode('login'); setSuccess(''); }, 2000);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Operation failed');
    } finally {
      setLoading(false);
    }
  };

  const switchMode = (newMode: Mode) => {
    setMode(newMode);
    setError('');
    setSuccess('');
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{ backgroundColor: 'var(--bg-primary)' }}
    >
      <div
        className="w-full max-w-md rounded-2xl p-8 shadow-xl"
        style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border)',
        }}
      >
        {/* Logo */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <Shield className="w-10 h-10" style={{ color: 'var(--accent)' }} />
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
              ThreatAnalyst
            </h1>
            <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
              AI-Powered Cyber Threat Intelligence
            </p>
          </div>
        </div>

        {/* Back button for sub-modes */}
        {(mode === 'forgot' || mode === 'reset' || mode === 'verify-email') && (
          <button
            onClick={() => switchMode('login')}
            className="flex items-center gap-1 mb-4 text-sm cursor-pointer"
            style={{ color: 'var(--accent)', backgroundColor: 'transparent', border: 'none' }}
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Sign In
          </button>
        )}

        {/* Tab toggle (login/register only) */}
        {(mode === 'login' || mode === 'register') && (
          <div
            className="flex rounded-lg mb-6 p-1"
            style={{ backgroundColor: 'var(--bg-primary)' }}
          >
            <button
              onClick={() => switchMode('login')}
              className="flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors cursor-pointer"
              style={{
                backgroundColor: mode === 'login' ? 'var(--accent)' : 'transparent',
                color: mode === 'login' ? '#fff' : 'var(--text-secondary)',
                border: 'none',
              }}
            >
              Sign In
            </button>
            <button
              onClick={() => switchMode('register')}
              className="flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors cursor-pointer"
              style={{
                backgroundColor: mode === 'register' ? 'var(--accent)' : 'transparent',
                color: mode === 'register' ? '#fff' : 'var(--text-secondary)',
                border: 'none',
              }}
            >
              Register
            </button>
          </div>
        )}

        {/* Headings for sub-modes */}
        {mode === 'forgot' && (
          <h2 className="text-lg font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
            Reset Password
          </h2>
        )}
        {mode === 'reset' && (
          <h2 className="text-lg font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
            Set New Password
          </h2>
        )}
        {mode === 'verify-email' && (
          <h2 className="text-lg font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
            Email Verification
          </h2>
        )}

        {/* Success message */}
        {success && (
          <div
            className="flex items-center gap-2 p-3 rounded-lg mb-4 text-sm"
            style={{ backgroundColor: 'rgba(34,197,94,0.1)', color: 'var(--low)' }}
          >
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            {success}
          </div>
        )}

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

        {/* Verify email mode - no form, just status */}
        {mode === 'verify-email' && !success && !error && (
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            Verifying your email...
          </p>
        )}

        {/* Forms */}
        {mode !== 'verify-email' && (
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email field (login, register, forgot) */}
            {(mode === 'login' || mode === 'register' || mode === 'forgot') && (
              <div>
                <label
                  className="block text-sm font-medium mb-1.5"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Email
                </label>
                <div className="relative">
                  <Mail
                    className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
                    style={{ color: 'var(--text-secondary)' }}
                  />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com"
                    className="w-full pl-10 pr-4 py-2.5 rounded-lg text-sm outline-none"
                    style={{
                      backgroundColor: 'var(--bg-primary)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border)',
                    }}
                  />
                </div>
              </div>
            )}

            {/* Username (register only) */}
            {mode === 'register' && (
              <div>
                <label
                  className="block text-sm font-medium mb-1.5"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Username
                </label>
                <div className="relative">
                  <User
                    className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
                    style={{ color: 'var(--text-secondary)' }}
                  />
                  <input
                    type="text"
                    required
                    minLength={2}
                    maxLength={50}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Your name"
                    className="w-full pl-10 pr-4 py-2.5 rounded-lg text-sm outline-none"
                    style={{
                      backgroundColor: 'var(--bg-primary)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border)',
                    }}
                  />
                </div>
              </div>
            )}

            {/* Reset token (reset mode) */}
            {mode === 'reset' && !resetToken && (
              <div>
                <label
                  className="block text-sm font-medium mb-1.5"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Reset Token
                </label>
                <input
                  type="text"
                  required
                  value={resetToken}
                  onChange={(e) => setResetToken(e.target.value)}
                  placeholder="Paste your reset token"
                  className="w-full px-4 py-2.5 rounded-lg text-sm outline-none"
                  style={{
                    backgroundColor: 'var(--bg-primary)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border)',
                  }}
                />
              </div>
            )}

            {/* Password (login, register, reset) */}
            {(mode === 'login' || mode === 'register' || mode === 'reset') && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label
                    className="block text-sm font-medium"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    {mode === 'reset' ? 'New Password' : 'Password'}
                  </label>
                  {mode === 'login' && (
                    <button
                      type="button"
                      onClick={() => switchMode('forgot')}
                      className="text-xs cursor-pointer"
                      style={{ color: 'var(--accent)', backgroundColor: 'transparent', border: 'none' }}
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <div className="relative">
                  <Lock
                    className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
                    style={{ color: 'var(--text-secondary)' }}
                  />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    minLength={8}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={mode === 'register' || mode === 'reset' ? 'Min. 8 characters' : 'Your password'}
                    className="w-full pl-10 pr-10 py-2.5 rounded-lg text-sm outline-none"
                    style={{
                      backgroundColor: 'var(--bg-primary)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border)',
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 cursor-pointer"
                    style={{ backgroundColor: 'transparent', border: 'none', padding: 0 }}
                    tabIndex={-1}
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
                    ) : (
                      <Eye className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
                    )}
                  </button>
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg text-sm font-medium transition-opacity cursor-pointer"
              style={{
                backgroundColor: 'var(--accent)',
                color: '#fff',
                border: 'none',
                opacity: loading ? 0.7 : 1,
              }}
            >
              {loading
                ? 'Please wait...'
                : mode === 'login'
                  ? 'Sign In'
                  : mode === 'register'
                    ? 'Create Account'
                    : mode === 'forgot'
                      ? 'Send Reset Link'
                      : 'Reset Password'}
            </button>

            {/* Forgot password hint */}
            {mode === 'forgot' && (
              <p className="text-xs text-center" style={{ color: 'var(--text-secondary)' }}>
                Have a reset token?{' '}
                <button
                  type="button"
                  onClick={() => switchMode('reset')}
                  className="cursor-pointer"
                  style={{ color: 'var(--accent)', backgroundColor: 'transparent', border: 'none' }}
                >
                  Enter it here
                </button>
              </p>
            )}
          </form>
        )}

        {/* OAuth section (always shown on login/register) */}
        {(mode === 'login' || mode === 'register') && (
          <>
            <div className="flex items-center gap-3 my-6">
              <div className="flex-1 h-px" style={{ backgroundColor: 'var(--border)' }} />
              <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                or continue with
              </span>
              <div className="flex-1 h-px" style={{ backgroundColor: 'var(--border)' }} />
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => providers?.google && oauthLogin('google')}
                disabled={!providers?.google}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer"
                style={{
                  backgroundColor: 'var(--bg-primary)',
                  color: providers?.google ? 'var(--text-primary)' : 'var(--text-secondary)',
                  border: '1px solid var(--border)',
                  opacity: providers?.google ? 1 : 0.5,
                  cursor: providers?.google ? 'pointer' : 'not-allowed',
                }}
                title={providers?.google ? 'Sign in with Google' : 'Google OAuth not configured'}
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                </svg>
                Google
              </button>

              <button
                onClick={() => providers?.github && oauthLogin('github')}
                disabled={!providers?.github}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer"
                style={{
                  backgroundColor: 'var(--bg-primary)',
                  color: providers?.github ? 'var(--text-primary)' : 'var(--text-secondary)',
                  border: '1px solid var(--border)',
                  opacity: providers?.github ? 1 : 0.5,
                  cursor: providers?.github ? 'pointer' : 'not-allowed',
                }}
                title={providers?.github ? 'Sign in with GitHub' : 'GitHub OAuth not configured'}
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
                GitHub
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
