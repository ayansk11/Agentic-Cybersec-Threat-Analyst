import { useState, useEffect } from 'react';
import { Settings, Webhook, Send, CheckCircle, XCircle, Loader2 } from 'lucide-react';

interface WebhookSettings {
  webhook_url: string;
  webhook_severity_threshold: string;
  smtp_configured: boolean;
}

async function fetchWebhookSettings(authHeaders: () => Record<string, string>): Promise<WebhookSettings> {
  const resp = await fetch('/api/auth/admin/settings/webhooks', {
    headers: authHeaders(),
  });
  if (!resp.ok) throw new Error('Failed to fetch webhook settings');
  return resp.json();
}

async function saveWebhookSettings(
  data: { webhook_url: string; webhook_severity_threshold: string },
  authHeaders: () => Record<string, string>,
): Promise<WebhookSettings> {
  const resp = await fetch('/api/auth/admin/settings/webhooks', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(data),
  });
  if (!resp.ok) throw new Error('Failed to save webhook settings');
  return resp.json();
}

async function testWebhook(
  url: string,
  authHeaders: () => Record<string, string>,
): Promise<{ success: boolean; status_code?: number; error?: string }> {
  const resp = await fetch('/api/auth/admin/settings/webhooks/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ url }),
  });
  if (!resp.ok) throw new Error('Failed to test webhook');
  return resp.json();
}

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem('access_token');
  if (token) return { Authorization: `Bearer ${token}` };
  return {};
}

const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export function SettingsPage() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [testResult, setTestResult] = useState<{ success: boolean; detail: string } | null>(null);

  const [webhookUrl, setWebhookUrl] = useState('');
  const [threshold, setThreshold] = useState('HIGH');
  const [smtpConfigured, setSmtpConfigured] = useState(false);

  useEffect(() => {
    fetchWebhookSettings(getAuthHeaders)
      .then((data) => {
        setWebhookUrl(data.webhook_url);
        setThreshold(data.webhook_severity_threshold);
        setSmtpConfigured(data.smtp_configured);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      await saveWebhookSettings(
        { webhook_url: webhookUrl, webhook_severity_threshold: threshold },
        getAuthHeaders,
      );
      setSuccess('Settings saved successfully');
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    if (!webhookUrl) return;
    setTesting(true);
    setTestResult(null);
    try {
      const result = await testWebhook(webhookUrl, getAuthHeaders);
      if (result.success) {
        setTestResult({ success: true, detail: `HTTP ${result.status_code}` });
      } else {
        setTestResult({ success: false, detail: result.error || 'Failed' });
      }
    } catch (e: unknown) {
      setTestResult({ success: false, detail: e instanceof Error ? e.message : 'Test failed' });
    } finally {
      setTesting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--text-secondary)' }} />
      </div>
    );
  }

  return (
    <div className="max-w-2xl">
      <div className="flex items-center gap-3 mb-6">
        <Settings className="w-6 h-6" style={{ color: 'var(--accent)' }} />
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Settings
        </h1>
      </div>

      {error && (
        <div
          className="flex items-center gap-2 px-4 py-3 rounded-lg mb-4 text-sm"
          style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: 'var(--critical)' }}
        >
          <XCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {success && (
        <div
          className="flex items-center gap-2 px-4 py-3 rounded-lg mb-4 text-sm"
          style={{ backgroundColor: 'rgba(34,197,94,0.1)', color: '#22c55e' }}
        >
          <CheckCircle className="w-4 h-4 flex-shrink-0" />
          {success}
        </div>
      )}

      {/* Webhooks Section */}
      <section
        className="rounded-lg p-6 mb-6"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
      >
        <div className="flex items-center gap-2 mb-4">
          <Webhook className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Webhook Notifications
          </h2>
        </div>
        <p className="text-sm mb-4" style={{ color: 'var(--text-secondary)' }}>
          Receive HTTP POST notifications when analyses complete above the severity threshold.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-primary)' }}>
              Webhook URL
            </label>
            <input
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="w-full px-3 py-2 rounded-lg text-sm"
              style={{
                backgroundColor: 'var(--bg-primary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border)',
                outline: 'none',
              }}
            />
            <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
              Leave empty to disable webhook notifications.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-primary)' }}>
              Severity Threshold
            </label>
            <select
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              className="px-3 py-2 rounded-lg text-sm"
              style={{
                backgroundColor: 'var(--bg-primary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border)',
                outline: 'none',
              }}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev} and above
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium cursor-pointer"
              style={{
                backgroundColor: 'var(--accent)',
                color: '#fff',
                border: 'none',
                opacity: saving ? 0.6 : 1,
              }}
            >
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              Save
            </button>

            <button
              onClick={handleTest}
              disabled={testing || !webhookUrl}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium cursor-pointer"
              style={{
                backgroundColor: 'transparent',
                color: 'var(--accent)',
                border: '1px solid var(--accent)',
                opacity: testing || !webhookUrl ? 0.5 : 1,
              }}
            >
              {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              Test Webhook
            </button>

            {testResult && (
              <span
                className="text-sm flex items-center gap-1"
                style={{ color: testResult.success ? '#22c55e' : 'var(--critical)' }}
              >
                {testResult.success ? (
                  <CheckCircle className="w-4 h-4" />
                ) : (
                  <XCircle className="w-4 h-4" />
                )}
                {testResult.detail}
              </span>
            )}
          </div>
        </div>
      </section>

      {/* SMTP Status Section */}
      <section
        className="rounded-lg p-6"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
      >
        <div className="flex items-center gap-2 mb-4">
          <Send className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Email (SMTP)
          </h2>
        </div>

        <div className="flex items-center gap-2">
          {smtpConfigured ? (
            <>
              <CheckCircle className="w-4 h-4" style={{ color: '#22c55e' }} />
              <span className="text-sm" style={{ color: '#22c55e' }}>
                SMTP is configured — emails will be sent for password resets and verification.
              </span>
            </>
          ) : (
            <>
              <XCircle className="w-4 h-4" style={{ color: 'var(--medium)' }} />
              <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                SMTP is not configured — tokens are logged to the server console.
                Set SMTP_HOST, SMTP_USER, and SMTP_PASSWORD in .env to enable email delivery.
              </span>
            </>
          )}
        </div>
      </section>
    </div>
  );
}
