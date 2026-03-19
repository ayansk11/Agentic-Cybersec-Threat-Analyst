const API_BASE = '/api';

// ── Auth types ─────────────────────────────────────────────────────────

export interface UserResponse {
  id: number;
  email: string;
  username: string;
  role: 'admin' | 'analyst';
  oauth_provider: string | null;
  is_active: boolean;
  email_verified: boolean;
  created_at: string;
}

export interface AuthProvidersResponse {
  local: boolean;
  google: boolean;
  github: boolean;
  jwt_configured: boolean;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: UserResponse;
}

// ── Auth header ────────────────────────────────────────────────────────

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('access_token');
  if (token) return { 'Authorization': `Bearer ${token}` };
  // Fallback to legacy API key for dev/CI
  const key = import.meta.env.VITE_API_KEY;
  return key ? { 'X-API-Key': key } : {};
}

// ── Authenticated fetch with 401 retry ─────────────────────────────────

async function authFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const headers = { ...authHeaders(), ...(options.headers as Record<string, string> || {}) };
  let resp = await fetch(url, { ...options, headers });

  if (resp.status === 401 && localStorage.getItem('access_token')) {
    // Try refreshing the token once
    try {
      const data = await refreshToken();
      localStorage.setItem('access_token', data.access_token);
      const retryHeaders = {
        'Authorization': `Bearer ${data.access_token}`,
        ...(options.headers as Record<string, string> || {}),
      };
      resp = await fetch(url, { ...options, headers: retryHeaders });
    } catch {
      localStorage.removeItem('access_token');
      window.location.reload();
    }
  }

  return resp;
}

// ── Auth API ───────────────────────────────────────────────────────────

export async function login(email: string, password: string): Promise<AuthResponse> {
  const resp = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include',
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || 'Login failed');
  }
  return resp.json();
}

export async function register(
  email: string,
  username: string,
  password: string,
): Promise<AuthResponse> {
  const resp = await fetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, username, password }),
    credentials: 'include',
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || 'Registration failed');
  }
  return resp.json();
}

export async function refreshToken(): Promise<{ access_token: string }> {
  const resp = await fetch(`${API_BASE}/auth/refresh`, {
    method: 'POST',
    credentials: 'include',
  });
  if (!resp.ok) throw new Error('Token refresh failed');
  return resp.json();
}

export async function logout(): Promise<void> {
  await fetch(`${API_BASE}/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  });
}

export async function fetchCurrentUser(): Promise<UserResponse> {
  const resp = await authFetch(`${API_BASE}/auth/me`);
  if (!resp.ok) throw new Error('Failed to fetch user');
  return resp.json();
}

// ── Admin API ──────────────────────────────────────────────────────────

export async function fetchUsers(
  limit = 50,
  offset = 0,
): Promise<{ users: UserResponse[]; count: number }> {
  const resp = await authFetch(`${API_BASE}/auth/admin/users?limit=${limit}&offset=${offset}`);
  if (!resp.ok) throw new Error('Failed to fetch users');
  return resp.json();
}

export async function updateUser(
  userId: number,
  data: { role?: string; is_active?: boolean },
): Promise<UserResponse> {
  const resp = await authFetch(`${API_BASE}/auth/admin/users/${userId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!resp.ok) throw new Error('Failed to update user');
  return resp.json();
}

// ── Password Reset ────────────────────────────────────────────────────

export async function forgotPassword(email: string): Promise<{ message: string }> {
  const resp = await fetch(`${API_BASE}/auth/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || 'Request failed');
  }
  return resp.json();
}

export async function resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
  const resp = await fetch(`${API_BASE}/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, new_password: newPassword }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || 'Reset failed');
  }
  return resp.json();
}

// ── Email Verification ───────────────────────────────────────────────

export async function verifyEmail(token: string): Promise<{ message: string }> {
  const resp = await fetch(`${API_BASE}/auth/verify-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || 'Verification failed');
  }
  return resp.json();
}

export async function resendVerification(email: string): Promise<{ message: string }> {
  const resp = await fetch(`${API_BASE}/auth/resend-verification`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || 'Request failed');
  }
  return resp.json();
}

// ── Auth Providers ───────────────────────────────────────────────────

export async function fetchAuthProviders(): Promise<AuthProvidersResponse> {
  const resp = await fetch(`${API_BASE}/auth/providers`);
  if (!resp.ok) return { local: true, google: false, github: false, jwt_configured: false };
  return resp.json();
}

// ── Models ────────────────────────────────────────────────────────────

export interface ModelInfo {
  id: string;
  display_name: string;
  description: string;
  size: string;
  default: boolean;
}

export interface ModelsResponse {
  models: ModelInfo[];
  default: string;
}

export async function fetchModels(): Promise<ModelsResponse> {
  const resp = await fetch(`${API_BASE}/models`);
  if (!resp.ok) return { models: [], default: 'foundation-sec-8b' };
  return resp.json();
}

// ── CVE ────────────────────────────────────────────────────────────────

export async function fetchCVE(cveId: string) {
  const resp = await authFetch(`${API_BASE}/cve/${cveId}`);
  if (!resp.ok) throw new Error(`Failed to fetch CVE: ${resp.statusText}`);
  return resp.json();
}

// ── Health (public) ────────────────────────────────────────────────────

export async function checkHealth() {
  const resp = await fetch(`${API_BASE}/health`);
  return resp.json();
}

// ── Feeds ──────────────────────────────────────────────────────────────

export interface FeedItem {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  severity: string;
  published: string | null;
  cwes: string[];
  in_kev: boolean;
}

export interface FeedResponse {
  items: FeedItem[];
  count: number;
}

export async function fetchRecentCVEs(days = 7, limit = 20): Promise<FeedResponse> {
  const resp = await authFetch(`${API_BASE}/feed/recent?days=${days}&limit=${limit}`);
  if (!resp.ok) throw new Error(`Failed to fetch feed: ${resp.statusText}`);
  return resp.json();
}

export interface OTXPulseItem {
  pulse_id: string;
  name: string;
  description: string;
  created: string | null;
  tags: string[];
  adversary: string;
  ioc_count: number;
}

export interface OTXFeedResponse {
  items: OTXPulseItem[];
  count: number;
}

export async function fetchOTXFeed(days = 7, limit = 20): Promise<OTXFeedResponse> {
  const resp = await authFetch(`${API_BASE}/feed/otx?days=${days}&limit=${limit}`);
  if (!resp.ok) throw new Error(`Failed to fetch OTX feed: ${resp.statusText}`);
  return resp.json();
}

export interface ThreatFoxIOCItem {
  ioc_id: number;
  ioc_type: string;
  ioc_value: string;
  threat_type: string;
  malware: string;
  confidence_level: number;
  first_seen: string | null;
  tags: string[];
}

export interface ThreatFoxFeedResponse {
  items: ThreatFoxIOCItem[];
  count: number;
}

export async function fetchThreatFoxFeed(days = 7, limit = 50): Promise<ThreatFoxFeedResponse> {
  const resp = await authFetch(`${API_BASE}/feed/threatfox?days=${days}&limit=${limit}`);
  if (!resp.ok) throw new Error(`Failed to fetch ThreatFox feed: ${resp.statusText}`);
  return resp.json();
}

// ── Dashboard ──────────────────────────────────────────────────────────

export interface DashboardStats {
  total_chunks: number;
  technique_chunks: number;
  mitigation_chunks: number;
  software_chunks: number;
  group_chunks: number;
  relationship_chunks: number;
  ollama_connected: boolean;
  qdrant_connected: boolean;
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const resp = await authFetch(`${API_BASE}/stats`);
  if (!resp.ok) throw new Error(`Failed to fetch stats: ${resp.statusText}`);
  return resp.json();
}

// ── History ────────────────────────────────────────────────────────────

export interface AnalysisHistoryItem {
  id: number;
  cve_id: string;
  severity: string;
  created_at: string;
  extracted_info: Record<string, unknown>;
  attack_techniques: Array<{
    technique_id: string;
    name: string;
    tactics: string[];
    confidence: number;
  }>;
}

export interface AnalysisHistoryResponse {
  items: AnalysisHistoryItem[];
  count: number;
}

export async function fetchAnalysisHistory(limit = 50): Promise<AnalysisHistoryResponse> {
  const resp = await authFetch(`${API_BASE}/history?limit=${limit}`);
  if (!resp.ok) throw new Error(`Failed to fetch history: ${resp.statusText}`);
  return resp.json();
}

export async function fetchSeverityStats(): Promise<{ counts: Record<string, number> }> {
  const resp = await authFetch(`${API_BASE}/history/stats/severity`);
  if (!resp.ok) throw new Error(`Failed to fetch severity stats: ${resp.statusText}`);
  return resp.json();
}

export async function fetchTacticStats(): Promise<{ counts: Record<string, number> }> {
  const resp = await authFetch(`${API_BASE}/history/stats/tactics`);
  if (!resp.ok) throw new Error(`Failed to fetch tactic stats: ${resp.statusText}`);
  return resp.json();
}

// ── Streaming analysis ─────────────────────────────────────────────────

export function streamAnalysis(
  cveId: string,
  cveDescription: string,
  onUpdate: (agent: string, output: Record<string, unknown>) => void,
  onDone: () => void,
  onError: (error: string) => void,
  model?: string,
): () => void {
  const controller = new AbortController();

  fetch(`${API_BASE}/analyze/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ cve_id: cveId, cve_description: cveDescription, model: model || null }),
    signal: controller.signal,
  })
    .then(async (response) => {
      const reader = response.body?.getReader();
      if (!reader) return;

      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('event: ')) {
            continue;
          }
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            try {
              const parsed = JSON.parse(data);
              if (parsed.status === 'complete') {
                onDone();
              } else if (parsed.error) {
                onError(parsed.error);
              } else if (parsed.agent) {
                onUpdate(parsed.agent, parsed.output);
              }
            } catch {
              // skip malformed lines
            }
          }
        }
      }
    })
    .catch((err) => {
      if (err.name !== 'AbortError') {
        onError(err.message);
      }
    });

  return () => controller.abort();
}
