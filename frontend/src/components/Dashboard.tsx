import { useState, useEffect } from 'react';
import {
  Shield,
  Database,
  Cpu,
  Network,
  Loader2,
  CheckCircle,
  XCircle,
  RefreshCw,
  Layers,
  Users,
  Bug,
  Link2,
  ShieldCheck,
  BarChart3,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area,
} from 'recharts';
import type { DashboardStats } from '../api/client';
import { fetchDashboardStats, fetchSeverityStats, fetchTacticStats, fetchAnalysisHistory } from '../api/client';
import type { AnalysisHistoryItem } from '../api/client';

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span
      className="inline-block w-2.5 h-2.5 rounded-full"
      style={{ backgroundColor: ok ? 'var(--low)' : 'var(--critical)' }}
    />
  );
}

const KNOWLEDGE_BASE_ITEMS = [
  { label: 'Techniques', key: 'technique_chunks' as const, icon: Shield, color: 'var(--high)' },
  { label: 'Mitigations', key: 'mitigation_chunks' as const, icon: ShieldCheck, color: 'var(--low)' },
  { label: 'Software', key: 'software_chunks' as const, icon: Bug, color: 'var(--medium)' },
  { label: 'Groups', key: 'group_chunks' as const, icon: Users, color: 'var(--critical)' },
  { label: 'Relationships', key: 'relationship_chunks' as const, icon: Link2, color: 'var(--accent)' },
];

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  UNKNOWN: '#64748b',
};

function buildTimelineData(items: AnalysisHistoryItem[]) {
  const counts: Record<string, number> = {};
  const now = new Date();
  // Initialize last 30 days
  for (let i = 29; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    counts[d.toISOString().slice(0, 10)] = 0;
  }
  for (const item of items) {
    const day = item.created_at.slice(0, 10);
    if (day in counts) counts[day] = (counts[day] || 0) + 1;
  }
  return Object.entries(counts).map(([date, count]) => ({
    date: date.slice(5), // MM-DD
    analyses: count,
  }));
}

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [severityData, setSeverityData] = useState<Array<{ name: string; value: number }>>([]);
  const [tacticData, setTacticData] = useState<Array<{ name: string; count: number }>>([]);
  const [timelineData, setTimelineData] = useState<Array<{ date: string; analyses: number }>>([]);
  const [hasHistory, setHasHistory] = useState(false);

  const loadStats = async () => {
    setLoading(true);
    setError('');
    try {
      const [data, severity, tactics, history] = await Promise.all([
        fetchDashboardStats(),
        fetchSeverityStats().catch(() => ({ counts: {} })),
        fetchTacticStats().catch(() => ({ counts: {} })),
        fetchAnalysisHistory(100).catch(() => ({ items: [], count: 0 })),
      ]);
      setStats(data);

      const sevEntries = Object.entries(severity.counts).map(([name, value]) => ({ name, value }));
      setSeverityData(sevEntries);

      const tacEntries = Object.entries(tactics.counts)
        .map(([name, count]) => ({ name: name.replace(/-/g, ' '), count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 12);
      setTacticData(tacEntries);

      setTimelineData(buildTimelineData(history.items));
      setHasHistory(history.count > 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load stats');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Dashboard</h2>
        <button
          onClick={loadStats}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm cursor-pointer disabled:opacity-50"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div
          className="rounded-xl p-4 mb-6 flex items-center gap-3"
          style={{ backgroundColor: 'var(--critical)15', border: '1px solid var(--critical)40' }}
        >
          <XCircle className="w-5 h-5 shrink-0" style={{ color: 'var(--critical)' }} />
          <p className="text-sm" style={{ color: 'var(--critical)' }}>{error}</p>
        </div>
      )}

      {/* Service Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div
          className="rounded-xl p-5"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Ollama LLM</span>
            <Cpu className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          </div>
          <div className="flex items-center gap-2">
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" style={{ color: 'var(--text-secondary)' }} />
            ) : stats ? (
              <>
                <StatusDot ok={stats.ollama_connected} />
                <span className="text-sm font-medium">
                  {stats.ollama_connected ? 'Connected' : 'Disconnected'}
                </span>
              </>
            ) : (
              <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>--</span>
            )}
          </div>
        </div>

        <div
          className="rounded-xl p-5"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Qdrant Vector DB</span>
            <Database className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          </div>
          <div className="flex items-center gap-2">
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" style={{ color: 'var(--text-secondary)' }} />
            ) : stats ? (
              <>
                <StatusDot ok={stats.qdrant_connected} />
                <span className="text-sm font-medium">
                  {stats.qdrant_connected ? 'Connected' : 'Disconnected'}
                </span>
              </>
            ) : (
              <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>--</span>
            )}
          </div>
        </div>

        <div
          className="rounded-xl p-5"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Agent Pipeline</span>
            <Network className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          </div>
          <div className="flex items-center gap-2">
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" style={{ color: 'var(--text-secondary)' }} />
            ) : stats ? (
              <>
                <StatusDot ok={stats.ollama_connected && stats.qdrant_connected} />
                <span className="text-sm font-medium">
                  {stats.ollama_connected && stats.qdrant_connected ? 'Ready' : 'Degraded'}
                </span>
              </>
            ) : (
              <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>--</span>
            )}
          </div>
        </div>
      </div>

      {/* Knowledge Base Stats */}
      <div
        className="rounded-xl p-6 mb-6"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
      >
        <div className="flex items-center gap-2 mb-5">
          <Layers className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          <h3 className="text-lg font-semibold">MITRE ATT&CK Knowledge Base</h3>
          {stats && (
            <span
              className="ml-auto px-2.5 py-1 rounded-full text-xs font-medium"
              style={{ backgroundColor: 'var(--accent)15', color: 'var(--accent)' }}
            >
              {stats.total_chunks.toLocaleString()} total chunks
            </span>
          )}
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-24">
            <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--accent)' }} />
          </div>
        ) : stats && stats.total_chunks > 0 ? (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {KNOWLEDGE_BASE_ITEMS.map((item) => {
              const count = stats[item.key];
              const pct = stats.total_chunks > 0 ? (count / stats.total_chunks) * 100 : 0;
              return (
                <div key={item.key} className="text-center">
                  <div className="flex items-center justify-center mb-2">
                    <item.icon className="w-5 h-5" style={{ color: item.color }} />
                  </div>
                  <p className="text-2xl font-bold mb-1">{count.toLocaleString()}</p>
                  <p className="text-xs mb-2" style={{ color: 'var(--text-secondary)' }}>{item.label}</p>
                  <div
                    className="h-1.5 rounded-full mx-auto"
                    style={{ backgroundColor: 'var(--bg-primary)', maxWidth: '80px' }}
                  >
                    <div
                      className="h-1.5 rounded-full"
                      style={{ width: `${Math.max(pct, 2)}%`, backgroundColor: item.color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-8">
            <Database className="w-8 h-8 mx-auto mb-3" style={{ color: 'var(--text-secondary)' }} />
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              No data ingested yet. Run the ingestion pipeline:
            </p>
            <code
              className="inline-block mt-2 px-3 py-1.5 rounded-lg text-xs"
              style={{ backgroundColor: 'var(--bg-primary)', color: 'var(--accent)' }}
            >
              python -m backend.ingestion.ingest_attack
            </code>
          </div>
        )}
      </div>

      {/* Analytics Charts */}
      {hasHistory && (
        <div className="mb-6">
          <div className="flex items-center gap-2 mb-4">
            <BarChart3 className="w-5 h-5" style={{ color: 'var(--accent)' }} />
            <h3 className="text-lg font-semibold">Analysis Analytics</h3>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            {/* Severity Distribution */}
            {severityData.length > 0 && (
              <div
                className="rounded-xl p-6"
                style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
              >
                <h4 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>
                  Severity Distribution
                </h4>
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={3}
                      dataKey="value"
                      label={({ name, value }) => `${name} (${value})`}
                    >
                      {severityData.map((entry) => (
                        <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#64748b'} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                      itemStyle={{ color: '#f1f5f9' }}
                    />
                    <Legend wrapperStyle={{ color: '#94a3b8', fontSize: '12px' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* ATT&CK Tactic Bar Chart */}
            {tacticData.length > 0 && (
              <div
                className="rounded-xl p-6"
                style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
              >
                <h4 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>
                  ATT&CK Tactics
                </h4>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={tacticData} layout="vertical" margin={{ left: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis
                      dataKey="name"
                      type="category"
                      tick={{ fill: '#94a3b8', fontSize: 10 }}
                      width={100}
                    />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                      itemStyle={{ color: '#f1f5f9' }}
                    />
                    <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          {/* Analysis Timeline */}
          <div
            className="rounded-xl p-6"
            style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
          >
            <h4 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>
              Analysis Timeline (Last 30 Days)
            </h4>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="date" tick={{ fill: '#94a3b8', fontSize: 10 }} interval="preserveStartEnd" />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                  itemStyle={{ color: '#f1f5f9' }}
                />
                <Area type="monotone" dataKey="analyses" stroke="#3b82f6" fill="#3b82f620" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* System Architecture */}
      <div
        className="rounded-xl p-6"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
      >
        <h3 className="text-lg font-semibold mb-4">Agent Pipeline Architecture</h3>
        <div className="flex flex-col md:flex-row items-stretch gap-3">
          {[
            { step: '1', name: 'CVE Extractor', desc: 'NVD + CISA KEV enrichment', color: 'var(--accent)' },
            { step: '2', name: 'ATT&CK Classifier', desc: 'RAG + LLM technique mapping', color: 'var(--high)' },
            { step: '3', name: 'Playbook Generator', desc: 'NIST 800-61 + Sigma rules', color: 'var(--low)' },
          ].map((agent, i) => (
            <div key={agent.step} className="flex items-center gap-3 flex-1">
              <div
                className="rounded-lg p-4 flex-1"
                style={{ backgroundColor: 'var(--bg-primary)', border: `1px solid ${agent.color}40` }}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold"
                    style={{ backgroundColor: `${agent.color}20`, color: agent.color }}
                  >
                    {agent.step}
                  </span>
                  <span className="text-sm font-semibold">{agent.name}</span>
                </div>
                <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{agent.desc}</p>
                {stats && (
                  <div className="mt-2 flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" style={{ color: 'var(--low)' }} />
                    <span className="text-xs" style={{ color: 'var(--low)' }}>Deployed</span>
                  </div>
                )}
              </div>
              {i < 2 && (
                <span className="text-lg hidden md:block" style={{ color: 'var(--text-secondary)' }}>
                  →
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
