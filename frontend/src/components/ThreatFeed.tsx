import { useState, useEffect, useCallback } from 'react';
import { Rss, Loader2, AlertCircle, RefreshCw, Search, Calendar, Globe, Bug, ExternalLink } from 'lucide-react';
import { fetchRecentCVEs, fetchOTXFeed, fetchThreatFoxFeed } from '../api/client';
import type { FeedItem, OTXPulseItem, ThreatFoxIOCItem } from '../api/client';

const DAYS_OPTIONS = [1, 3, 7, 14];
type FeedTab = 'nvd' | 'otx' | 'threatfox';

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    CRITICAL: 'var(--critical)',
    HIGH: 'var(--high)',
    MEDIUM: 'var(--medium)',
    LOW: 'var(--low)',
  };
  const color = colors[severity?.toUpperCase()] || 'var(--text-secondary)';

  return (
    <span
      className="px-2 py-0.5 rounded text-xs font-bold shrink-0"
      style={{ backgroundColor: `${color}20`, color, border: `1px solid ${color}40` }}
    >
      {severity || 'UNKNOWN'}
    </span>
  );
}

function CVSSScore({ score }: { score: number | null }) {
  if (score == null) return null;
  const color = score >= 9 ? 'var(--critical)' : score >= 7 ? 'var(--high)' : score >= 4 ? 'var(--medium)' : 'var(--low)';
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-lg font-bold" style={{ color }}>{score}</span>
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>CVSS</span>
    </div>
  );
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return 'N/A';
  try {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return dateStr;
  }
}

function OTXPulseCard({ pulse }: { pulse: OTXPulseItem }) {
  const [hovered, setHovered] = useState(false);

  return (
    <a
      href={`https://otx.alienvault.com/pulse/${pulse.pulse_id}`}
      target="_blank"
      rel="noopener noreferrer"
      className="block rounded-xl p-5 no-underline"
      style={{
        backgroundColor: 'var(--bg-card)',
        border: `1px solid ${hovered ? 'var(--accent)' : 'var(--border)'}`,
        cursor: 'pointer',
        textDecoration: 'none',
        color: 'inherit',
        transform: hovered ? 'translateY(-1px)' : 'none',
        boxShadow: hovered ? '0 4px 12px rgba(88, 166, 255, 0.15)' : 'none',
        transition: 'all 0.25s ease',
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div className="flex items-center gap-2.5 mb-2 flex-wrap">
        <Globe className="w-4 h-4" style={{ color: 'var(--accent)' }} />
        <span className="text-sm font-bold">{pulse.name}</span>
        {pulse.adversary && (
          <span
            className="px-2 py-0.5 rounded text-xs font-bold"
            style={{ backgroundColor: 'var(--high)20', color: 'var(--high)', border: '1px solid var(--high)40' }}
          >
            {pulse.adversary}
          </span>
        )}
        <ExternalLink
          className="w-3 h-3 ml-auto shrink-0"
          style={{
            color: hovered ? 'var(--accent)' : 'var(--text-secondary)',
            transition: 'color 0.25s ease',
          }}
        />
      </div>

      <div
        style={{
          maxHeight: hovered ? '500px' : '2.8em',
          overflow: 'hidden',
          transition: 'max-height 0.35s ease',
        }}
      >
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {pulse.description || 'No description.'}
        </p>
      </div>

      <div
        className="flex items-center gap-3 mt-3"
        style={{ flexWrap: 'wrap' }}
      >
        <span className="text-xs font-medium" style={{ color: 'var(--accent)' }}>
          {pulse.ioc_count} IOCs
        </span>
        {(hovered ? pulse.tags : pulse.tags.slice(0, 5)).map((tag) => (
          <span
            key={tag}
            className="px-2 py-0.5 rounded text-xs"
            style={{ backgroundColor: 'var(--bg-primary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
          >
            {tag}
          </span>
        ))}
        {!hovered && pulse.tags.length > 5 && (
          <span className="text-xs" style={{ color: 'var(--accent)' }}>
            +{pulse.tags.length - 5} more
          </span>
        )}
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          {formatDate(pulse.created)}
        </span>
      </div>
    </a>
  );
}

function ThreatFoxCard({ ioc }: { ioc: ThreatFoxIOCItem }) {
  const [hovered, setHovered] = useState(false);

  return (
    <a
      href={`https://threatfox.abuse.ch/ioc/${ioc.ioc_id}/`}
      target="_blank"
      rel="noopener noreferrer"
      className="block rounded-xl p-5 no-underline"
      style={{
        backgroundColor: 'var(--bg-card)',
        border: `1px solid ${hovered ? 'var(--critical)' : 'var(--border)'}`,
        cursor: 'pointer',
        textDecoration: 'none',
        color: 'inherit',
        transform: hovered ? 'translateY(-1px)' : 'none',
        boxShadow: hovered ? '0 4px 12px rgba(248, 81, 73, 0.15)' : 'none',
        transition: 'all 0.25s ease',
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div className="flex items-center gap-2.5 mb-2 flex-wrap">
        <Bug className="w-4 h-4" style={{ color: 'var(--critical)' }} />
        <span
          className="px-2 py-0.5 rounded text-xs font-bold font-mono"
          style={{ backgroundColor: 'var(--bg-primary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
        >
          {ioc.ioc_type}
        </span>
        {ioc.malware && (
          <span
            className="px-2 py-0.5 rounded text-xs font-bold"
            style={{ backgroundColor: 'var(--critical)20', color: 'var(--critical)', border: '1px solid var(--critical)40' }}
          >
            {ioc.malware}
          </span>
        )}
        <ExternalLink
          className="w-3 h-3 ml-auto shrink-0"
          style={{
            color: hovered ? 'var(--critical)' : 'var(--text-secondary)',
            transition: 'color 0.25s ease',
          }}
        />
      </div>

      <div
        style={{
          maxHeight: hovered ? '200px' : '1.6em',
          overflow: 'hidden',
          transition: 'max-height 0.35s ease',
        }}
      >
        <p className="text-sm font-mono" style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>
          {ioc.ioc_value}
        </p>
      </div>

      <div className="flex items-center gap-3 mt-3" style={{ flexWrap: 'wrap' }}>
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          {ioc.threat_type}
        </span>
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          Confidence: {ioc.confidence_level}%
        </span>
        {(hovered ? ioc.tags : ioc.tags.slice(0, 3)).map((tag) => (
          <span
            key={tag}
            className="px-2 py-0.5 rounded text-xs"
            style={{ backgroundColor: 'var(--bg-primary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
          >
            {tag}
          </span>
        ))}
        {!hovered && ioc.tags.length > 3 && (
          <span className="text-xs" style={{ color: 'var(--critical)' }}>
            +{ioc.tags.length - 3} more
          </span>
        )}
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          {formatDate(ioc.first_seen)}
        </span>
      </div>
    </a>
  );
}

interface ThreatFeedProps {
  onAnalyze?: (cveId: string) => void;
}

export function ThreatFeed({ onAnalyze }: ThreatFeedProps) {
  const [activeTab, setActiveTab] = useState<FeedTab>('nvd');
  const [items, setItems] = useState<FeedItem[]>([]);
  const [otxItems, setOtxItems] = useState<OTXPulseItem[]>([]);
  const [threatfoxItems, setThreatfoxItems] = useState<ThreatFoxIOCItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(7);

  const loadFeed = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (activeTab === 'nvd') {
        const data = await fetchRecentCVEs(days, 20);
        setItems(data.items);
      } else if (activeTab === 'otx') {
        const data = await fetchOTXFeed(days, 20);
        setOtxItems(data.items);
      } else {
        const data = await fetchThreatFoxFeed(days, 50);
        setThreatfoxItems(data.items);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load feed');
    } finally {
      setLoading(false);
    }
  }, [days, activeTab]);

  useEffect(() => {
    loadFeed();
  }, [loadFeed]);

  const tabs: { id: FeedTab; label: string; icon: typeof Rss; count: number }[] = [
    { id: 'nvd', label: 'NVD CVEs', icon: Rss, count: items.length },
    { id: 'otx', label: 'OTX Pulses', icon: Globe, count: otxItems.length },
    { id: 'threatfox', label: 'ThreatFox IOCs', icon: Bug, count: threatfoxItems.length },
  ];

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Threat Feed</h2>

      {/* Controls */}
      <div
        className="rounded-xl p-4 mb-6"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
      >
        {/* Tab switcher */}
        <div className="flex items-center gap-1 mb-4 p-1 rounded-lg" style={{ backgroundColor: 'var(--bg-primary)' }}>
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className="flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium cursor-pointer transition-colors flex-1 justify-center"
                style={{
                  backgroundColor: activeTab === tab.id ? 'var(--bg-card)' : 'transparent',
                  color: activeTab === tab.id ? 'var(--text-primary)' : 'var(--text-secondary)',
                  boxShadow: activeTab === tab.id ? '0 1px 3px rgba(0,0,0,0.2)' : 'none',
                }}
              >
                <Icon className="w-3.5 h-3.5" />
                {tab.label}
                {activeTab === tab.id && tab.count > 0 && (
                  <span className="px-1.5 py-0.5 rounded-full text-xs" style={{ backgroundColor: 'var(--bg-primary)', color: 'var(--text-secondary)' }}>
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Day filter + refresh */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-1.5">
            <Calendar className="w-3.5 h-3.5" style={{ color: 'var(--text-secondary)' }} />
            <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Last</span>
            {DAYS_OPTIONS.map((d) => (
              <button
                key={d}
                onClick={() => setDays(d)}
                className="px-2.5 py-1 rounded text-xs font-medium cursor-pointer transition-colors"
                style={{
                  backgroundColor: days === d ? 'var(--accent)' : 'var(--bg-primary)',
                  color: days === d ? 'white' : 'var(--text-secondary)',
                  border: `1px solid ${days === d ? 'var(--accent)' : 'var(--border)'}`,
                }}
              >
                {d}d
              </button>
            ))}
          </div>

          <button
            onClick={loadFeed}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer disabled:opacity-50"
            style={{ backgroundColor: 'var(--bg-primary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div
          className="rounded-xl p-12 flex flex-col items-center justify-center"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <Loader2 className="w-8 h-8 animate-spin mb-3" style={{ color: 'var(--accent)' }} />
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {activeTab === 'nvd' && 'Fetching recent CVEs from NVD...'}
            {activeTab === 'otx' && 'Fetching threat pulses from AlienVault OTX...'}
            {activeTab === 'threatfox' && 'Fetching IOCs from ThreatFox...'}
          </p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div
          className="rounded-xl p-4 mb-4 flex items-center gap-3"
          style={{ backgroundColor: 'var(--critical)15', border: '1px solid var(--critical)40' }}
        >
          <AlertCircle className="w-5 h-5 shrink-0" style={{ color: 'var(--critical)' }} />
          <p className="text-sm" style={{ color: 'var(--critical)' }}>{error}</p>
        </div>
      )}

      {/* NVD CVE Feed */}
      {!loading && activeTab === 'nvd' && items.length > 0 && (
        <div className="space-y-3">
          {items.map((item) => (
            <div
              key={item.cve_id}
              className="rounded-xl p-5"
              style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 mb-2 flex-wrap">
                    <span className="text-sm font-bold">{item.cve_id}</span>
                    <SeverityBadge severity={item.severity} />
                    {item.in_kev && (
                      <span
                        className="px-2 py-0.5 rounded text-xs font-bold shrink-0"
                        style={{ backgroundColor: 'var(--critical)20', color: 'var(--critical)', border: '1px solid var(--critical)40' }}
                      >
                        CISA KEV
                      </span>
                    )}
                  </div>
                  <p className="text-sm mb-3 line-clamp-2" style={{ color: 'var(--text-secondary)' }}>
                    {item.description || 'No description available.'}
                  </p>
                  <div className="flex items-center gap-4 flex-wrap">
                    <CVSSScore score={item.cvss_score} />
                    {item.cwes.length > 0 && (
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                        {item.cwes.join(', ')}
                      </span>
                    )}
                    <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                      Published: {formatDate(item.published)}
                    </span>
                  </div>
                </div>
                {onAnalyze && (
                  <button
                    onClick={() => onAnalyze(item.cve_id)}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium cursor-pointer shrink-0"
                    style={{ backgroundColor: 'var(--accent)', color: 'white', border: 'none' }}
                  >
                    <Search className="w-3.5 h-3.5" />
                    Analyze
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* OTX Pulses Feed */}
      {!loading && activeTab === 'otx' && otxItems.length > 0 && (
        <div className="space-y-3">
          {otxItems.map((pulse) => (
            <OTXPulseCard key={pulse.pulse_id} pulse={pulse} />
          ))}
        </div>
      )}

      {/* ThreatFox IOCs Feed */}
      {!loading && activeTab === 'threatfox' && threatfoxItems.length > 0 && (
        <div className="space-y-3">
          {threatfoxItems.map((ioc) => (
            <ThreatFoxCard key={ioc.ioc_id} ioc={ioc} />
          ))}
        </div>
      )}

      {/* Empty states */}
      {!loading && !error && activeTab === 'nvd' && items.length === 0 && (
        <div
          className="rounded-xl p-12 flex flex-col items-center justify-center text-center"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <Rss className="w-10 h-10 mb-3" style={{ color: 'var(--text-secondary)' }} />
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            No CVEs found for the last {days} day{days > 1 ? 's' : ''}. Try a wider time range.
          </p>
        </div>
      )}
      {!loading && !error && activeTab === 'otx' && otxItems.length === 0 && (
        <div
          className="rounded-xl p-12 flex flex-col items-center justify-center text-center"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <Globe className="w-10 h-10 mb-3" style={{ color: 'var(--text-secondary)' }} />
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            No OTX pulses found. Set OTX_API_KEY in .env to enable this feed.
          </p>
        </div>
      )}
      {!loading && !error && activeTab === 'threatfox' && threatfoxItems.length === 0 && (
        <div
          className="rounded-xl p-12 flex flex-col items-center justify-center text-center"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <Bug className="w-10 h-10 mb-3" style={{ color: 'var(--text-secondary)' }} />
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            No ThreatFox IOCs found. Set THREATFOX_API_KEY in .env to enable this feed.
          </p>
        </div>
      )}
    </div>
  );
}
