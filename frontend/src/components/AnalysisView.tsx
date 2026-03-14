import { useState, useEffect } from 'react';
import { Search, Loader2, CheckCircle, AlertCircle, ShieldAlert, Shield, FileText, Code2, Copy, Check, Globe, Bug } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { useAnalysis } from '../hooks/useSSE';
import type { ExtractedInfo } from '../types';

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
      className="px-2 py-1 rounded text-xs font-bold"
      style={{ backgroundColor: `${color}20`, color, border: `1px solid ${color}40` }}
    >
      {severity || 'UNKNOWN'}
    </span>
  );
}

function AgentStatus({ name, isActive, isDone }: { name: string; isActive: boolean; isDone: boolean }) {
  return (
    <div className="flex items-center gap-2 py-2">
      {isDone ? (
        <CheckCircle className="w-4 h-4" style={{ color: 'var(--low)' }} />
      ) : isActive ? (
        <Loader2 className="w-4 h-4 animate-spin" style={{ color: 'var(--accent)' }} />
      ) : (
        <div className="w-4 h-4 rounded-full" style={{ border: '2px solid var(--border)' }} />
      )}
      <span className="text-sm" style={{ color: isDone || isActive ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
        {name}
      </span>
    </div>
  );
}

function InfoField({ label, value }: { label: string; value: string | string[] | undefined }) {
  if (!value || (Array.isArray(value) && value.length === 0)) return null;
  const display = Array.isArray(value) ? value.join(', ') : value;
  return (
    <div className="mb-3">
      <dt className="text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>{label}</dt>
      <dd className="text-sm">{display}</dd>
    </div>
  );
}

function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100);
  const color = confidence > 0.7 ? 'var(--low)' : confidence > 0.4 ? 'var(--medium)' : 'var(--critical)';
  return (
    <div className="flex items-center gap-2">
      <div
        className="h-2 rounded-full flex-1"
        style={{ backgroundColor: 'var(--bg-primary)', maxWidth: '120px' }}
      >
        <div
          className="h-2 rounded-full transition-all"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-xs font-mono" style={{ color }}>{pct}%</span>
    </div>
  );
}

function TacticBadge({ tactic }: { tactic: string }) {
  return (
    <span
      className="px-1.5 py-0.5 rounded text-xs"
      style={{ backgroundColor: 'var(--accent)15', color: 'var(--accent)', border: '1px solid var(--accent)30' }}
    >
      {tactic.replace(/-/g, ' ')}
    </span>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors"
      style={{
        backgroundColor: copied ? 'var(--low)20' : 'var(--bg-primary)',
        color: copied ? 'var(--low)' : 'var(--text-secondary)',
        border: `1px solid ${copied ? 'var(--low)40' : 'var(--border)'}`,
      }}
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {copied ? 'Copied!' : 'Copy'}
    </button>
  );
}

interface AnalysisViewProps {
  prefillCveId?: string;
  onPrefillConsumed?: () => void;
}

export function AnalysisView({ prefillCveId, onPrefillConsumed }: AnalysisViewProps) {
  const [cveId, setCveId] = useState('');
  const [description, setDescription] = useState('');
  const analysis = useAnalysis();

  useEffect(() => {
    if (prefillCveId) {
      setCveId(prefillCveId);
      onPrefillConsumed?.();
    }
  }, [prefillCveId, onPrefillConsumed]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!cveId && !description) return;
    analysis.startAnalysis(cveId, description);
  };

  const completedAgents = analysis.agentUpdates.map((u) => u.agent);
  const info: ExtractedInfo | null = analysis.extractedInfo;
  const techniques = analysis.attackTechniques;
  const playbook = analysis.playbook;
  const sigmaRule = analysis.sigmaRule;

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Threat Analysis</h2>

      {/* Input form */}
      <form onSubmit={handleSubmit} className="mb-8">
        <div
          className="rounded-xl p-6"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <div className="flex gap-4 mb-4">
            <input
              type="text"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="CVE-2021-44228"
              className="flex-1 px-4 py-2.5 rounded-lg text-sm"
              style={{
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            />
            <button
              type="submit"
              disabled={analysis.isLoading || (!cveId && !description)}
              className="px-6 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 cursor-pointer disabled:opacity-50"
              style={{
                backgroundColor: 'var(--accent)',
                color: 'white',
                border: 'none',
              }}
            >
              {analysis.isLoading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Search className="w-4 h-4" />
              )}
              Analyze
            </button>
          </div>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Or paste a vulnerability description here..."
            rows={3}
            className="w-full px-4 py-2.5 rounded-lg text-sm resize-none"
            style={{
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              color: 'var(--text-primary)',
              outline: 'none',
            }}
          />
        </div>
      </form>

      {/* Analysis pipeline progress */}
      {(analysis.isLoading || analysis.agentUpdates.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Pipeline status */}
          <div
            className="rounded-xl p-6"
            style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
          >
            <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>
              PIPELINE STATUS
            </h3>
            <AgentStatus
              name="1. CVE Extractor"
              isActive={analysis.currentAgent === 'cve_extractor'}
              isDone={completedAgents.includes('cve_extractor')}
            />
            <AgentStatus
              name="2. ATT&CK Classifier"
              isActive={analysis.currentAgent === 'attack_classifier'}
              isDone={completedAgents.includes('attack_classifier')}
            />
            <AgentStatus
              name="3. Playbook Generator"
              isActive={analysis.currentAgent === 'playbook_generator'}
              isDone={completedAgents.includes('playbook_generator')}
            />
          </div>

          {/* Extracted info */}
          <div
            className="lg:col-span-2 rounded-xl p-6"
            style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
          >
            {info ? (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5" style={{ color: 'var(--critical)' }} />
                    {info.cve_id || cveId}
                  </h3>
                  <div className="flex gap-2">
                    <SeverityBadge severity={info.nvd_severity || info.severity_assessment?.split(' ')[0] || ''} />
                    {info.cisa_kev && (
                      <span
                        className="px-2 py-1 rounded text-xs font-bold"
                        style={{ backgroundColor: 'var(--critical)20', color: 'var(--critical)', border: '1px solid var(--critical)40' }}
                      >
                        CISA KEV
                      </span>
                    )}
                  </div>
                </div>

                {info.nvd_cvss_score != null && (
                  <div className="mb-4 flex items-center gap-3">
                    <span className="text-3xl font-bold">{info.nvd_cvss_score}</span>
                    <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>CVSS Score</span>
                  </div>
                )}

                <dl>
                  <InfoField label="Summary" value={info.summary} />
                  <InfoField label="Vulnerability Type" value={info.vulnerability_type} />
                  <InfoField label="Attack Vector" value={info.attack_vector} />
                  <InfoField label="Potential Impact" value={info.potential_impact} />
                  <InfoField label="Affected Software" value={info.affected_software} />
                  <InfoField label="CWE" value={info.cwe_category} />
                  <InfoField label="Key Risk Factors" value={info.key_risk_factors} />
                  <InfoField label="Exploitation Likelihood" value={info.exploitation_likelihood} />
                  <InfoField label="Recommended Priority" value={info.recommended_priority} />
                </dl>

                {/* OTX Threat Intelligence */}
                {info.otx_pulse_count != null && info.otx_pulse_count > 0 && (
                  <div className="mt-4 rounded-lg p-4" style={{ backgroundColor: 'var(--bg-primary)', border: '1px solid var(--border)' }}>
                    <h4 className="text-xs font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--text-secondary)' }}>
                      <Globe className="w-3.5 h-3.5" style={{ color: 'var(--accent)' }} />
                      OTX THREAT INTELLIGENCE
                      <span className="px-1.5 py-0.5 rounded text-xs" style={{ backgroundColor: 'var(--accent)15', color: 'var(--accent)' }}>
                        {info.otx_pulse_count} pulse{info.otx_pulse_count !== 1 ? 's' : ''}
                      </span>
                    </h4>
                    {info.otx_pulses && info.otx_pulses.length > 0 && (
                      <div className="space-y-2 mb-3">
                        {info.otx_pulses.slice(0, 5).map((pulse) => (
                          <div key={pulse.pulse_id} className="text-xs p-2 rounded" style={{ backgroundColor: 'var(--bg-card)' }}>
                            <span className="font-medium">{pulse.name}</span>
                            {pulse.iocs && pulse.iocs.length > 0 && (
                              <span className="ml-2" style={{ color: 'var(--text-secondary)' }}>
                                ({pulse.iocs.length} IOC{pulse.iocs.length !== 1 ? 's' : ''})
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                    {info.otx_iocs && info.otx_iocs.length > 0 && (
                      <div>
                        <p className="text-xs mb-2 font-medium" style={{ color: 'var(--text-secondary)' }}>
                          Indicators of Compromise ({info.otx_iocs.length})
                        </p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
                          {info.otx_iocs.slice(0, 10).map((ioc, i) => (
                            <div key={i} className="text-xs font-mono p-1.5 rounded flex items-center gap-2" style={{ backgroundColor: 'var(--bg-card)' }}>
                              <span className="px-1 py-0.5 rounded text-[10px] shrink-0" style={{ backgroundColor: 'var(--high)15', color: 'var(--high)' }}>
                                {ioc.type}
                              </span>
                              <span className="truncate" title={ioc.indicator}>{ioc.indicator}</span>
                            </div>
                          ))}
                        </div>
                        {info.otx_iocs.length > 10 && (
                          <p className="text-xs mt-2" style={{ color: 'var(--text-secondary)' }}>
                            +{info.otx_iocs.length - 10} more indicators
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* ThreatFox IOCs */}
                {info.threatfox_ioc_count != null && info.threatfox_ioc_count > 0 && (
                  <div className="mt-4 rounded-lg p-4" style={{ backgroundColor: 'var(--bg-primary)', border: '1px solid var(--border)' }}>
                    <h4 className="text-xs font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--text-secondary)' }}>
                      <Bug className="w-3.5 h-3.5" style={{ color: 'var(--critical)' }} />
                      THREATFOX IOCs
                      <span className="px-1.5 py-0.5 rounded text-xs" style={{ backgroundColor: 'var(--critical)15', color: 'var(--critical)' }}>
                        {info.threatfox_ioc_count} indicator{info.threatfox_ioc_count !== 1 ? 's' : ''}
                      </span>
                    </h4>
                    {info.threatfox_iocs && info.threatfox_iocs.length > 0 && (
                      <div className="space-y-1.5">
                        {info.threatfox_iocs.slice(0, 10).map((ioc, i) => (
                          <div key={i} className="text-xs p-2 rounded flex items-center gap-3" style={{ backgroundColor: 'var(--bg-card)' }}>
                            <span className="px-1.5 py-0.5 rounded text-[10px] shrink-0 font-medium" style={{ backgroundColor: 'var(--medium)15', color: 'var(--medium)' }}>
                              {ioc.ioc_type}
                            </span>
                            <span className="font-mono truncate flex-1" title={ioc.ioc_value}>{ioc.ioc_value}</span>
                            {ioc.malware && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] shrink-0" style={{ backgroundColor: 'var(--critical)15', color: 'var(--critical)' }}>
                                {ioc.malware}
                              </span>
                            )}
                            <span className="text-[10px] shrink-0" style={{ color: 'var(--text-secondary)' }}>
                              {ioc.confidence_level}%
                            </span>
                          </div>
                        ))}
                        {info.threatfox_iocs.length > 10 && (
                          <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
                            +{info.threatfox_iocs.length - 10} more indicators
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {info.raw_output && info.parse_error && (
                  <div className="mt-4 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-primary)' }}>
                    <p className="text-xs mb-2 flex items-center gap-1" style={{ color: 'var(--medium)' }}>
                      <AlertCircle className="w-3 h-3" /> Raw LLM output (JSON parsing failed)
                    </p>
                    <pre className="text-xs whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>
                      {info.raw_output}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex items-center justify-center h-32">
                <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--accent)' }} />
              </div>
            )}
          </div>
        </div>
      )}

      {/* ATT&CK Techniques */}
      {techniques.length > 0 && (
        <div
          className="rounded-xl p-6 mt-6"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--text-secondary)' }}>
            <Shield className="w-4 h-4" style={{ color: 'var(--accent)' }} />
            MITRE ATT&CK MAPPING
          </h3>

          <div className="space-y-3">
            {techniques.map((t, i) => {
              const tech = t as { technique_id?: string; name?: string; tactics?: string[]; confidence?: number; rationale?: string };
              return (
                <div
                  key={tech.technique_id || i}
                  className="rounded-lg p-4"
                  style={{ backgroundColor: 'var(--bg-primary)', border: '1px solid var(--border)' }}
                >
                  <div className="flex items-start justify-between gap-4 mb-2">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <span
                        className="px-2 py-1 rounded text-xs font-bold font-mono shrink-0"
                        style={{ backgroundColor: 'var(--high)15', color: 'var(--high)', border: '1px solid var(--high)30' }}
                      >
                        {tech.technique_id || '?'}
                      </span>
                      <span className="text-sm font-medium truncate">{tech.name || 'Unknown'}</span>
                    </div>
                    {tech.confidence != null && (
                      <div className="shrink-0 w-40">
                        <ConfidenceBar confidence={tech.confidence} />
                      </div>
                    )}
                  </div>

                  {tech.tactics && tech.tactics.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mb-2">
                      {tech.tactics.map((tactic) => (
                        <TacticBadge key={tactic} tactic={tactic} />
                      ))}
                    </div>
                  )}

                  {tech.rationale && (
                    <p className="text-xs mt-2" style={{ color: 'var(--text-secondary)' }}>
                      {tech.rationale}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Response Playbook */}
      {playbook && (
        <div
          className="rounded-xl p-6 mt-6"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--text-secondary)' }}>
            <FileText className="w-4 h-4" style={{ color: 'var(--low)' }} />
            INCIDENT RESPONSE PLAYBOOK
          </h3>
          <div className="prose">
            <ReactMarkdown>{playbook}</ReactMarkdown>
          </div>
        </div>
      )}

      {/* Sigma Detection Rule */}
      {sigmaRule && (
        <div
          className="rounded-xl p-6 mt-6"
          style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)' }}
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--text-secondary)' }}>
              <Code2 className="w-4 h-4" style={{ color: 'var(--medium)' }} />
              SIGMA DETECTION RULE
            </h3>
            <CopyButton text={sigmaRule} />
          </div>
          <pre
            className="text-xs leading-relaxed rounded-lg p-4 overflow-x-auto"
            style={{
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              color: 'var(--text-secondary)',
              fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
            }}
          >
            {sigmaRule}
          </pre>
        </div>
      )}

      {/* Error */}
      {analysis.error && (
        <div
          className="rounded-xl p-4 mt-4 flex items-center gap-3"
          style={{ backgroundColor: 'var(--critical)15', border: '1px solid var(--critical)40' }}
        >
          <AlertCircle className="w-5 h-5" style={{ color: 'var(--critical)' }} />
          <p className="text-sm" style={{ color: 'var(--critical)' }}>{analysis.error}</p>
        </div>
      )}
    </div>
  );
}
