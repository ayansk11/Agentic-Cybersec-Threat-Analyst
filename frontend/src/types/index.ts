export interface ExtractedInfo {
  summary?: string;
  severity_assessment?: string;
  attack_vector?: string;
  attack_complexity?: string;
  privileges_required?: string;
  user_interaction?: string;
  affected_software?: string[];
  cwe_category?: string;
  vulnerability_type?: string;
  potential_impact?: string;
  iocs?: string[];
  key_risk_factors?: string[];
  exploitation_likelihood?: string;
  recommended_priority?: string;
  nvd_cvss_score?: number | null;
  nvd_severity?: string;
  nvd_cwes?: string[];
  cisa_kev?: boolean;
  cve_id?: string;
  raw_output?: string;
  parse_error?: boolean;
  otx_pulses?: Array<{ pulse_id: string; name: string; iocs: Array<{ type: string; indicator: string }> }>;
  otx_iocs?: Array<{ type: string; indicator: string; description?: string }>;
  otx_pulse_count?: number;
  threatfox_iocs?: Array<{ ioc_type: string; ioc_value: string; malware: string; confidence_level: number }>;
  threatfox_ioc_count?: number;
}

export interface AttackTechnique {
  technique_id: string;
  name: string;
  tactics: string[];
  confidence: number;
}

export interface AnalysisResult {
  cve_id: string;
  extracted_info: ExtractedInfo;
  attack_techniques: AttackTechnique[];
  response_playbook: string;
  sigma_rule: string;
}

export interface AgentUpdate {
  agent: string;
  output: Record<string, unknown>;
}

export interface SSEEvent {
  event: string;
  data: string;
}

export interface AnalysisHistoryItem {
  id: number;
  cve_id: string;
  cve_description: string;
  severity: string;
  created_at: string;
  extracted_info: Record<string, unknown>;
  attack_techniques: Array<{ technique_id: string; name: string; tactics: string[]; confidence: number }>;
  response_playbook: string;
  sigma_rule: string;
}
