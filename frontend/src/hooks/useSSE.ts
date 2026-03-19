import { useState, useCallback, useRef } from 'react';
import { streamAnalysis } from '../api/client';
import type { AgentUpdate, ExtractedInfo } from '../types';

interface AnalysisState {
  isLoading: boolean;
  agentUpdates: AgentUpdate[];
  extractedInfo: ExtractedInfo | null;
  attackTechniques: Record<string, unknown>[];
  playbook: string;
  sigmaRule: string;
  error: string | null;
  currentAgent: string | null;
}

export function useAnalysis() {
  const [state, setState] = useState<AnalysisState>({
    isLoading: false,
    agentUpdates: [],
    extractedInfo: null,
    attackTechniques: [],
    playbook: '',
    sigmaRule: '',
    error: null,
    currentAgent: null,
  });

  const abortRef = useRef<(() => void) | null>(null);

  const startAnalysis = useCallback((cveId: string, cveDescription: string, model?: string) => {
    // Cancel any ongoing analysis
    if (abortRef.current) abortRef.current();

    setState({
      isLoading: true,
      agentUpdates: [],
      extractedInfo: null,
      attackTechniques: [],
      playbook: '',
      sigmaRule: '',
      error: null,
      currentAgent: null,
    });

    const cancel = streamAnalysis(
      cveId,
      cveDescription,
      (agent, output) => {
        setState((prev) => {
          const update: AgentUpdate = { agent, output };
          const newState = {
            ...prev,
            currentAgent: agent,
            agentUpdates: [...prev.agentUpdates, update],
          };

          if (agent === 'cve_extractor' && output.extracted_info) {
            newState.extractedInfo = output.extracted_info as ExtractedInfo;
          }
          if (agent === 'attack_classifier' && output.attack_techniques) {
            newState.attackTechniques = output.attack_techniques as Record<string, unknown>[];
          }
          if (agent === 'playbook_generator') {
            if (output.response_playbook) newState.playbook = output.response_playbook as string;
            if (output.sigma_rule) newState.sigmaRule = output.sigma_rule as string;
          }

          return newState;
        });
      },
      () => {
        setState((prev) => ({ ...prev, isLoading: false, currentAgent: null }));
      },
      (error) => {
        setState((prev) => ({ ...prev, isLoading: false, error, currentAgent: null }));
      },
      model,
    );

    abortRef.current = cancel;
  }, []);

  const cancelAnalysis = useCallback(() => {
    if (abortRef.current) {
      abortRef.current();
      setState((prev) => ({ ...prev, isLoading: false, currentAgent: null }));
    }
  }, []);

  return { ...state, startAnalysis, cancelAnalysis };
}
