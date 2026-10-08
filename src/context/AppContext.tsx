import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { 
  AttackPayload, 
  AuditBlock, 
  BayoraSharedState, 
  DashboardMetrics, 
  DefenseRule, 
  EvaluationRun, 
  ModelSession, 
  PolicyRule, 
  Role, 
  SecurityEvent, 
  SystemStatus, 
  VerificationStatus 
} from '../types.ts';

export type AppView = 
  | 'dashboard'
  | 'evaluations'
  | 'security_tests'
  | 'red_team'
  | 'client_llm'
  | 'blue_team'
  | 'policy_gateway'
  | 'audit_ledger';

interface AppContextType {
  activeRole: Role;
  setActiveRole: (role: Role) => void;
  currentView: AppView;
  setCurrentView: (view: AppView) => void;
  sharedState: BayoraSharedState | null;
  status: SystemStatus | null;
  evaluations: EvaluationRun[];
  policyRules: PolicyRule[];
  attackVectors: AttackPayload[];
  defenseRules: DefenseRule[];
  modelSessions: ModelSession[];
  auditBlocks: AuditBlock[];
  securityEvents: SecurityEvent[];
  metrics: DashboardMetrics | null;
  verification: VerificationStatus | null;
  activeEvaluationId: string | null;
  setActiveEvaluationId: (id: string | null) => void;
  isLoading: boolean;
  error: string | null;
  notification: { message: string; type: 'info' | 'success' | 'warn' | 'error' } | null;
  setNotification: (notif: { message: string; type: 'info' | 'success' | 'warn' | 'error' } | null) => void;
  refreshAllState: () => Promise<void>;
  refreshStatus: () => Promise<void>;
  refreshEvaluations: () => Promise<void>;
  refreshLedger: () => Promise<void>;
  apiFetch: (endpoint: string, options?: RequestInit) => Promise<any>;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeRole, setActiveRole] = useState<Role>('SYSTEM_ADMIN');
  const [currentView, setCurrentView] = useState<AppView>('dashboard');
  const [sharedState, setSharedState] = useState<BayoraSharedState | null>(null);
  const [activeEvaluationId, setActiveEvaluationId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ message: string; type: 'info' | 'success' | 'warn' | 'error' } | null>(null);

  const apiFetch = useCallback(async (endpoint: string, options: RequestInit = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      'x-bayora-role': activeRole,
      ...(options.headers || {}),
    };

    const res = await fetch(endpoint, {
      ...options,
      headers,
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.reason || data.error || data.message || `HTTP error ${res.status}`);
    }
    return data;
  }, [activeRole]);

  const refreshAllState = useCallback(async () => {
    try {
      setError(null);
      const data = await apiFetch('/api/state');
      setSharedState(data);
      if (data.evaluations && data.evaluations.length > 0 && !activeEvaluationId) {
        setActiveEvaluationId(data.evaluations[0].id);
      }
    } catch (err: any) {
      console.error('Failed to load shared state:', err);
      setError(err.message || 'Failed to connect to Bayora security state');
    }
  }, [apiFetch, activeEvaluationId]);

  const refreshStatus = useCallback(async () => {
    await refreshAllState();
  }, [refreshAllState]);

  const refreshEvaluations = useCallback(async () => {
    await refreshAllState();
  }, [refreshAllState]);

  const refreshLedger = useCallback(async () => {
    await refreshAllState();
  }, [refreshAllState]);

  useEffect(() => {
    let isMounted = true;
    async function init() {
      setIsLoading(true);
      try {
        await refreshAllState();
      } catch (err: any) {
        if (isMounted) setError(err.message);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }
    init();

    // Periodic state synchronization every 8 seconds
    const interval = setInterval(() => {
      refreshAllState();
    }, 8000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [refreshAllState]);

  // Auto-dismiss notification after 4 seconds
  useEffect(() => {
    if (notification) {
      const timer = setTimeout(() => {
        setNotification(null);
      }, 4000);
      return () => clearTimeout(timer);
    }
  }, [notification]);

  // Derived state values with safe fallbacks
  const status: SystemStatus | null = sharedState ? {
    enclaveStatus: sharedState.enclaveStatus,
    timestamp: new Date().toISOString(),
    zones: sharedState.zones,
    metrics: sharedState.dashboardMetrics,
  } : null;

  const evaluations: EvaluationRun[] = sharedState?.evaluations || [];
  const policyRules: PolicyRule[] = sharedState?.policyRules || [];
  const attackVectors: AttackPayload[] = sharedState?.redTeamAttackVectors || [];
  const defenseRules: DefenseRule[] = sharedState?.blueTeamDefenseRules || [];
  const modelSessions: ModelSession[] = sharedState?.clientLLMSessions || [];
  const auditBlocks: AuditBlock[] = sharedState?.auditLedgerBlocks || [];
  const securityEvents: SecurityEvent[] = sharedState?.securityEvents || [];
  const metrics: DashboardMetrics | null = sharedState?.dashboardMetrics || null;
  const verification: VerificationStatus | null = sharedState?.verification || null;

  return (
    <AppContext.Provider
      value={{
        activeRole,
        setActiveRole,
        currentView,
        setCurrentView,
        sharedState,
        status,
        evaluations,
        policyRules,
        attackVectors,
        defenseRules,
        modelSessions,
        auditBlocks,
        securityEvents,
        metrics,
        verification,
        activeEvaluationId,
        setActiveEvaluationId,
        isLoading,
        error,
        notification,
        setNotification,
        refreshAllState,
        refreshStatus,
        refreshEvaluations,
        refreshLedger,
        apiFetch,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};
