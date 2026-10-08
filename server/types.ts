export type Role = 'RED_TEAM' | 'BLUE_TEAM' | 'CLIENT_LLM' | 'POLICY_ENGINE' | 'SYSTEM_ADMIN' | 'AUDIT_LEDGER';

export type PolicyDecision = 'ALLOW' | 'BLOCK' | 'AUDIT' | 'QUARANTINE';

export type PipelineStage = 
  | 'REGISTER'
  | 'ISOLATE'
  | 'ATTACK'
  | 'POLICY_GATE'
  | 'INFERENCE'
  | 'DEFEND'
  | 'VERIFY'
  | 'FINDING';

export interface AuditBlock {
  blockIndex: number;
  eventId: string;
  timestamp: string;
  eventType: string;
  sourceZone: Role;
  destinationZone: Role;
  action: string;
  verdict: PolicyDecision;
  payloadHash: string;
  previousHash: string;
  currentHash: string;
  summary: string;
  details?: Record<string, any>;
  tampered?: boolean;

  // Compatibility aliases
  id?: string;
  index?: number;
  actor?: Role;
  decision?: PolicyDecision;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  actor: Role;
  type: string;
  severity: 'INFO' | 'WARN' | 'CRITICAL' | 'SUCCESS';
  message: string;
  decision?: PolicyDecision;
  meta?: Record<string, any>;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  sourceZone: Role | 'ANY';
  destinationZone: Role | 'ANY';
  actionType: string;
  condition: string;
  decision: PolicyDecision;
  enabled: boolean;
  hits: number;
  criticality: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface AttackPayload {
  id: string;
  category: 'Jailbreak' | 'Prompt Injection' | 'Data Extraction' | 'Denial of Service' | 'Tool Misuse' | 'Role Confusion';
  name: string;
  description: string;
  prompt: string;
  riskScore: number; // 0-100
  mitigationSuggestion: string;
}

export interface DefenseRule {
  id: string;
  name: string;
  category: 'Prompt Guard' | 'PII Scrubber' | 'Token Boundary' | 'Output Redactor' | 'Exfiltration Shield';
  enabled: boolean;
  sensitivity: 'Low' | 'Medium' | 'Strict';
  blockedCount: number;
  description: string;
}

export interface EvaluationStageDetail {
  stageName: PipelineStage;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'BLOCKED' | 'FAILED' | 'SUCCESS';
  startedAt?: string;
  completedAt?: string;
  eventId?: string;
  message?: string;
  summary?: string;
  details?: Record<string, any>;
  data?: Record<string, any>;
  auditBlockId?: string | number;
}

export interface EvaluationRun {
  // Canonical specification fields
  id: string;
  evaluationId?: string; // alias for id
  name?: string; // alias for title
  title: string;
  attackType?: string; // alias for attackCategory
  attackCategory: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'BLOCKED' | 'FAILED';
  createdAt: string;
  updatedAt?: string;
  sourceZone?: Role;
  targetZone?: Role;
  targetModel: string;
  currentStage: PipelineStage;
  stages?: EvaluationStageDetail[];
  stageResults: {
    [key in PipelineStage]?: {
      completedAt: string;
      status: 'SUCCESS' | 'COMPLETED' | 'BLOCKED' | 'WARNING' | 'FAILED';
      summary: string;
      data?: Record<string, any>;
      eventId?: string;
      auditBlockId?: string | number;
    };
  };
  finding?: {
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    vulnerabilityIdentified: boolean;
    cveIdentifier?: string;
    description: string;
    recommendation: string;
  };
  eventIds?: string[];
  auditBlockIds?: (string | number)[];
  finalVerdict?: 'MITIGATED' | 'BLOCKED' | 'PASSED' | 'VIOLATION' | 'FAILED' | 'PENDING';
  
  // Adversarial & execution telemetry
  adversarialPrompt: string;
  policyDecision?: PolicyDecision;
  triggeredRules?: string[];
  llmResponse?: string;
  tokensUsed?: number;
  latencyMs?: number;
  auditHash?: string;
}

export interface ModelSession {
  id: string;
  name: string;
  systemContext: string;
  startedAt: string;
  totalTokens: number;
  approvedRequestsCount: number;
  blockedAttemptsDropped: number;
  lastActive: string;
}

export interface PolicyEvaluationRequest {
  sourceZone: Role;
  destinationZone: Role;
  actionType?: string;
  action?: string;
  payload?: string;
  payloadContent?: string;
  capability?: string;
  capabilityRequested?: string;
}

export interface PolicyEvaluationResponse {
  allowed: boolean;
  ruleId: string;
  verdict: 'ALLOW' | 'BLOCK';
  decision?: PolicyDecision;
  reason: string;
  timestamp: string;
  eventId: string;
  sourceZone: Role;
  destinationZone: Role;
  action: string;
  ruleTriggered?: PolicyRule;
  riskScore?: number;
}

export interface VerificationStatus {
  isValid: boolean;
  brokenBlockIndex?: number;
  expectedHash?: string;
  actualHash?: string;
  totalBlocks: number;
  message: string;
}

export interface DashboardMetrics {
  totalEvaluations: number;
  threatsMitigated: number;
  policyRulesActive: number;
  ledgerBlocks: number;
  zeroTrustInvariants: string;
  activeShieldsCount: number;
  totalShieldsCount: number;
}

export interface SystemStatus {
  enclaveStatus: string;
  timestamp: string;
  zones: {
    redTeam: {
      status: string;
      description: string;
      activeProbesCount: number;
      payloadsLoaded: number;
    };
    clientLLM: {
      status: string;
      description: string;
      model: string;
      totalRequestsHandled: number;
    };
    blueTeam: {
      status: string;
      description: string;
      activeDefensesCount: number;
    };
    policyGateway: {
      status: string;
      activeRulesCount: number;
      totalEvaluated: number;
    };
    auditLedger: {
      status: string;
      totalBlocks: number;
      isValid: boolean;
      algorithm: string;
    };
  };
  metrics: DashboardMetrics;
}

export interface SecurityTestResult {
  testId: 'TEST-001' | 'TEST-002' | 'TEST-003' | 'TEST-004';
  name: string;
  flow: string;
  sourceZone: Role;
  destinationZone: Role;
  action: string;
  expectedPolicy: 'ALLOW' | 'BLOCK';
  expectedModel: 'EXECUTED' | 'NOT EXECUTED';
  expectedEvidence: string;
  status: 'PENDING' | 'RUNNING' | 'PASS' | 'FAIL' | 'ERROR';
  actualPolicy?: 'ALLOW' | 'BLOCK';
  actualModel?: 'EXECUTED' | 'NOT EXECUTED';
  ruleId?: string;
  ruleName?: string;
  reason?: string;
  eventId?: string;
  evaluationId?: string;
  auditBlockIndex?: number;
  auditHash?: string;
  tokensUsed?: number;
  latencyMs?: number;
  evidenceSummary?: string;
  executedAt?: string;
  error?: string;
}

export interface SecurityVerificationSummary {
  totalTests: number;
  passedCount: number;
  failedCount: number;
  pendingCount: number;
  overallStatus: 'PASS' | 'FAIL' | 'PENDING';
  ledgerStatus: 'INTACT' | 'VIOLATION';
  totalBlocks: number;
  regressionCheck: 'PASS' | 'FAIL';
  lastRunAt?: string;
}

export interface BayoraSharedState {
  evaluations: EvaluationRun[];
  policyRules: PolicyRule[];
  redTeamAttackVectors: AttackPayload[];
  blueTeamDefenseRules: DefenseRule[];
  clientLLMSessions: ModelSession[];
  auditLedgerBlocks: AuditBlock[];
  securityEvents: SecurityEvent[];
  dashboardMetrics: DashboardMetrics;
  zones: SystemStatus['zones'];
  enclaveStatus: string;
  verification: VerificationStatus;
  securityTestMatrix?: SecurityTestResult[];
}
