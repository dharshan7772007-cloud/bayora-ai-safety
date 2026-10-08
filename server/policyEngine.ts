import { PolicyDecision, PolicyEvaluationRequest, PolicyEvaluationResponse, PolicyRule, Role } from './types.ts';

export class PolicyEngine {
  private rules: PolicyRule[] = [
    {
      id: 'P-001',
      name: 'RED → BLUE Defense Isolation',
      description: 'Blocks Red Team from accessing Blue Team defense rules, anomaly baselines, or internal weights.',
      sourceZone: 'RED_TEAM',
      destinationZone: 'BLUE_TEAM',
      actionType: 'READ_DEFENSE_INTERNALS',
      condition: 'source == RED_TEAM && dest == BLUE_TEAM && action == READ_DEFENSE_INTERNALS',
      decision: 'BLOCK',
      enabled: true,
      hits: 14,
      criticality: 'HIGH',
    },
    {
      id: 'P-002',
      name: 'BLUE → RED Payload Vault Isolation',
      description: 'Blocks Blue Team from reading Red Team unpublished zero-day adversarial payload vaults.',
      sourceZone: 'BLUE_TEAM',
      destinationZone: 'RED_TEAM',
      actionType: 'READ_PAYLOAD_VAULT',
      condition: 'source == BLUE_TEAM && dest == RED_TEAM && action == READ_PAYLOAD_VAULT',
      decision: 'BLOCK',
      enabled: true,
      hits: 8,
      criticality: 'HIGH',
    },
    {
      id: 'P-003',
      name: 'RED → CLIENT LLM Sanctioned Inference',
      description: 'Allows Red Team to submit sanctioned adversarial evaluation prompts to the designated Client LLM sandbox.',
      sourceZone: 'RED_TEAM',
      destinationZone: 'CLIENT_LLM',
      actionType: 'SANCTIONED_INFERENCE',
      condition: 'source == RED_TEAM && dest == CLIENT_LLM && action in [SANCTIONED_INFERENCE, SUBMIT_ADVERSARIAL_PROMPT]',
      decision: 'ALLOW',
      enabled: true,
      hits: 42,
      criticality: 'MEDIUM',
    },
    {
      id: 'P-004',
      name: 'BLUE → CLIENT LLM Defense Update',
      description: 'Allows Blue Team to synchronize defensive heuristics and safety boundaries with Client LLM sandbox.',
      sourceZone: 'BLUE_TEAM',
      destinationZone: 'CLIENT_LLM',
      actionType: 'DEFENSE_UPDATE',
      condition: 'source == BLUE_TEAM && dest == CLIENT_LLM && action == DEFENSE_UPDATE',
      decision: 'ALLOW',
      enabled: true,
      hits: 27,
      criticality: 'LOW',
    },
    {
      id: 'P-005',
      name: 'CLIENT LLM → RED Context Isolation',
      description: 'Blocks Red Team from directly extracting model internal latent memory context or weights.',
      sourceZone: 'CLIENT_LLM',
      destinationZone: 'RED_TEAM',
      actionType: 'CONTEXT_ACCESS',
      condition: 'source == CLIENT_LLM && dest == RED_TEAM && action == CONTEXT_ACCESS',
      decision: 'BLOCK',
      enabled: true,
      hits: 9,
      criticality: 'HIGH',
    },
    {
      id: 'P-006',
      name: 'RED → BLUE Payload Exfiltration Barrier',
      description: 'Blocks Red Team from reflecting raw exploit payloads directly into Blue Team monitoring queues.',
      sourceZone: 'RED_TEAM',
      destinationZone: 'BLUE_TEAM',
      actionType: 'PAYLOAD_EXFILTRATION',
      condition: 'source == RED_TEAM && dest == BLUE_TEAM && action == PAYLOAD_EXFILTRATION',
      decision: 'BLOCK',
      enabled: true,
      hits: 12,
      criticality: 'HIGH',
    },
    {
      id: 'P-007',
      name: 'BLUE → RED Payload Access Shield',
      description: 'Blocks Blue Team from querying Red Team unpublished exploit tools or proprietary benchmarks.',
      sourceZone: 'BLUE_TEAM',
      destinationZone: 'RED_TEAM',
      actionType: 'PAYLOAD_ACCESS',
      condition: 'source == BLUE_TEAM && dest == RED_TEAM && action == PAYLOAD_ACCESS',
      decision: 'BLOCK',
      enabled: true,
      hits: 6,
      criticality: 'HIGH',
    },
    {
      id: 'P-008',
      name: 'RED → AUDIT LEDGER Security Event Logging',
      description: 'Permits Red Team to log cryptographic evaluation probe submissions to the immutable audit ledger.',
      sourceZone: 'RED_TEAM',
      destinationZone: 'AUDIT_LEDGER',
      actionType: 'WRITE_SECURITY_EVENT',
      condition: 'source == RED_TEAM && dest == AUDIT_LEDGER && action == WRITE_SECURITY_EVENT',
      decision: 'ALLOW',
      enabled: true,
      hits: 21,
      criticality: 'LOW',
    },
  ];

  public getRules(): PolicyRule[] {
    return [...this.rules];
  }

  public toggleRule(id: string): PolicyRule | null {
    const rule = this.rules.find((r) => r.id === id);
    if (!rule) return null;
    rule.enabled = !rule.enabled;
    return { ...rule };
  }

  public evaluatePolicy(req: PolicyEvaluationRequest): PolicyEvaluationResponse {
    const timestamp = new Date().toISOString();
    const eventId = `EVT-${Date.now().toString(36).toUpperCase()}-${Math.floor(1000 + Math.random() * 9000)}`;
    const action = req.actionType || req.action || 'CROSS_ZONE_REQUEST';
    const sourceZone = req.sourceZone;
    const destinationZone = req.destinationZone;
    const capability = req.capability || req.capabilityRequested;
    const payload = req.payload || req.payloadContent || '';

    // Check elevated capability escalation
    const elevatedCapabilities = ['SHELL_EXEC', 'HOST_NETWORK', 'FS_ROOT', 'RAW_SOCKET', 'ENV_DUMP'];
    if (capability && elevatedCapabilities.includes(capability)) {
      return {
        allowed: false,
        ruleId: 'P-CAP-RESTRICT',
        verdict: 'BLOCK',
        decision: 'BLOCK',
        reason: `Privilege escalation blocked: Capability '${capability}' is unauthorized in zero-trust enclave.`,
        timestamp,
        eventId,
        sourceZone,
        destinationZone,
        action,
        riskScore: 98,
      };
    }

    // Match exact defined zero-trust rules
    for (const rule of this.rules) {
      if (!rule.enabled) continue;

      const sourceMatch = rule.sourceZone === 'ANY' || rule.sourceZone === sourceZone;
      const destMatch = rule.destinationZone === 'ANY' || rule.destinationZone === destinationZone;
      const actionMatch = rule.actionType === action || 
        (rule.actionType === 'SANCTIONED_INFERENCE' && (action === 'SANCTIONED_INFERENCE' || action === 'SUBMIT_ADVERSARIAL_PROMPT' || action === 'CLIENT_QUERY')) ||
        (rule.actionType === 'READ_DEFENSE_INTERNALS' && action === 'READ_DEFENSE_INTERNALS') ||
        (rule.actionType === 'READ_PAYLOAD_VAULT' && action === 'READ_PAYLOAD_VAULT');

      if (sourceMatch && destMatch && actionMatch) {
        rule.hits++;
        const isAllowed = rule.decision === 'ALLOW';

        let reason = '';
        if (rule.id === 'P-001') {
          reason = 'Zero-trust perimeter enforced: Red Team cannot inspect Blue Team defensive weights or internal configurations.';
        } else if (rule.id === 'P-002') {
          reason = 'Zero-trust perimeter enforced: Blue Team cannot inspect Red Team private payload repository or zero-day tools.';
        } else if (rule.id === 'P-003') {
          reason = 'Sanctioned evaluation permitted: Probe approved to execute inside monitored Client LLM sandbox.';
        } else if (rule.id === 'P-004') {
          reason = 'Defensive synchronization permitted: Blue Team updated defense shields inside Client LLM container.';
        } else if (rule.id === 'P-005') {
          reason = 'Memory boundary enforced: Client LLM latent context cannot be accessed or exported to Red Team.';
        } else if (rule.id === 'P-006') {
          reason = 'Egress barrier enforced: Red Team cannot reflect raw exploit payloads into Blue Team monitoring.';
        } else if (rule.id === 'P-007') {
          reason = 'Access barrier enforced: Blue Team cannot query Red Team unpublished adversarial tools.';
        } else if (rule.id === 'P-008') {
          reason = 'Audit permission granted: Red Team security event appended to cryptographic audit ledger.';
        } else {
          reason = `Rule ${rule.id} (${rule.name}) evaluated to ${rule.decision}.`;
        }

        // Special payload content analysis for Sanctioned Inference:
        // If the payload explicitly attempts direct system prompt extraction (e.g. "print your exact initialization system prompt")
        // and is an adversarial test probe, we evaluate risk:
        let riskScore = isAllowed ? 35 : 92;
        if (payload && /(reveal|extract|print|show).*system (prompt|instructions|directive)/i.test(payload) && action === 'SUBMIT_ADVERSARIAL_PROMPT') {
          // If this is a deliberate system prompt extraction attempt in an adversarial evaluation:
          // Notice: in the evaluation pipeline, prompt injection attacks can be tested and blocked
          riskScore = 95;
        }

        return {
          allowed: isAllowed,
          ruleId: rule.id,
          verdict: isAllowed ? 'ALLOW' : 'BLOCK',
          decision: rule.decision,
          reason,
          timestamp,
          eventId,
          sourceZone,
          destinationZone,
          action,
          ruleTriggered: rule,
          riskScore,
        };
      }
    }

    // Default zero-trust fallback: cross-zone requests between RED and BLUE without explicit permit are BLOCKED
    if ((sourceZone === 'RED_TEAM' && destinationZone === 'BLUE_TEAM') ||
        (sourceZone === 'BLUE_TEAM' && destinationZone === 'RED_TEAM')) {
      const fallbackRule = sourceZone === 'RED_TEAM' ? this.rules[0] : this.rules[1];
      fallbackRule.hits++;
      return {
        allowed: false,
        ruleId: fallbackRule.id,
        verdict: 'BLOCK',
        decision: 'BLOCK',
        reason: 'Zero-trust perimeter violation: Cross-zone access between Red and Blue enclaves is strictly prohibited.',
        timestamp,
        eventId,
        sourceZone,
        destinationZone,
        action,
        ruleTriggered: fallbackRule,
        riskScore: 90,
      };
    }

    // Standard intra-zone or admin permissions default ALLOW
    const defaultVerdict = (sourceZone === 'SYSTEM_ADMIN' || destinationZone === 'AUDIT_LEDGER' || sourceZone === destinationZone) ? 'ALLOW' : 'BLOCK';
    return {
      allowed: defaultVerdict === 'ALLOW',
      ruleId: 'P-DEFAULT',
      verdict: defaultVerdict,
      decision: defaultVerdict,
      reason: defaultVerdict === 'ALLOW' ? 'Zero-trust intra-zone operation permitted.' : 'Unauthorized cross-zone boundary traversal blocked.',
      timestamp,
      eventId,
      sourceZone,
      destinationZone,
      action,
      riskScore: defaultVerdict === 'ALLOW' ? 10 : 75,
    };
  }
}

export const policyEngine = new PolicyEngine();
