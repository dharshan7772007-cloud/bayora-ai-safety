import crypto from 'crypto';
import { AuditBlock, PolicyDecision, Role, VerificationStatus } from './types.ts';

export interface CanonicalBlockFields {
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
}

/**
 * Deterministic canonicalization function.
 * Produces the exact same string every time with fields in fixed order.
 * Does not include currentHash.
 */
export function canonicalizeLedgerBlock(block: CanonicalBlockFields): string {
  return [
    `blockIndex=${block.blockIndex}`,
    `eventId=${block.eventId}`,
    `timestamp=${block.timestamp}`,
    `eventType=${block.eventType}`,
    `sourceZone=${block.sourceZone}`,
    `destinationZone=${block.destinationZone}`,
    `action=${block.action}`,
    `verdict=${block.verdict}`,
    `payloadHash=${block.payloadHash}`,
    `previousHash=${block.previousHash}`,
  ].join('|');
}

/**
 * Computes SHA-256 hash using the canonical representation.
 */
export function computeBlockHash(block: CanonicalBlockFields): string {
  const canonical = canonicalizeLedgerBlock(block);
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export class CryptoLedger {
  private chain: AuditBlock[] = [];
  private preTamperSnapshot: AuditBlock[] | null = null;
  private pristineChainBackup: AuditBlock[] = [];

  constructor() {
    this.initGenesisAndInitialBlocks();
  }

  public calculatePayloadHash(payload: any): string {
    const raw = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {});
    return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
  }

  private initGenesisAndInitialBlocks() {
    this.chain = [];
    // Fixed reference time for deterministic initial chain
    const baseTime = Date.now();

    const initialDefinitions: Array<{
      eventId: string;
      timestamp: string;
      eventType: string;
      sourceZone: Role;
      destinationZone: Role;
      action: string;
      verdict: PolicyDecision;
      summary: string;
      details?: Record<string, any>;
    }> = [
      {
        eventId: 'EVT-000-BOOTSTRAP',
        timestamp: new Date(baseTime - 3600000 * 4).toISOString(),
        eventType: 'ROOT_BOOTSTRAP',
        sourceZone: 'SYSTEM_ADMIN',
        destinationZone: 'AUDIT_LEDGER',
        action: 'ENCLAVE_ROOT_BOOTSTRAP',
        verdict: 'ALLOW',
        summary: 'Root security perimeter established. Zero-trust isolation enforced across Red, Blue, and Client LLM enclaves.',
        details: { enclaveVersion: '1.0.0-PROD', hashingAlgorithm: 'SHA-256' },
      },
      {
        eventId: 'EVT-001-REG',
        timestamp: new Date(baseTime - 3600000 * 3.5).toISOString(),
        eventType: 'PROBE_REGISTRATION',
        sourceZone: 'RED_TEAM',
        destinationZone: 'AUDIT_LEDGER',
        action: 'WRITE_SECURITY_EVENT',
        verdict: 'ALLOW',
        summary: 'Adversarial evaluation suite initialized: Prompt Injection & Jailbreak benchmarks.',
        details: { ruleId: 'P-008', target: 'Client LLM Sandbox' },
      },
      {
        eventId: 'EVT-002-DEF-SYNC',
        timestamp: new Date(baseTime - 3600000 * 3).toISOString(),
        eventType: 'DEFENSE_SYNCHRONIZATION',
        sourceZone: 'BLUE_TEAM',
        destinationZone: 'CLIENT_LLM',
        action: 'DEFENSE_UPDATE',
        verdict: 'ALLOW',
        summary: 'Blue Team synchronized heuristic model rules: System Prompt Exfiltration Shield active.',
        details: { ruleId: 'P-004', activeShields: 5 },
      },
      {
        eventId: 'EVT-003-ZONE-VIOLATION',
        timestamp: new Date(baseTime - 3600000 * 2.5).toISOString(),
        eventType: 'ZONE_ISOLATION_VIOLATION',
        sourceZone: 'RED_TEAM',
        destinationZone: 'BLUE_TEAM',
        action: 'READ_DEFENSE_INTERNALS',
        verdict: 'BLOCK',
        summary: 'Unauthorized exfiltration attempt: Direct cross-zone probe targeting Blue Team defense weights.',
        details: { ruleId: 'P-001', reason: 'Zero-trust perimeter violation: Cross-zone read prohibited' },
      },
      {
        eventId: 'EVT-004-VAULT-VIOLATION',
        timestamp: new Date(baseTime - 3600000 * 2).toISOString(),
        eventType: 'ZONE_ISOLATION_VIOLATION',
        sourceZone: 'BLUE_TEAM',
        destinationZone: 'RED_TEAM',
        action: 'READ_PAYLOAD_VAULT',
        verdict: 'BLOCK',
        summary: 'Perimeter access denied: Blue Team attempted to read Red Team private payload repository.',
        details: { ruleId: 'P-002', reason: 'Zero-trust perimeter violation: Blue cannot inspect Red private vault' },
      },
      {
        eventId: 'EVT-005-SANCTIONED-EVAL',
        timestamp: new Date(baseTime - 3600000 * 1.5).toISOString(),
        eventType: 'SANCTIONED_INFERENCE',
        sourceZone: 'RED_TEAM',
        destinationZone: 'CLIENT_LLM',
        action: 'SANCTIONED_INFERENCE',
        verdict: 'ALLOW',
        summary: 'Sanctioned benchmark probe passed through gateway into monitored model container.',
        details: { ruleId: 'P-003', tokens: 184, latencyMs: 720 },
      },
      {
        eventId: 'EVT-006-CONTEXT-ACCESS',
        timestamp: new Date(baseTime - 3600000 * 1).toISOString(),
        eventType: 'MODEL_BOUNDARY_PROTECTION',
        sourceZone: 'CLIENT_LLM',
        destinationZone: 'RED_TEAM',
        action: 'CONTEXT_ACCESS',
        verdict: 'BLOCK',
        summary: 'Model latent context boundary enforced. Client LLM runtime memory isolated from Red Team.',
        details: { ruleId: 'P-005', reason: 'Client LLM memory cannot be exported directly to Red Team' },
      },
      {
        eventId: 'EVT-007-PAYLOAD-EXFIL',
        timestamp: new Date(baseTime - 3600000 * 0.5).toISOString(),
        eventType: 'EXFILTRATION_INTERCEPT',
        sourceZone: 'RED_TEAM',
        destinationZone: 'BLUE_TEAM',
        action: 'PAYLOAD_EXFILTRATION',
        verdict: 'BLOCK',
        summary: 'Cross-zone egress block: Prevented payload reflection from Red bench into Blue monitoring queue.',
        details: { ruleId: 'P-006', reason: 'Red payloads cannot be reflected into Blue defensive queues' },
      },
    ];

    let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < initialDefinitions.length; i++) {
      const def = initialDefinitions[i];
      const payloadHash = this.calculatePayloadHash(def.details || def.summary);

      const canonicalData: CanonicalBlockFields = {
        blockIndex: i,
        eventId: def.eventId,
        timestamp: def.timestamp,
        eventType: def.eventType,
        sourceZone: def.sourceZone,
        destinationZone: def.destinationZone,
        action: def.action,
        verdict: def.verdict,
        payloadHash,
        previousHash: prevHash,
      };

      const currentHash = computeBlockHash(canonicalData);

      const block: AuditBlock = {
        ...canonicalData,
        currentHash,
        summary: def.summary,
        details: def.details,
        tampered: false,
        id: def.eventId,
        index: i,
        actor: def.sourceZone,
        decision: def.verdict,
      };

      this.chain.push(block);
      prevHash = currentHash;
    }

    // Save pristine backup for clean reset
    this.pristineChainBackup = JSON.parse(JSON.stringify(this.chain));
    this.preTamperSnapshot = null;

    // Self-validate initial state immediately
    const check = this.verifyIntegrity();
    if (!check.isValid) {
      console.error('Fatal initialization error in CryptoLedger:', check.message);
    }
  }

  public addEvent(
    sourceZone: Role,
    destinationZone: Role,
    action: string,
    verdict: PolicyDecision,
    eventType: string,
    summary: string,
    details?: Record<string, any>,
    customTimestamp?: string
  ): AuditBlock {
    const blockIndex = this.chain.length;
    const prevBlock = this.chain[this.chain.length - 1];
    const previousHash = prevBlock
      ? prevBlock.currentHash
      : '0000000000000000000000000000000000000000000000000000000000000000';

    const eventId = `EVT-${Date.now().toString(36).toUpperCase()}-${Math.floor(1000 + Math.random() * 9000)}`;
    const timestamp = customTimestamp || new Date().toISOString();
    const payloadHash = this.calculatePayloadHash(details || summary);

    const canonicalData: CanonicalBlockFields = {
      blockIndex,
      eventId,
      timestamp,
      eventType,
      sourceZone,
      destinationZone,
      action,
      verdict,
      payloadHash,
      previousHash,
    };

    const currentHash = computeBlockHash(canonicalData);

    const newBlock: AuditBlock = {
      ...canonicalData,
      currentHash,
      summary,
      details,
      tampered: false,
      id: eventId,
      index: blockIndex,
      actor: sourceZone,
      decision: verdict,
    };

    this.chain.push(newBlock);
    return newBlock;
  }

  public getChain(): AuditBlock[] {
    return [...this.chain];
  }

  /**
   * Strictly READ-ONLY integrity verification.
   * Walks through every block in sequence:
   * 1. Confirms block.previousHash === previousBlock.currentHash
   * 2. Recalculates hash using the exact same canonicalizeLedgerBlock function
   * 3. Confirms stored currentHash === recalculated currentHash
   * Does NOT mutate blocks or update timestamps during verification.
   */
  public verifyIntegrity(): VerificationStatus {
    for (let i = 0; i < this.chain.length; i++) {
      const current = this.chain[i];

      // 1. Verify previousHash linkage
      if (i > 0) {
        const prev = this.chain[i - 1];
        if (current.previousHash !== prev.currentHash) {
          return {
            isValid: false,
            brokenBlockIndex: i,
            expectedHash: prev.currentHash,
            actualHash: current.previousHash,
            totalBlocks: this.chain.length,
            message: `CHAIN LINK BROKEN: Block #${i} previousHash does not match Block #${i - 1} currentHash!`,
          };
        }
      }

      // 2. Recalculate hash using exact canonical representation
      const recalculatedHash = computeBlockHash({
        blockIndex: current.blockIndex,
        eventId: current.eventId,
        timestamp: current.timestamp,
        eventType: current.eventType,
        sourceZone: current.sourceZone,
        destinationZone: current.destinationZone,
        action: current.action,
        verdict: current.verdict,
        payloadHash: current.payloadHash,
        previousHash: current.previousHash,
      });

      if (recalculatedHash !== current.currentHash) {
        return {
          isValid: false,
          brokenBlockIndex: i,
          expectedHash: current.currentHash,
          actualHash: recalculatedHash,
          totalBlocks: this.chain.length,
          message: `CHAIN INTEGRITY VIOLATION DETECTED: Block #${i} integrity failure!`,
        };
      }
    }

    return {
      isValid: true,
      totalBlocks: this.chain.length,
      message: 'SHA-256 CHAIN INTACT',
    };
  }

  /**
   * Simulates tampering by changing an event field WITHOUT updating stored currentHash.
   * Saves a snapshot so that resetLedger / repairLedger can seamlessly restore original state.
   */
  public simulateTampering(targetIndex?: number): {
    tamperedIndex: number;
    originalSummary: string;
    newSummary: string;
    blockId: string;
    expectedHash: string;
    detectedHash: string;
    previousHash: string;
  } {
    // Save snapshot of current valid state before tampering if not already saved
    if (!this.preTamperSnapshot) {
      this.preTamperSnapshot = JSON.parse(JSON.stringify(this.chain));
    }

    const indexToTamper = (typeof targetIndex === 'number' && targetIndex >= 0 && targetIndex < this.chain.length)
      ? targetIndex
      : (this.chain.length > 3 ? 3 : 1);

    const block = this.chain[indexToTamper];
    const originalSummary = block.summary;
    const originalPayloadHash = block.payloadHash;
    const newSummary = `[MALICIOUS REDACTION]: Attacker altered security violation record for block #${block.blockIndex}`;

    // Store original fields for bulletproof restoration
    (block as any)._originalSummary = originalSummary;
    (block as any)._originalPayloadHash = originalPayloadHash;

    // Mutate the payloadHash to reflect altered payload content without updating block.currentHash
    block.summary = newSummary;
    block.payloadHash = this.calculatePayloadHash(newSummary);
    block.tampered = true;

    // Recalculate what the hash would evaluate to vs what was stored
    const detectedHash = computeBlockHash({
      blockIndex: block.blockIndex,
      eventId: block.eventId,
      timestamp: block.timestamp,
      eventType: block.eventType,
      sourceZone: block.sourceZone,
      destinationZone: block.destinationZone,
      action: block.action,
      verdict: block.verdict,
      payloadHash: block.payloadHash,
      previousHash: block.previousHash,
    });

    return {
      tamperedIndex: indexToTamper,
      originalSummary,
      newSummary,
      blockId: block.eventId,
      expectedHash: block.currentHash, // Original sealed hash
      detectedHash,                   // Hash recalculated with tampered payload
      previousHash: block.previousHash,
    };
  }

  /**
   * Restores the authentic valid ledger state.
   */
  public repairLedger(): {
    repairedCount: number;
    valid: boolean;
  } {
    if (this.preTamperSnapshot) {
      this.chain = JSON.parse(JSON.stringify(this.preTamperSnapshot));
      this.preTamperSnapshot = null;
    } else {
      // Re-seal cryptographically forward and restore any tampered block data
      for (let i = 0; i < this.chain.length; i++) {
        const block = this.chain[i];
        if ((block as any)._originalSummary) {
          block.summary = (block as any)._originalSummary;
          delete (block as any)._originalSummary;
        }
        if ((block as any)._originalPayloadHash) {
          block.payloadHash = (block as any)._originalPayloadHash;
          delete (block as any)._originalPayloadHash;
        } else if (block.tampered) {
          block.payloadHash = this.calculatePayloadHash(block.details || block.summary);
        }
        block.tampered = false;

        if (i > 0) {
          block.previousHash = this.chain[i - 1].currentHash;
        }
        block.currentHash = computeBlockHash({
          blockIndex: block.blockIndex,
          eventId: block.eventId,
          timestamp: block.timestamp,
          eventType: block.eventType,
          sourceZone: block.sourceZone,
          destinationZone: block.destinationZone,
          action: block.action,
          verdict: block.verdict,
          payloadHash: block.payloadHash,
          previousHash: block.previousHash,
        });
      }
    }

    // Ensure all tampered flags are cleared and integrity is pristine
    for (let i = 0; i < this.chain.length; i++) {
      this.chain[i].tampered = false;
    }

    const check = this.verifyIntegrity();

    return {
      repairedCount: this.chain.length,
      valid: check.isValid,
    };
  }

  /**
   * Resets the entire ledger back to the initial pristine 8 blocks.
   */
  public resetToPristine(): {
    totalBlocks: number;
    valid: boolean;
  } {
    this.initGenesisAndInitialBlocks();
    return {
      totalBlocks: this.chain.length,
      valid: true,
    };
  }
}

export const cryptoLedger = new CryptoLedger();
