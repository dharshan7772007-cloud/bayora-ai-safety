import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext.tsx';
import { AuditBlock, VerificationStatus } from '../types.ts';
import { 
  Database, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  RefreshCw, 
  Link as LinkIcon, 
  Hash, 
  Wrench, 
  Flame,
  FileCheck2,
  Lock
} from 'lucide-react';

export const AuditLedgerView: React.FC = () => {
  const { auditBlocks, verification, refreshAllState, apiFetch, setNotification, isLoading, error } = useApp();
  const [selectedBlock, setSelectedBlock] = useState<AuditBlock | null>(null);
  const [localVerification, setLocalVerification] = useState<VerificationStatus | null>(verification);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isTampering, setIsTampering] = useState(false);
  const [isRepairing, setIsRepairing] = useState(false);
  const [tamperDetails, setTamperDetails] = useState<any>(null);

  useEffect(() => {
    if (auditBlocks.length > 0 && !selectedBlock) {
      setSelectedBlock(auditBlocks[auditBlocks.length - 1]);
    }
    if (verification) {
      setLocalVerification(verification);
    }
  }, [auditBlocks, verification, selectedBlock]);

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      const res: VerificationStatus = await apiFetch('/api/audit/verify');
      setLocalVerification(res);
      await refreshAllState();

      if (res.isValid) {
        setNotification({
          message: `SHA-256 CHAIN INTACT: All ${res.totalBlocks} blocks verified across cryptographic linkage.`,
          type: 'success',
        });
      } else {
        setNotification({
          message: `CHAIN INTEGRITY VIOLATION DETECTED: Block #${res.brokenBlockIndex} integrity failure!`,
          type: 'error',
        });
      }
    } catch (err: any) {
      setNotification({ message: err.message || 'Verification failed', type: 'error' });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSimulateTamper = async () => {
    setIsTampering(true);
    try {
      // Pick block #3 (Zone isolation violation record) or block #2
      const targetIndex = auditBlocks.length > 3 ? 3 : 2;
      const res = await apiFetch('/api/audit/tamper', {
        method: 'POST',
        body: JSON.stringify({ blockIndex: targetIndex }),
      });
      setTamperDetails(res);

      // Verify immediately to highlight the break
      const verifyRes: VerificationStatus = await apiFetch('/api/audit/verify');
      setLocalVerification(verifyRes);
      await refreshAllState();

      if (auditBlocks[targetIndex]) {
        setSelectedBlock(auditBlocks[targetIndex]);
      }

      setNotification({
        message: `🚨 TAMPERING DETECTED on Block #${targetIndex}: SHA-256 invariant broken!`,
        type: 'warn',
      });
    } catch (err: any) {
      setNotification({ message: err.message || 'Tamper simulation failed', type: 'error' });
    } finally {
      setIsTampering(false);
    }
  };

  const handleRepairLedger = async () => {
    setIsRepairing(true);
    try {
      const res = await apiFetch('/api/audit/repair', {
        method: 'POST',
      });
      setTamperDetails(null);

      const verifyRes: VerificationStatus = await apiFetch('/api/audit/verify');
      setLocalVerification(verifyRes);
      await refreshAllState();

      setNotification({
        message: `Cryptographic integrity restored. SHA-256 chain re-sealed (${res.repairedCount} blocks).`,
        type: 'success',
      });
    } catch (err: any) {
      setNotification({ message: err.message || 'Repair failed', type: 'error' });
    } finally {
      setIsRepairing(false);
    }
  };

  const currentVerifyStatus = localVerification || verification;
  const isChainValid = currentVerifyStatus ? currentVerifyStatus.isValid : true;

  if (isLoading && auditBlocks.length === 0) {
    return (
      <div className="p-12 rounded-lg border border-slate-800 bg-slate-900/40 text-center space-y-3">
        <RefreshCw className="h-6 w-6 animate-spin text-cyan-400 mx-auto" />
        <div className="text-sm font-semibold text-slate-200">Loading Cryptographic Audit Ledger...</div>
        <p className="text-xs text-slate-500">Connecting to SHA-256 append-only event chain.</p>
      </div>
    );
  }

  if (error && auditBlocks.length === 0) {
    return (
      <div className="p-8 rounded-lg border border-rose-900/60 bg-rose-950/20 text-center space-y-3">
        <AlertTriangle className="h-6 w-6 text-rose-400 mx-auto" />
        <div className="text-sm font-semibold text-rose-300">Failed to Connect to Audit Ledger</div>
        <p className="text-xs text-slate-400">{error}</p>
        <button
          onClick={() => refreshAllState()}
          className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-medium transition-colors"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <span className="p-1 rounded bg-cyan-950/80 border border-cyan-800/40 text-cyan-400">
              <Database className="h-4 w-4" />
            </span>
            <span>Cryptographic Audit Ledger</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Immutable, SHA-256 hash-linked chain recording all cross-zone access evaluations, adversarial probes, and policy verdicts.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleSimulateTamper}
            disabled={isTampering}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-rose-900/60 bg-rose-950/40 hover:bg-rose-900/60 text-xs font-medium text-rose-300 transition-colors disabled:opacity-50"
          >
            <Flame className="h-3.5 w-3.5" />
            <span>{isTampering ? 'Simulating...' : 'Simulate Tampering'}</span>
          </button>

          {!isChainValid && (
            <button
              onClick={handleRepairLedger}
              disabled={isRepairing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-emerald-900/60 bg-emerald-950/60 hover:bg-emerald-900/80 text-xs font-semibold text-emerald-300 transition-colors disabled:opacity-50"
            >
              <Wrench className="h-3.5 w-3.5" />
              <span>{isRepairing ? 'Restoring...' : 'Restore Integrity'}</span>
            </button>
          )}

          <button
            onClick={handleVerify}
            disabled={isVerifying}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors disabled:opacity-50"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>{isVerifying ? 'Verifying...' : 'Verify Invariants'}</span>
          </button>
        </div>
      </div>

      {/* Verification Status Banner */}
      {currentVerifyStatus && (
        <div className={`p-4 rounded-lg border ${
          currentVerifyStatus.isValid
            ? 'border-emerald-900/60 bg-emerald-950/20 text-emerald-200'
            : 'border-rose-900/80 bg-rose-950/40 text-rose-200'
        }`}>
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              {currentVerifyStatus.isValid ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
              )}
              <div>
                <div className="font-bold text-xs uppercase tracking-wider">
                  {currentVerifyStatus.isValid ? 'SHA-256 CHAIN INTACT' : '🚨 TAMPERING DETECTED — CHAIN INTEGRITY VIOLATION DETECTED'}
                </div>
                <div className="text-xs text-slate-300 mt-1 leading-relaxed">
                  {currentVerifyStatus.message}
                </div>
                {!currentVerifyStatus.isValid && (
                  <div className="mt-2 text-[11px] font-mono text-rose-300 space-y-1">
                    <div>Affected Block: #{currentVerifyStatus.brokenBlockIndex}</div>
                    {currentVerifyStatus.expectedHash && (
                      <div className="truncate">Expected Hash: {currentVerifyStatus.expectedHash}</div>
                    )}
                    {currentVerifyStatus.actualHash && (
                      <div className="truncate">Detected Hash: {currentVerifyStatus.actualHash}</div>
                    )}
                  </div>
                )}
              </div>
            </div>

            <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-900/80 border border-slate-800 text-slate-300 shrink-0">
              Algorithm: SHA-256
            </span>
          </div>
        </div>
      )}

      {/* Visual Hash Chain: EVENT -> HASH -> EVENT -> HASH -> EVENT */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-5 space-y-3">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/60">
          <div>
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              SHA-256 Hash-Linked Event Chain
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Append-only ledger where each block currentHash cryptographically depends on previousHash.
            </div>
          </div>
          <span className="text-[11px] font-mono text-cyan-400 font-semibold">{auditBlocks.length} blocks in ledger</span>
        </div>

        <div className="overflow-x-auto py-3">
          <div className="flex items-center gap-3 min-w-max pb-2">
            {auditBlocks.map((block, idx) => {
              const isSelected = selectedBlock?.eventId === block.eventId || selectedBlock?.blockIndex === block.blockIndex;
              const isTampered = block.tampered;
              return (
                <React.Fragment key={block.eventId || idx}>
                  {/* Event Block */}
                  <div
                    onClick={() => setSelectedBlock(block)}
                    className={`cursor-pointer w-64 p-3.5 rounded-lg border transition-all ${
                      isSelected
                        ? 'border-cyan-500 bg-slate-850 ring-1 ring-cyan-500'
                        : isTampered
                        ? 'border-rose-600 bg-rose-950/40'
                        : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-mono text-slate-500">#{block.blockIndex}</span>
                      <span className={`px-1.5 py-0.2 rounded font-mono text-[10px] ${
                        block.verdict === 'BLOCK' ? 'bg-rose-950 text-rose-300' : 'bg-emerald-950 text-emerald-300'
                      }`}>
                        {block.verdict}
                      </span>
                    </div>

                    <div className="text-xs font-bold text-slate-200 mt-1 truncate">
                      {block.action}
                    </div>

                    <div className="text-[10px] text-slate-400 mt-1 flex items-center justify-between">
                      <span className="font-mono text-cyan-400">{block.sourceZone} → {block.destinationZone}</span>
                      <span>{new Date(block.timestamp).toLocaleTimeString()}</span>
                    </div>

                    <div className="mt-2 pt-2 border-t border-slate-800/60 text-[10px] font-mono text-slate-500 truncate">
                      Hash: {block.currentHash.substring(0, 16)}...
                    </div>
                  </div>

                  {/* Hash Link connector */}
                  {idx < auditBlocks.length - 1 && (
                    <div className="flex flex-col items-center justify-center px-1 text-slate-600">
                      <div className="text-[10px] font-mono text-cyan-400/80 mb-0.5">SHA-256</div>
                      <div className="flex items-center">
                        <div className="w-4 h-0.5 bg-slate-700" />
                        <LinkIcon className="h-3.5 w-3.5 text-cyan-500 mx-0.5 shrink-0" />
                        <div className="w-4 h-0.5 bg-slate-700" />
                      </div>
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>
      </div>

      {/* Block Inspector */}
      {selectedBlock && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div>
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Cryptographic Block Inspector
              </div>
              <div className="text-base font-bold text-white mt-0.5 flex items-center gap-2">
                <span>Block #{selectedBlock.blockIndex}: {selectedBlock.action}</span>
                {selectedBlock.tampered && (
                  <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-800 font-mono">
                    TAMPER DETECTED
                  </span>
                )}
              </div>
            </div>

            <div className="text-xs font-mono text-slate-400">
              Event ID: {selectedBlock.eventId}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-sans block">Previous Block Hash:</span>
              <span className="text-slate-300 break-all select-all">{selectedBlock.previousHash}</span>
            </div>

            <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-sans block">Current Block Hash (SHA-256):</span>
              <span className="text-cyan-300 break-all select-all">{selectedBlock.currentHash}</span>
            </div>
          </div>

          <div className="p-4 rounded bg-slate-950 border border-slate-800 text-xs space-y-2">
            <div className="text-slate-400 flex flex-wrap items-center gap-3">
              <div>
                <strong className="text-slate-300">Flow: </strong>
                <span className="font-mono text-cyan-400">{selectedBlock.sourceZone} → {selectedBlock.destinationZone}</span>
              </div>
              <span className="text-slate-700">·</span>
              <div>
                <strong className="text-slate-300">Timestamp: </strong>
                <span className="font-mono text-slate-300">{new Date(selectedBlock.timestamp).toISOString()}</span>
              </div>
              <span className="text-slate-700">·</span>
              <div>
                <strong className="text-slate-300">Verdict: </strong>
                <span className={`font-mono font-bold ${selectedBlock.verdict === 'BLOCK' ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {selectedBlock.verdict}
                </span>
              </div>
              <span className="text-slate-700">·</span>
              <div>
                <strong className="text-slate-300">Payload Hash: </strong>
                <span className="font-mono text-slate-400 truncate max-w-[120px] inline-block align-bottom">{selectedBlock.payloadHash.substring(0, 16)}...</span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 text-slate-300 font-sans leading-relaxed">
              <div className="text-[11px] font-semibold text-slate-400 mb-1">Stored Event Summary:</div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-slate-200">
                {selectedBlock.summary}
              </div>
            </div>

            {selectedBlock.details && (
              <div className="text-[11px] text-slate-400 font-mono pt-1">
                Details: {JSON.stringify(selectedBlock.details)}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
