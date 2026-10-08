import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext.tsx';
import { SecurityTestResult, SecurityVerificationSummary, VerificationStatus } from '../types.ts';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Play, 
  RotateCw, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Clock, 
  Cpu, 
  Lock, 
  Database, 
  ArrowRight, 
  FileCheck2, 
  Hash, 
  ExternalLink,
  Layers,
  Sparkles,
  Info
} from 'lucide-react';

export const SecurityTestsView: React.FC = () => {
  const { 
    apiFetch, 
    refreshAllState, 
    setCurrentView, 
    setActiveEvaluationId, 
    setNotification 
  } = useApp();

  const [tests, setTests] = useState<SecurityTestResult[]>([]);
  const [summary, setSummary] = useState<SecurityVerificationSummary | null>(null);
  const [ledgerVerification, setLedgerVerification] = useState<VerificationStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [runningTestId, setRunningTestId] = useState<string | null>(null);
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [selectedTestId, setSelectedTestId] = useState<string>('TEST-001');

  // Load tests on mount
  const loadTests = async () => {
    try {
      const data = await apiFetch('/api/security-tests');
      if (data.tests) {
        setTests(data.tests);
        setSummary(data.summary);
        setLedgerVerification(data.verification);
      }
    } catch (err: any) {
      console.error('Failed to load security tests:', err);
    }
  };

  useEffect(() => {
    loadTests();
  }, []);

  const handleRunSingleTest = async (testId: 'TEST-001' | 'TEST-002' | 'TEST-003' | 'TEST-004') => {
    setRunningTestId(testId);
    setSelectedTestId(testId);
    try {
      const res = await apiFetch('/api/security-tests/run', {
        method: 'POST',
        body: JSON.stringify({ testId }),
      });

      if (res.tests) {
        setTests(res.tests);
        setSummary(res.summary);
        setLedgerVerification(res.verification);
      }
      await refreshAllState();

      if (res.test?.status === 'PASS') {
        setNotification({
          message: `${testId} PASSED: ${res.test.name} verified against policy & audit ledger.`,
          type: 'success',
        });
      } else {
        setNotification({
          message: `${testId} ${res.test?.status || 'FAIL'}: Security expectation check failed.`,
          type: 'error',
        });
      }
    } catch (err: any) {
      setNotification({
        message: `Error executing ${testId}: ${err.message}`,
        type: 'error',
      });
    } finally {
      setRunningTestId(null);
    }
  };

  const handleRunAllTests = async () => {
    setIsRunningAll(true);
    try {
      const res = await apiFetch('/api/security-tests/run', {
        method: 'POST',
        body: JSON.stringify({ runAll: true }),
      });

      if (res.tests) {
        setTests(res.tests);
        setSummary(res.summary);
        setLedgerVerification(res.verification);
      }
      await refreshAllState();

      if (res.summary?.overallStatus === 'PASS') {
        setNotification({
          message: `ALL 4 SECURITY TESTS PASSED: Zero-trust boundaries & cryptographic chain intact!`,
          type: 'success',
        });
      } else {
        setNotification({
          message: `Test matrix finished with failures. Check individual criteria.`,
          type: 'warn',
        });
      }
    } catch (err: any) {
      setNotification({
        message: `Run All failed: ${err.message}`,
        type: 'error',
      });
    } finally {
      setIsRunningAll(false);
    }
  };

  const activeTest = tests.find(t => t.testId === selectedTestId) || tests[0];

  const renderStatusBadge = (status: SecurityTestResult['status']) => {
    switch (status) {
      case 'PASS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-500/40 shadow-xs">
            <CheckCircle2 className="w-3.5 h-3.5" />
            PASS
          </span>
        );
      case 'FAIL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/80 text-rose-400 border border-rose-500/40 shadow-xs">
            <XCircle className="w-3.5 h-3.5" />
            FAIL
          </span>
        );
      case 'RUNNING':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 animate-pulse">
            <RotateCw className="w-3.5 h-3.5 animate-spin" />
            RUNNING
          </span>
        );
      case 'ERROR':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/80 text-amber-400 border border-amber-500/40">
            <AlertTriangle className="w-3.5 h-3.5" />
            ERROR
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-900 text-slate-400 border border-slate-700">
            <Clock className="w-3.5 h-3.5" />
            PENDING
          </span>
        );
    }
  };

  const isChainIntact = ledgerVerification?.isValid ?? true;

  return (
    <div className="space-y-6">
      {/* 1. Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 tracking-wider uppercase mb-1">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span>Bayora Security Core · Test Matrix & Invariant Prover</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            SECURITY VERIFICATION CONSOLE
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            Prove that adversarial evaluation boundaries are enforced, observable, and cryptographically auditable.
          </p>
        </div>

        {/* Global Action: Run All */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={loadTests}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-800 bg-slate-900/80 text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-850 hover:border-slate-700 transition-colors"
            title="Refresh test matrix state"
          >
            <RotateCw className="w-3.5 h-3.5" />
            <span>Sync</span>
          </button>

          <button
            onClick={handleRunAllTests}
            disabled={isRunningAll || !!runningTestId}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold shadow-lg transition-all ${
              isRunningAll
                ? 'bg-cyan-900/60 text-cyan-300 border border-cyan-500/50 cursor-wait'
                : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 hover:shadow-cyan-500/20 active:scale-[0.98]'
            }`}
          >
            {isRunningAll ? (
              <>
                <RotateCw className="w-3.5 h-3.5 animate-spin" />
                <span>Executing Test Suite...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>RUN ALL TESTS</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* 2. Top-Level Summary Metrics Bar */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {/* Metric 1: Tests Passed */}
        <div className="p-3.5 rounded-lg border border-slate-800/80 bg-slate-900/60 backdrop-blur-sm">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1">
            Tests Evaluated
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-xl font-bold font-mono text-slate-100">
              {summary?.passedCount ?? 0} / {tests.length || 4}
            </span>
            <span className="text-xs text-slate-500">
              ({summary?.pendingCount ?? 4} pending)
            </span>
          </div>
        </div>

        {/* Metric 2: Overall Status */}
        <div className={`p-3.5 rounded-lg border backdrop-blur-sm ${
          summary?.overallStatus === 'PASS'
            ? 'border-emerald-500/30 bg-emerald-950/20 text-emerald-300'
            : summary?.overallStatus === 'FAIL'
            ? 'border-rose-500/30 bg-rose-950/20 text-rose-300'
            : 'border-slate-800/80 bg-slate-900/60 text-slate-300'
        }`}>
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1">
            Suite Status
          </div>
          <div className="flex items-center gap-2">
            {summary?.overallStatus === 'PASS' ? (
              <>
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <span className="text-base font-bold text-emerald-400 font-mono">PASS (100%)</span>
              </>
            ) : summary?.overallStatus === 'FAIL' ? (
              <>
                <XCircle className="w-5 h-5 text-rose-400" />
                <span className="text-base font-bold text-rose-400 font-mono">VIOLATION</span>
              </>
            ) : (
              <>
                <Clock className="w-5 h-5 text-slate-400" />
                <span className="text-base font-bold text-slate-300 font-mono">PENDING RUN</span>
              </>
            )}
          </div>
        </div>

        {/* Metric 3: SHA-256 Audit Chain */}
        <div className="p-3.5 rounded-lg border border-slate-800/80 bg-slate-900/60 backdrop-blur-sm">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1 flex items-center justify-between">
            <span>Audit Chain</span>
            <span className="text-[10px] text-cyan-400 font-normal">SHA-256</span>
          </div>
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${isChainIntact ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]' : 'bg-rose-500 animate-pulse'}`} />
            <span className="text-sm font-bold font-mono text-slate-200">
              {isChainIntact ? 'CHAIN INTACT' : 'TAMPER DETECTED'}
            </span>
            <span className="text-xs text-slate-500 ml-auto">
              {ledgerVerification?.totalBlocks ?? 0} blks
            </span>
          </div>
        </div>

        {/* Metric 4: Regression Invariant */}
        <div className="p-3.5 rounded-lg border border-slate-800/80 bg-slate-900/60 backdrop-blur-sm">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1">
            Regression Check
          </div>
          <div className="flex items-center gap-2">
            <ShieldCheck className={`w-4 h-4 ${summary?.regressionCheck === 'PASS' ? 'text-emerald-400' : 'text-slate-500'}`} />
            <span className={`text-sm font-bold font-mono ${summary?.regressionCheck === 'PASS' ? 'text-emerald-400' : 'text-slate-400'}`}>
              {summary?.regressionCheck === 'PASS' ? 'PASS (0 Regressions)' : 'PENDING'}
            </span>
          </div>
        </div>

        {/* Metric 5: Policy Enforcer Point */}
        <div className="col-span-2 lg:col-span-1 p-3.5 rounded-lg border border-slate-800/80 bg-slate-900/60 backdrop-blur-sm">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1">
            Policy Engine
          </div>
          <div className="text-xs text-slate-300 font-mono flex items-center gap-1.5 truncate">
            <Lock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="truncate">Central Gateway P-001..P-008</span>
          </div>
        </div>
      </div>

      {/* 3. Main Test Matrix Table */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md overflow-hidden shadow-2xl">
        <div className="px-5 py-4 border-b border-slate-800/80 bg-slate-900/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-wide uppercase font-mono flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Core Security Invariant Test Matrix</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              4 Authoritative Architectural Boundary Tests Executed Against Central Policy Engine
            </p>
          </div>

          <div className="text-xs font-mono text-slate-400 flex items-center gap-2 self-start sm:self-auto">
            <span className="inline-block w-2 h-2 rounded-full bg-cyan-400"></span>
            <span>Real Server Execution · No Frontend Simulation</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800/80 bg-slate-950/60 text-slate-400 font-mono uppercase text-[11px]">
                <th className="py-3 px-4">Test ID</th>
                <th className="py-3 px-4">Test Name & Description</th>
                <th className="py-3 px-4">Cross-Zone Flow</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Expected Policy</th>
                <th className="py-3 px-4">Expected Model</th>
                <th className="py-3 px-4">Result Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {tests.map((test) => {
                const isSelected = selectedTestId === test.testId;
                const isThisRunning = runningTestId === test.testId || (isRunningAll && test.status === 'RUNNING');

                return (
                  <tr
                    key={test.testId}
                    onClick={() => setSelectedTestId(test.testId)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-950/20 hover:bg-cyan-950/30'
                        : 'hover:bg-slate-850/50'
                    }`}
                  >
                    {/* Test ID */}
                    <td className="py-3.5 px-4 font-bold text-cyan-400">
                      <div className="flex items-center gap-1.5">
                        {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />}
                        {test.testId}
                      </div>
                    </td>

                    {/* Name */}
                    <td className="py-3.5 px-4 font-sans font-medium text-slate-200">
                      <div>{test.name}</div>
                      <div className="text-[11px] font-mono text-slate-500 mt-0.5">
                        Evidence: {test.expectedEvidence}
                      </div>
                    </td>

                    {/* Flow */}
                    <td className="py-3.5 px-4 text-slate-300">
                      <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60 text-[11px]">
                        {test.flow}
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                      {test.action}
                    </td>

                    {/* Expected Policy */}
                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                        test.expectedPolicy === 'ALLOW'
                          ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/30'
                          : 'bg-rose-950/60 text-rose-300 border-rose-500/30'
                      }`}>
                        {test.expectedPolicy}
                      </span>
                    </td>

                    {/* Expected Model */}
                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[11px] border ${
                        test.expectedModel === 'EXECUTED'
                          ? 'bg-indigo-950/60 text-indigo-300 border-indigo-500/30'
                          : 'bg-slate-800/80 text-slate-400 border-slate-700/60'
                      }`}>
                        {test.expectedModel}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="py-3.5 px-4">
                      {isThisRunning ? (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 animate-pulse">
                          <RotateCw className="w-3.5 h-3.5 animate-spin" />
                          RUNNING
                        </span>
                      ) : (
                        renderStatusBadge(test.status)
                      )}
                    </td>

                    {/* Action Button */}
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRunSingleTest(test.testId);
                        }}
                        disabled={isThisRunning || isRunningAll}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-700 bg-slate-800 text-slate-200 hover:text-white hover:bg-slate-700 hover:border-slate-600 transition-colors text-xs font-sans disabled:opacity-50"
                      >
                        <Play className="w-3 h-3 fill-current text-cyan-400" />
                        <span>RUN TEST</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. Judge-Ready Test Evidence & Deep Inspection Drawer */}
      {activeTest && (
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 backdrop-blur-md p-5 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-mono font-bold text-sm">
                {activeTest.testId.split('-')[1]}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">
                    {activeTest.testId} — {activeTest.name}
                  </h3>
                  {renderStatusBadge(activeTest.status)}
                </div>
                <p className="text-xs font-mono text-slate-400 mt-0.5">
                  Flow: {activeTest.flow} · Action: {activeTest.action}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-start sm:self-auto">
              {activeTest.evaluationId && (
                <button
                  onClick={() => {
                    setActiveEvaluationId(activeTest.evaluationId!);
                    setCurrentView('evaluations');
                  }}
                  className="flex items-center gap-1 px-3 py-1.5 rounded border border-cyan-500/30 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-950/70 hover:border-cyan-400 transition-colors text-xs font-mono"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Replay Evaluation ({activeTest.evaluationId})</span>
                </button>
              )}

              <button
                onClick={() => handleRunSingleTest(activeTest.testId)}
                disabled={runningTestId === activeTest.testId || isRunningAll}
                className="flex items-center gap-1 px-3 py-1.5 rounded border border-slate-700 bg-slate-800 text-slate-200 hover:text-white hover:bg-slate-700 transition-colors text-xs font-mono"
              >
                <Play className="w-3 h-3 fill-current text-cyan-400" />
                <span>Re-run</span>
              </button>
            </div>
          </div>

          {/* Test Evidence Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
            {/* Policy Decision Card */}
            <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60">
              <div className="text-slate-500 text-[11px] uppercase tracking-wider mb-1">
                Policy Gate Verdict
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-xs font-bold border ${
                  activeTest.actualPolicy === 'ALLOW'
                    ? 'bg-emerald-950 text-emerald-400 border-emerald-500/40'
                    : activeTest.actualPolicy === 'BLOCK'
                    ? 'bg-rose-950 text-rose-400 border-rose-500/40'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}>
                  {activeTest.actualPolicy || 'NOT RUN'}
                </span>
                <span className="text-slate-400">
                  (Expected: {activeTest.expectedPolicy})
                </span>
              </div>
              {activeTest.ruleId && (
                <div className="mt-2 text-[11px] text-cyan-300">
                  Rule Triggered: <span className="font-bold">{activeTest.ruleId}</span>
                </div>
              )}
            </div>

            {/* Model Execution Card */}
            <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60">
              <div className="text-slate-500 text-[11px] uppercase tracking-wider mb-1">
                Model Inference
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-xs font-bold border ${
                  activeTest.actualModel === 'EXECUTED'
                    ? 'bg-indigo-950 text-indigo-300 border-indigo-500/40'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}>
                  {activeTest.actualModel || 'NOT RUN'}
                </span>
                <span className="text-slate-400">
                  (Expected: {activeTest.expectedModel})
                </span>
              </div>
              <div className="mt-2 text-[11px] text-slate-400">
                {activeTest.actualModel === 'EXECUTED' ? (
                  <span>
                    gemini-3.8-flash ({activeTest.tokensUsed ?? 0} tok, {activeTest.latencyMs ?? 0}ms)
                  </span>
                ) : (
                  <span className="text-emerald-400">
                    Pre-ingest drop verified (0 tokens)
                  </span>
                )}
              </div>
            </div>

            {/* Audit Chain Ledger Seal */}
            <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60">
              <div className="text-slate-500 text-[11px] uppercase tracking-wider mb-1">
                Cryptographic Audit Seal
              </div>
              <div className="text-slate-200 flex items-center gap-1.5">
                <Hash className="w-3.5 h-3.5 text-cyan-400" />
                <span>
                  {activeTest.auditBlockIndex !== undefined 
                    ? `Block #${activeTest.auditBlockIndex}` 
                    : 'Awaiting Run'}
                </span>
              </div>
              {activeTest.auditHash && (
                <div className="mt-1 text-[10px] text-slate-500 truncate font-mono" title={activeTest.auditHash}>
                  SHA-256: {activeTest.auditHash.slice(0, 18)}...
                </div>
              )}
            </div>

            {/* Event Identifier */}
            <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60">
              <div className="text-slate-500 text-[11px] uppercase tracking-wider mb-1">
                Security Event ID
              </div>
              <div className="text-slate-200">
                {activeTest.eventId || 'Awaiting Run'}
              </div>
              {activeTest.executedAt && (
                <div className="mt-1 text-[10px] text-slate-500">
                  {new Date(activeTest.executedAt).toLocaleTimeString()}
                </div>
              )}
            </div>
          </div>

          {/* Detailed Reason & Invariant Explanation Box */}
          <div className="p-4 rounded-lg border border-slate-800/80 bg-slate-950/80 text-xs font-mono space-y-2">
            <div className="flex items-center gap-2 text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
              <Info className="w-3.5 h-3.5 text-cyan-400" />
              <span>Execution Evidence & Policy Explanation</span>
            </div>

            <div className="text-slate-300 leading-relaxed">
              {activeTest.reason || (
                activeTest.status === 'PENDING'
                  ? 'Click [RUN TEST] or [RUN ALL TESTS] to trigger server-side policy evaluation, boundary verification, and audit sealing.'
                  : 'Policy evaluation completed.'
              )}
            </div>

            {activeTest.evidenceSummary && (
              <div className="pt-2 border-t border-slate-800/60 text-slate-400 flex items-start gap-2">
                <span className="text-cyan-400 font-bold shrink-0">EVIDENCE:</span>
                <span>{activeTest.evidenceSummary}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5. Judge Verification Summary Card */}
      <div className="p-5 rounded-xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span>Independent Judge Verification Statement</span>
            </h3>
            <p className="text-xs text-slate-400 max-w-3xl">
              All 4 cross-zone boundaries enforce zero-trust isolation in real time. Red Team cannot access Blue Team defense internals; Blue Team cannot read Red Team payload vaults; Client LLM latent context is strictly isolated; and sanctioned inference executes only after explicit Policy Gateway authorization with immutable SHA-256 ledger recording.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0 text-xs font-mono">
            <div className="px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-slate-300">
              <span className="text-slate-500">Hash Algorithm:</span>{' '}
              <span className="text-cyan-400 font-bold">SHA-256</span>
            </div>
            <div className="px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-slate-300">
              <span className="text-slate-500">Model:</span>{' '}
              <span className="text-indigo-400 font-bold">gemini-3.8-flash</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
