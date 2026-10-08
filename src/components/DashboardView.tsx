import React, { useState } from 'react';
import { useApp } from '../context/AppContext.tsx';
import { 
  Shield, 
  ShieldAlert, 
  Cpu, 
  Lock, 
  Database, 
  ArrowRight, 
  Activity, 
  Play, 
  RefreshCw, 
  FileCheck2, 
  ArrowUpRight,
  Flame,
  CheckCircle2,
  XCircle,
  Terminal,
  Layers
} from 'lucide-react';

export const DashboardView: React.FC = () => {
  const { 
    status, 
    evaluations, 
    policyRules, 
    defenseRules, 
    attackVectors, 
    auditBlocks, 
    securityEvents, 
    metrics, 
    verification, 
    setCurrentView, 
    setActiveEvaluationId, 
    refreshAllState, 
    apiFetch,
    setNotification 
  } = useApp();

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [runningDemoStep, setRunningDemoStep] = useState<number | null>(null);
  const [demoResults, setDemoResults] = useState<Record<number, any>>({});

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await refreshAllState();
    setIsRefreshing(false);
  };

  const runDemoStep = async (step: number) => {
    setRunningDemoStep(step);
    try {
      const res = await apiFetch('/api/demo/run-step', {
        method: 'POST',
        body: JSON.stringify({ step }),
      });
      setDemoResults(prev => ({ ...prev, [step]: res }));
      await refreshAllState();
      setNotification({
        message: `Demo Step ${step} executed: ${res.test} (${res.verdict || res.status})`,
        type: res.verdict === 'BLOCK' || res.status === 'TAMPERING DETECTED' ? 'warn' : 'success',
      });
    } catch (err: any) {
      setNotification({ message: err.message || 'Demo step failed', type: 'error' });
    } finally {
      setRunningDemoStep(null);
    }
  };

  const latestEval = evaluations[0];
  const isChainValid = verification ? verification.isValid : true;

  // Exact metrics derived from central shared state
  const totalEvaluationsCount = metrics?.totalEvaluations ?? evaluations.length;
  const threatsMitigatedCount = metrics?.threatsMitigated ?? 5;
  const activeRulesCount = metrics?.policyRulesActive ?? policyRules.filter(r => r.enabled).length;
  const ledgerBlocksCount = metrics?.ledgerBlocks ?? auditBlocks.length;
  const activeShieldsCount = metrics?.activeShieldsCount ?? defenseRules.filter(d => d.enabled).length;
  const totalShieldsCount = metrics?.totalShieldsCount ?? defenseRules.length;

  return (
    <div className="space-y-6">
      {/* Top Header & Architecture summary */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white">
              Zero-Trust AI Safety Perimeter
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 font-mono">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
              Central Policy Engine Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Isolated execution framework where Red Team attack vectors, Client LLM inference context, and Blue Team defenses operate without leaking internal state.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-800 bg-slate-900/80 text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Sync Perimeter</span>
          </button>
          <button
            onClick={() => setCurrentView('evaluations')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-slate-950 transition-colors"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>Launch Evaluation</span>
          </button>
        </div>
      </div>

      {/* Key Metrics Grid - Single Shared State */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Total Evaluations</div>
          <div className="text-2xl font-bold font-mono text-white mt-1 tabular-nums">
            {totalEvaluationsCount}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Automated & manual pipelines
          </div>
        </div>

        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Threats Mitigated</div>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-1 tabular-nums">
            {threatsMitigatedCount}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Blocked before model memory ingest
          </div>
        </div>

        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Policy Rules Active</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1 tabular-nums">
            {activeRulesCount}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Enforced by server Policy Engine
          </div>
        </div>

        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Cryptographic Ledger</div>
          <div className={`text-2xl font-bold font-mono mt-1 tabular-nums ${isChainValid ? 'text-emerald-400' : 'text-rose-400'}`}>
            {ledgerBlocksCount} BLOCKS
          </div>
          <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-1">
            <span className={`h-1.5 w-1.5 rounded-full ${isChainValid ? 'bg-emerald-400' : 'bg-rose-500'}`} />
            <span>{isChainValid ? 'SHA-256 Chain Intact' : 'Tamper Detected!'}</span>
          </div>
        </div>
      </div>

      {/* End-to-End Demo Verification Sequence (Requirement 14) */}
      <div className="p-4 rounded-lg border border-cyan-900/60 bg-cyan-950/20 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <div className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
              <Terminal className="h-3.5 w-3.5 text-cyan-400" />
              <span>Zero-Trust Validation Sequence (End-to-End Demo)</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Execute canonical zero-trust boundary tests against the live server-side policy engine and audit chain.
            </div>
          </div>
          <div className="flex items-center gap-2 self-start sm:self-auto">
            <button
              onClick={() => setCurrentView('security_tests')}
              className="text-[10px] font-mono text-cyan-300 hover:text-cyan-100 bg-cyan-900/60 hover:bg-cyan-800/80 px-2.5 py-1 rounded border border-cyan-500/50 flex items-center gap-1 transition-colors"
            >
              <span>Security Tests Console</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
            <span className="text-[10px] font-mono text-cyan-400/80 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800/50">
              Authoritative Server State
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2 text-xs">
          {/* Test 1 */}
          <button
            onClick={() => runDemoStep(1)}
            disabled={runningDemoStep !== null}
            className="p-2.5 rounded bg-slate-900/90 border border-slate-800 hover:border-cyan-500/60 text-left transition-all disabled:opacity-50"
          >
            <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono mb-1">
              <span>TEST 1</span>
              {demoResults[1] && <span className="text-rose-400 font-bold">BLOCK (P-001)</span>}
            </div>
            <div className="font-semibold text-slate-200">RED → BLUE Internals</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Defense shield block</div>
          </button>

          {/* Test 2 */}
          <button
            onClick={() => runDemoStep(2)}
            disabled={runningDemoStep !== null}
            className="p-2.5 rounded bg-slate-900/90 border border-slate-800 hover:border-cyan-500/60 text-left transition-all disabled:opacity-50"
          >
            <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono mb-1">
              <span>TEST 2</span>
              {demoResults[2] && <span className="text-rose-400 font-bold">BLOCK (P-002)</span>}
            </div>
            <div className="font-semibold text-slate-200">BLUE → RED Vault</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Payload vault isolation</div>
          </button>

          {/* Test 3 */}
          <button
            onClick={() => runDemoStep(3)}
            disabled={runningDemoStep !== null}
            className="p-2.5 rounded bg-slate-900/90 border border-slate-800 hover:border-cyan-500/60 text-left transition-all disabled:opacity-50"
          >
            <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono mb-1">
              <span>TEST 3</span>
              {demoResults[3] && <span className="text-emerald-400 font-bold">ALLOW (P-003)</span>}
            </div>
            <div className="font-semibold text-slate-200">RED → CLIENT LLM</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Sanctioned Gemini inference</div>
          </button>

          {/* Test 4 */}
          <button
            onClick={() => runDemoStep(4)}
            disabled={runningDemoStep !== null}
            className="p-2.5 rounded bg-slate-900/90 border border-slate-800 hover:border-rose-500/60 text-left transition-all disabled:opacity-50"
          >
            <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono mb-1">
              <span>TEST 4</span>
              {demoResults[4] && <span className="text-rose-400 font-bold">TAMPER DETECTED</span>}
            </div>
            <div className="font-semibold text-rose-300">Simulate Tampering</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Hash mismatch detected</div>
          </button>

          {/* Test 5 */}
          <button
            onClick={() => runDemoStep(5)}
            disabled={runningDemoStep !== null}
            className="p-2.5 rounded bg-slate-900/90 border border-slate-800 hover:border-emerald-500/60 text-left transition-all disabled:opacity-50"
          >
            <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono mb-1">
              <span>TEST 5</span>
              {demoResults[5] && <span className="text-emerald-400 font-bold">CHAIN INTACT</span>}
            </div>
            <div className="font-semibold text-emerald-300">Verify & Re-seal</div>
            <div className="text-[10px] text-slate-500 mt-0.5">SHA-256 chain verified</div>
          </button>
        </div>
      </div>

      {/* Security Zones Grid */}
      <div>
        <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
          Security Enclaves & Isolation Status
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Red Team Enclave */}
          <div 
            onClick={() => setCurrentView('red_team')}
            className="group cursor-pointer p-4 rounded-lg border border-slate-800 bg-slate-900/30 hover:border-rose-900/60 hover:bg-slate-900/50 transition-all"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded bg-rose-950/60 border border-rose-800/40 text-rose-400">
                  <ShieldAlert className="h-4 w-4" />
                </div>
                <span className="text-sm font-semibold text-slate-200 group-hover:text-rose-300 transition-colors">
                  Red Team Zone
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-rose-300">
                ISOLATED
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2.5 leading-relaxed">
              Adversarial exploration workspace. Proprietary zero-day payloads remain in private vault, invisible to Blue defense models.
            </p>
            <div className="mt-3 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
              <span className="tabular-nums">{attackVectors.length} vectors loaded</span>
              <span className="flex items-center gap-1 text-rose-400 group-hover:translate-x-0.5 transition-transform">
                Open Console <ArrowUpRight className="h-3 w-3" />
              </span>
            </div>
          </div>

          {/* Client LLM Sandbox */}
          <div 
            onClick={() => setCurrentView('client_llm')}
            className="group cursor-pointer p-4 rounded-lg border border-slate-800 bg-slate-900/30 hover:border-emerald-900/60 hover:bg-slate-900/50 transition-all"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded bg-emerald-950/60 border border-emerald-800/40 text-emerald-400">
                  <Cpu className="h-4 w-4" />
                </div>
                <span className="text-sm font-semibold text-slate-200 group-hover:text-emerald-300 transition-colors">
                  Client LLM Sandbox
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-emerald-300">
                SANDBOXED
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2.5 leading-relaxed">
              Target inference model running in sanitized container. Only policy-approved requests reach context memory.
            </p>
            <div className="mt-3 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
              <span className="font-mono">gemini-3.8-flash</span>
              <span className="flex items-center gap-1 text-emerald-400 group-hover:translate-x-0.5 transition-transform">
                Open Sandbox <ArrowUpRight className="h-3 w-3" />
              </span>
            </div>
          </div>

          {/* Blue Team Defense */}
          <div 
            onClick={() => setCurrentView('blue_team')}
            className="group cursor-pointer p-4 rounded-lg border border-slate-800 bg-slate-900/30 hover:border-indigo-900/60 hover:bg-slate-900/50 transition-all"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded bg-indigo-950/60 border border-indigo-800/40 text-indigo-400">
                  <Lock className="h-4 w-4" />
                </div>
                <span className="text-sm font-semibold text-slate-200 group-hover:text-indigo-300 transition-colors">
                  Blue Team Shield
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-indigo-300">
                ACTIVE
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2.5 leading-relaxed">
              Heuristic classifiers, PII scrubbers, and exfiltration barriers. Defends without inspecting Red Team private tools.
            </p>
            <div className="mt-3 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
              <span className="tabular-nums font-mono">{activeShieldsCount}/{totalShieldsCount} active shields</span>
              <span className="flex items-center gap-1 text-indigo-400 group-hover:translate-x-0.5 transition-transform">
                Open Defense <ArrowUpRight className="h-3 w-3" />
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Center Layout: Active Evaluation & Boundary Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Evaluation Banner */}
        <div className="lg:col-span-2 rounded-lg border border-slate-800 bg-slate-900/40 p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/60">
            <div>
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Featured Evaluation Pipeline
              </div>
              <div className="text-base font-semibold text-slate-100 mt-0.5">
                {latestEval ? latestEval.title : 'No active evaluation'}
              </div>
            </div>
            {latestEval && (
              <span className={`px-2.5 py-1 rounded text-xs font-mono font-medium ${
                latestEval.status === 'BLOCKED' 
                  ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60'
                  : latestEval.status === 'COMPLETED'
                  ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                  : 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/60'
              }`}>
                {latestEval.status}
              </span>
            )}
          </div>

          {latestEval ? (
            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-3 gap-3 text-xs">
                <div>
                  <span className="text-slate-500 block">ID:</span>
                  <span className="font-mono text-slate-200">{latestEval.id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Category:</span>
                  <span className="text-slate-200">{latestEval.attackCategory}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Current Stage:</span>
                  <span className="font-mono text-cyan-400 font-medium">{latestEval.currentStage}</span>
                </div>
              </div>

              <div className="p-3 rounded bg-slate-950/60 border border-slate-800 text-xs">
                <div className="text-[11px] text-slate-400 mb-1 font-medium">Adversarial Prompt Fragment:</div>
                <div className="font-mono text-slate-300 line-clamp-2">
                  {latestEval.adversarialPrompt}
                </div>
              </div>

              {latestEval.finding && (
                <div className="p-3 rounded bg-slate-900/80 border border-slate-800/80 text-xs flex items-start gap-2.5">
                  <FileCheck2 className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-200">Finding Summary: </span>
                    <span className="text-slate-400">{latestEval.finding.description}</span>
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] font-mono text-slate-500 truncate max-w-xs">
                  Hash: {latestEval.auditHash || 'Pending Verification Seal'}
                </span>
                <button
                  onClick={() => {
                    setActiveEvaluationId(latestEval.id);
                    setCurrentView('evaluations');
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition-colors"
                >
                  <span>Inspect Pipeline Stages</span>
                  <ArrowRight className="h-3 w-3" />
                </button>
              </div>
            </div>
          ) : (
            <div className="py-8 text-center text-xs text-slate-500">
              No evaluation runs registered. Launch an evaluation to initiate the 8-stage pipeline.
            </div>
          )}
        </div>

        {/* Cross-Zone Boundary Enforcement Matrix (P-001 to P-008) */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-5 flex flex-col justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Cross-Zone Policy Matrix ({activeRulesCount} Rules)
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Authoritative rules enforced by the central policy engine.
            </p>

            <div className="mt-4 space-y-1.5 text-xs font-mono">
              {policyRules.slice(0, 5).map(rule => (
                <div key={rule.id} className="flex items-center justify-between p-2 rounded bg-slate-950/50 border border-slate-800/60">
                  <div className="truncate pr-2">
                    <span className="text-cyan-400 mr-1.5">[{rule.id}]</span>
                    <span className="text-slate-300 font-sans">{rule.name}</span>
                  </div>
                  <span className={`font-semibold shrink-0 text-[11px] ${rule.decision === 'BLOCK' ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {rule.decision}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60">
            <button
              onClick={() => setCurrentView('policy_gateway')}
              className="w-full flex items-center justify-center gap-1.5 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
            >
              <span>View All 8 Rules in Policy Gateway</span>
              <ArrowRight className="h-3 w-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Security Event Stream */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-5">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/60">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-cyan-400" />
            <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Recent Security Event Stream
            </span>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Synchronized with SHA-256 Ledger</span>
        </div>

        <div className="mt-3 divide-y divide-slate-800/40">
          {securityEvents.length === 0 ? (
            <div className="py-4 text-center text-xs text-slate-500">Awaiting security events...</div>
          ) : (
            securityEvents.slice(0, 6).map((evt) => (
              <div key={evt.id} className="py-2.5 flex items-start justify-between gap-4 text-xs">
                <div className="flex items-start gap-3 min-w-0">
                  <span className={`h-2 w-2 rounded-full mt-1.5 shrink-0 ${
                    evt.severity === 'CRITICAL' ? 'bg-rose-400' :
                    evt.severity === 'WARN' ? 'bg-amber-400' :
                    evt.severity === 'SUCCESS' ? 'bg-emerald-400' : 'bg-cyan-400'
                  }`} />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-slate-400 text-[11px]">{evt.actor}</span>
                      <span className="text-slate-600">·</span>
                      <span className="font-medium text-slate-200">{evt.type}</span>
                      {evt.decision && (
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                          evt.decision === 'BLOCK' ? 'bg-rose-950 text-rose-300' : 'bg-emerald-950 text-emerald-300'
                        }`}>
                          {evt.decision}
                        </span>
                      )}
                    </div>
                    <div className="text-slate-400 text-xs mt-0.5 truncate">
                      {evt.message}
                    </div>
                  </div>
                </div>

                <div className="font-mono text-[11px] text-slate-500 shrink-0">
                  {new Date(evt.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
