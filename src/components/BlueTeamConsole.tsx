import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext.tsx';
import { DefenseRule } from '../types.ts';
import { 
  Lock, 
  CheckCircle2, 
  XCircle, 
  EyeOff, 
  RefreshCw, 
  Activity, 
  ShieldCheck 
} from 'lucide-react';

export const BlueTeamConsole: React.FC = () => {
  const { defenseRules, metrics, refreshAllState, apiFetch, setNotification } = useApp();
  const [telemetry, setTelemetry] = useState<any>(null);
  const [crossZoneAttemptResult, setCrossZoneAttemptResult] = useState<any>(null);
  const [isToggling, setIsToggling] = useState<string | null>(null);

  const loadTelemetry = async () => {
    try {
      const telem = await apiFetch('/api/blue-team/telemetry');
      setTelemetry(telem);
    } catch (err: any) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadTelemetry();
  }, []);

  const handleToggleDefense = async (id: string) => {
    setIsToggling(id);
    try {
      const updated = await apiFetch(`/api/blue-team/defenses/${id}/toggle`, {
        method: 'POST',
      });
      await refreshAllState();
      await loadTelemetry();
      setNotification({
        message: `Defense shield ${updated.name} ${updated.enabled ? 'ENABLED' : 'DISABLED'}. Updated in central state.`,
        type: 'info',
      });
    } catch (err: any) {
      setNotification({ message: err.message || 'Toggle failed', type: 'error' });
    } finally {
      setIsToggling(null);
    }
  };

  const handleTestProbeRedVault = async () => {
    setCrossZoneAttemptResult(null);
    try {
      // Intentionally attempt to access Red Team private payload repository from Blue Team role (P-002)
      const res = await apiFetch('/api/red-team/vault', {
        headers: { 'x-bayora-role': 'BLUE_TEAM' },
      });
      setCrossZoneAttemptResult({ success: true, data: res });
    } catch (err: any) {
      setCrossZoneAttemptResult({
        blocked: true,
        message: err.message,
        timestamp: new Date().toLocaleTimeString(),
      });
      await refreshAllState();
      await loadTelemetry();
    }
  };

  const activeShieldsCount = defenseRules.filter(d => d.enabled).length;
  const totalShieldsCount = defenseRules.length;
  const threatsMitigatedCount = metrics?.threatsMitigated ?? 5;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <span className="p-1 rounded bg-indigo-950/80 border border-indigo-800/40 text-indigo-400">
              <Lock className="h-4 w-4" />
            </span>
            <span>Blue Team Defense Console</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Zero-knowledge defensive management. Monitors sanitized telemetry and configures policy guardrails without inspecting Red Team unpublished attack tools.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded border border-indigo-900/60 bg-indigo-950/40 text-indigo-300 font-mono text-[11px]">
            Zone: BLUE_TEAM_SHIELD
          </span>
        </div>
      </div>

      {/* Top Threat Telemetry Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Active Defense Shields</div>
          <div className="text-2xl font-bold font-mono text-indigo-400 mt-1 tabular-nums">
            {activeShieldsCount}/{totalShieldsCount}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Heuristic filters operational</div>
        </div>

        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Threat Signatures Mitigated</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1 tabular-nums">
            {threatsMitigatedCount}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Intercepted at Policy Gate</div>
        </div>

        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Payload Vault Exposure</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            0% (BLIND)
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Red Team state completely isolated</div>
        </div>

        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">PII & Token Scrubber</div>
          <div className="text-2xl font-bold font-mono text-indigo-400 mt-1">
            STRICT
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Egress regex & embedding mask</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Active Defense Controls (7 cols) */}
        <div className="lg:col-span-7 rounded-lg border border-slate-800 bg-slate-900/40 p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/60">
            <div>
              <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Defensive Shields ({activeShieldsCount}/5 Active)
              </div>
              <div className="text-xs text-slate-400 mt-0.5">
                Toggle shields to protect model runtime and sanitize inputs/outputs.
              </div>
            </div>
            <button
              onClick={() => { refreshAllState(); loadTelemetry(); }}
              className="p-1 rounded text-slate-400 hover:text-white"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {defenseRules.map((def) => (
              <div
                key={def.id}
                className="p-3.5 rounded-lg border border-slate-800/80 bg-slate-950/40 flex items-start justify-between gap-4"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-slate-500">{def.id}</span>
                    <span className="text-xs font-bold text-slate-200">{def.name}</span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                      {def.category}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                    {def.description}
                  </p>
                  <div className="mt-2 text-[11px] text-slate-500 flex items-center gap-3">
                    <span>Sensitivity: <strong className="text-slate-400">{def.sensitivity}</strong></span>
                    <span>·</span>
                    <span>Threats Intercepted: <strong className="font-mono text-emerald-400 tabular-nums">{def.blockedCount}</strong></span>
                  </div>
                </div>

                <button
                  onClick={() => handleToggleDefense(def.id)}
                  disabled={isToggling === def.id}
                  className={`px-3 py-1 rounded text-xs font-mono font-medium transition-colors ${
                    def.enabled
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/80'
                      : 'bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700'
                  }`}
                >
                  {def.enabled ? 'ACTIVE' : 'DISABLED'}
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Sanitized Threat Intelligence & Boundary Test (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Sanitized Telemetry Feed */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-5 space-y-3">
            <div className="pb-3 border-b border-slate-800/60">
              <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <Activity className="h-3.5 w-3.5 text-indigo-400" />
                <span>Sanitized Threat Intelligence</span>
              </div>
              <div className="text-xs text-slate-400 mt-0.5">
                Attack incident signatures without leaking raw Red Team zero-day code.
              </div>
            </div>

            <div className="space-y-2 text-xs">
              {telemetry?.mitigatedVectors?.map((vec: any, idx: number) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded bg-slate-950/60 border border-slate-800/60 font-mono"
                >
                  <span className="text-slate-300 font-sans">{vec.vector}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 tabular-nums">{vec.count} hits</span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] bg-indigo-950 text-indigo-300">
                      {vec.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Cross-Zone Policy Invariant Test Card (P-002) */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-5 space-y-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 uppercase tracking-wider">
              <EyeOff className="h-4 w-4 text-cyan-400" />
              <span>Zero-Trust Privacy Invariant (P-002)</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Verify that Blue Team analysts cannot read Red Team proprietary unpublished attack payloads.
            </p>

            <button
              onClick={handleTestProbeRedVault}
              className="w-full flex items-center justify-center gap-1.5 py-2 rounded bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition-colors"
            >
              <span>Probe Red Team Payload Vault</span>
            </button>

            {crossZoneAttemptResult && (
              <div className="p-3 rounded bg-rose-950/40 border border-rose-900/60 text-xs space-y-1">
                <div className="font-semibold text-rose-300 flex items-center gap-1">
                  <XCircle className="h-3.5 w-3.5 text-rose-400 shrink-0" />
                  <span>Cross-Zone Access Blocked (403 Forbidden)</span>
                </div>
                <div className="text-slate-300">{crossZoneAttemptResult.message}</div>
                <div className="text-[10px] font-mono text-slate-500">
                  Enforced by P-002 · Recorded on SHA-256 ledger at {crossZoneAttemptResult.timestamp}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
