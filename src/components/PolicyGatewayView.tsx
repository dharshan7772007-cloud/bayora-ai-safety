import React, { useState } from 'react';
import { useApp } from '../context/AppContext.tsx';
import { PolicyEvaluationResponse, PolicyRule, Role } from '../types.ts';
import { 
  ShieldCheck, 
  Plus, 
  Play, 
  CheckCircle2, 
  XCircle, 
  RefreshCw, 
  Terminal, 
  Hash, 
  Clock 
} from 'lucide-react';

export const PolicyGatewayView: React.FC = () => {
  const { policyRules, refreshAllState, apiFetch, setNotification, isLoading } = useApp();

  // Simulator states
  const [simSource, setSimSource] = useState<Role>('RED_TEAM');
  const [simDest, setSimDest] = useState<Role>('BLUE_TEAM');
  const [simAction, setSimAction] = useState('READ_DEFENSE_INTERNALS');
  const [simCapability, setSimCapability] = useState('STANDARD');
  const [simPayload, setSimPayload] = useState('Probe query targeting defensive neural weights');
  const [simResult, setSimResult] = useState<PolicyEvaluationResponse | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  // Quick preset selector for standard zero-trust tests
  const handleQuickPreset = (source: Role, dest: Role, action: string, payloadText: string) => {
    setSimSource(source);
    setSimDest(dest);
    setSimAction(action);
    setSimPayload(payloadText);
    setSimResult(null);
  };

  const handleToggleRule = async (id: string) => {
    try {
      const updated = await apiFetch(`/api/policy/rules/${id}/toggle`, {
        method: 'POST',
      });
      await refreshAllState();
      setNotification({
        message: `Policy rule ${updated.id} (${updated.name}) ${updated.enabled ? 'ENABLED' : 'DISABLED'}.`,
        type: 'info',
      });
    } catch (err: any) {
      setNotification({ message: err.message, type: 'error' });
    }
  };

  const handleSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSimulating(true);
    setSimResult(null);

    try {
      const res: PolicyEvaluationResponse = await apiFetch('/api/policy/simulate', {
        method: 'POST',
        body: JSON.stringify({
          sourceZone: simSource,
          destinationZone: simDest,
          actionType: simAction,
          capabilityRequested: simCapability !== 'STANDARD' ? simCapability : undefined,
          payloadContent: simPayload,
        }),
      });

      setSimResult(res);
      await refreshAllState();

      setNotification({
        message: `Policy evaluated: ${res.verdict} (${res.ruleId}). Event recorded to audit ledger.`,
        type: res.verdict === 'ALLOW' ? 'success' : 'warn',
      });
    } catch (err: any) {
      setNotification({ message: err.message, type: 'error' });
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <span className="p-1 rounded bg-cyan-950/80 border border-cyan-800/40 text-cyan-400">
              <ShieldCheck className="h-4 w-4" />
            </span>
            <span>Centralized Policy Gateway</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative server-side policy engine enforcing zero-trust access boundaries (P-001 through P-008).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-cyan-300">
            Registered Rules: {policyRules.length}
          </span>
        </div>
      </div>

      {/* Rules Table - Required Zero-Trust Rules (P-001 to P-008) */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/60">
          <div>
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Authoritative Zero-Trust Rules (P-001 to P-008)
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Evaluated server-side on every cross-enclave access attempt.
            </div>
          </div>
          <span className="text-[11px] font-mono text-cyan-400">{policyRules.filter(r => r.enabled).length}/8 Rules Active</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 font-semibold uppercase tracking-wider">
                <th className="py-2.5 px-3">Rule ID & Designation</th>
                <th className="py-2.5 px-3">Boundary Path</th>
                <th className="py-2.5 px-3">Action Type</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">Hits</th>
                <th className="py-2.5 px-3 text-right">Enforcement</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {policyRules.map((rule) => (
                <tr key={rule.id} className="hover:bg-slate-850/40 transition-colors">
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-400 font-bold">{rule.id}</span>
                      <span className="font-bold text-slate-200 font-sans">{rule.name}</span>
                    </div>
                    <div className="text-[10px] text-slate-500 font-sans mt-0.5">{rule.description}</div>
                  </td>
                  <td className="py-3 px-3 text-slate-300 whitespace-nowrap">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[11px]">
                      {rule.sourceZone} → {rule.destinationZone}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-400 text-[11px]">
                    {rule.actionType}
                  </td>
                  <td className="py-3 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      rule.decision === 'BLOCK' ? 'bg-rose-950 text-rose-300 border border-rose-900/40' :
                      rule.decision === 'ALLOW' ? 'bg-emerald-950 text-emerald-300 border border-emerald-900/40' :
                      'bg-amber-950 text-amber-300 border border-amber-900/40'
                    }`}>
                      {rule.decision}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-300 font-bold tabular-nums">
                    {rule.hits}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <button
                      onClick={() => handleToggleRule(rule.id)}
                      className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                        rule.enabled
                          ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 hover:bg-cyan-900'
                          : 'bg-slate-800 text-slate-500 border border-slate-700 hover:bg-slate-750'
                      }`}
                    >
                      {rule.enabled ? 'ACTIVE' : 'DISABLED'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Interactive Policy Simulator (Requirement 5) */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-5 space-y-4">
        <div className="pb-3 border-b border-slate-800/60">
          <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
            <Terminal className="h-3.5 w-3.5 text-cyan-400" />
            <span>Interactive Policy Gate Simulator</span>
          </div>
          <div className="text-xs text-slate-400 mt-0.5">
            Evaluate access requests against the server policy engine. Updates rule hit counts and records audit ledger events.
          </div>

          {/* Quick preset chips */}
          <div className="flex flex-wrap items-center gap-2 mt-3">
            <span className="text-[11px] text-slate-500">Quick Scenarios:</span>
            <button
              type="button"
              onClick={() => handleQuickPreset('RED_TEAM', 'BLUE_TEAM', 'READ_DEFENSE_INTERNALS', 'Adversarial probe requesting defensive neural weights')}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] font-mono text-rose-300 border border-slate-700"
            >
              RED → BLUE (P-001)
            </button>
            <button
              type="button"
              onClick={() => handleQuickPreset('BLUE_TEAM', 'RED_TEAM', 'READ_PAYLOAD_VAULT', 'Analyst attempting to read private unpublished zero-day vectors')}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] font-mono text-rose-300 border border-slate-700"
            >
              BLUE → RED (P-002)
            </button>
            <button
              type="button"
              onClick={() => handleQuickPreset('RED_TEAM', 'CLIENT_LLM', 'SANCTIONED_INFERENCE', 'Sanctioned evaluation prompt on token isolation boundaries')}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] font-mono text-emerald-300 border border-slate-700"
            >
              RED → CLIENT_LLM (P-003)
            </button>
            <button
              type="button"
              onClick={() => handleQuickPreset('BLUE_TEAM', 'CLIENT_LLM', 'DEFENSE_UPDATE', 'Synchronizing prompt guardrail filters')}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] font-mono text-emerald-300 border border-slate-700"
            >
              BLUE → CLIENT_LLM (P-004)
            </button>
          </div>
        </div>

        <form onSubmit={handleSimulate} className="grid grid-cols-1 lg:grid-cols-12 gap-4 text-xs">
          <div className="lg:col-span-3 space-y-3">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Source Zone</label>
              <select
                value={simSource}
                onChange={(e) => setSimSource(e.target.value as Role)}
                className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="RED_TEAM">RED_TEAM</option>
                <option value="BLUE_TEAM">BLUE_TEAM</option>
                <option value="CLIENT_LLM">CLIENT_LLM</option>
                <option value="SYSTEM_ADMIN">SYSTEM_ADMIN</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Destination Zone</label>
              <select
                value={simDest}
                onChange={(e) => setSimDest(e.target.value as Role)}
                className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="BLUE_TEAM">BLUE_TEAM</option>
                <option value="RED_TEAM">RED_TEAM</option>
                <option value="CLIENT_LLM">CLIENT_LLM</option>
                <option value="AUDIT_LEDGER">AUDIT_LEDGER</option>
              </select>
            </div>
          </div>

          <div className="lg:col-span-3 space-y-3">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Action Type</label>
              <select
                value={simAction}
                onChange={(e) => setSimAction(e.target.value)}
                className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="READ_DEFENSE_INTERNALS">READ_DEFENSE_INTERNALS</option>
                <option value="READ_PAYLOAD_VAULT">READ_PAYLOAD_VAULT</option>
                <option value="SANCTIONED_INFERENCE">SANCTIONED_INFERENCE</option>
                <option value="DEFENSE_UPDATE">DEFENSE_UPDATE</option>
                <option value="CONTEXT_ACCESS">CONTEXT_ACCESS</option>
                <option value="PAYLOAD_EXFILTRATION">PAYLOAD_EXFILTRATION</option>
                <option value="PAYLOAD_ACCESS">PAYLOAD_ACCESS</option>
                <option value="WRITE_SECURITY_EVENT">WRITE_SECURITY_EVENT</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Elevated Capability</label>
              <select
                value={simCapability}
                onChange={(e) => setSimCapability(e.target.value)}
                className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="STANDARD">STANDARD (No Escalation)</option>
                <option value="SHELL_EXEC">SHELL_EXEC (Host Command)</option>
                <option value="HOST_NETWORK">HOST_NETWORK (Raw Socket)</option>
                <option value="FS_ROOT">FS_ROOT (Filesystem Root)</option>
              </select>
            </div>
          </div>

          <div className="lg:col-span-6 space-y-3">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Payload Content / Arguments</label>
              <textarea
                rows={4}
                value={simPayload}
                onChange={(e) => setSimPayload(e.target.value)}
                placeholder="Simulate payload content..."
                className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center justify-end">
              <button
                type="submit"
                disabled={isSimulating}
                className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold transition-colors disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>{isSimulating ? 'Evaluating...' : 'Evaluate Through Gateway'}</span>
              </button>
            </div>
          </div>
        </form>

        {/* Simulation Output Card - Required exact fields */}
        {simResult && (
          <div className={`mt-4 p-4 rounded-lg border text-xs ${
            simResult.verdict === 'BLOCK' ? 'border-rose-900/60 bg-rose-950/20 text-rose-200' :
            'border-emerald-900/60 bg-emerald-950/20 text-emerald-200'
          }`}>
            <div className="flex items-center justify-between pb-2 border-b border-slate-800/60">
              <div className="flex items-center gap-2 font-bold uppercase tracking-wider">
                {simResult.verdict === 'BLOCK' ? <XCircle className="h-4 w-4 text-rose-400" /> : <CheckCircle2 className="h-4 w-4 text-emerald-400" />}
                <span className="text-sm">POLICY DECISION: {simResult.verdict}</span>
              </div>
              <span className="font-mono text-[11px] bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                Rule: {simResult.ruleId}
              </span>
            </div>

            <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-2 font-mono text-[11px] pb-2 border-b border-slate-800/60">
              <div>
                <span className="text-slate-400 block font-sans">Source Zone:</span>
                <span className="text-slate-200">{simResult.sourceZone}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-sans">Destination Zone:</span>
                <span className="text-slate-200">{simResult.destinationZone}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-sans">Action Evaluated:</span>
                <span className="text-slate-200">{simResult.action}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-sans">Event ID:</span>
                <span className="text-cyan-400">{simResult.eventId}</span>
              </div>
            </div>

            <div className="mt-2 space-y-1">
              <div>
                <strong className="text-slate-300 font-sans">Authoritative Reason: </strong>
                <span>{simResult.reason}</span>
              </div>
              <div className="text-[10px] text-slate-400 font-mono flex items-center gap-2 pt-1">
                <Clock className="h-3 w-3 text-slate-500" />
                <span>Evaluated at {new Date(simResult.timestamp).toLocaleString()}</span>
                <span>·</span>
                <span>Recorded to Cryptographic Audit Ledger</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
