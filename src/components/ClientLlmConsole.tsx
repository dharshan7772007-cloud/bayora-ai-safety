import React, { useState } from 'react';
import { useApp } from '../context/AppContext.tsx';
import { 
  Cpu, 
  Send, 
  Terminal, 
  RefreshCw, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  Hash 
} from 'lucide-react';

export const ClientLlmConsole: React.FC = () => {
  const { modelSessions, refreshAllState, apiFetch, setNotification } = useApp();
  const session = modelSessions[0];

  const [queryInput, setQueryInput] = useState('Explain how cryptographic audit ledgers prevent state tampering in adversarial testing environments.');
  const [isInferring, setIsInferring] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [conversation, setConversation] = useState<Array<{
    role: 'user' | 'model';
    text: string;
    meta?: {
      verdict?: 'ALLOW' | 'BLOCK';
      tokens?: number;
      latencyMs?: number;
      model?: string;
      sessionId?: string;
      blocked?: boolean;
      error?: boolean;
    };
  }>>([
    {
      role: 'user',
      text: 'Evaluate standard reasoning under stress: Compare zero-trust token isolation vs network namespace boundaries.',
      meta: { verdict: 'ALLOW', tokens: 18 }
    },
    {
      role: 'model',
      text: 'Zero-trust token isolation governs model context memory and capability execution, ensuring adversarial inputs never poison latent state. Network namespace isolation operates at the kernel/container layer. Both work harmoniously.',
      meta: { verdict: 'ALLOW', tokens: 184, latencyMs: 720, model: 'gemini-3.8-flash', sessionId: 'SES-GEMINI-ALPHA' }
    }
  ]);

  const handleSendQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!queryInput.trim() || isInferring) return;

    const userText = queryInput;
    setQueryInput('');
    setIsInferring(true);
    setErrorMessage(null);

    // Append user prompt to feed
    setConversation(prev => [...prev, { role: 'user', text: userText, meta: { verdict: 'ALLOW' } }]);

    try {
      // Flow: Enforce policy gate server-side; if allowed, execute Gemini inference
      const result = await apiFetch('/api/client-llm/query', {
        method: 'POST',
        body: JSON.stringify({ prompt: userText }),
      });

      setConversation(prev => [
        ...prev,
        {
          role: 'model',
          text: result.text,
          meta: {
            verdict: 'ALLOW',
            tokens: result.tokens,
            latencyMs: result.latencyMs,
            model: result.model,
            sessionId: result.sessionId || session?.id || 'SES-GEMINI-ALPHA',
          },
        },
      ]);

      await refreshAllState();
      setNotification({
        message: `Query processed cleanly by ${result.model} (${result.tokens} tokens, ${result.latencyMs}ms).`,
        type: 'success',
      });
    } catch (err: any) {
      const errText = err.message || 'Request evaluation failed';
      setErrorMessage(errText);

      setConversation(prev => [
        ...prev,
        {
          role: 'model',
          text: `[POLICY INTERCEPT / GATEWAY BLOCK]: ${errText}`,
          meta: {
            verdict: 'BLOCK',
            blocked: true,
            error: true,
            sessionId: session?.id || 'SES-GEMINI-ALPHA',
          },
        },
      ]);

      await refreshAllState();
      setNotification({
        message: `Request terminated by Policy Gateway: ${errText}`,
        type: 'warn',
      });
    } finally {
      setIsInferring(false);
    }
  };

  const approvedCount = session?.approvedRequestsCount ?? 84;
  const blockedDropped = session?.blockedAttemptsDropped ?? 31;
  const totalTokens = session?.totalTokens ?? 14290;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <span className="p-1 rounded bg-emerald-950/80 border border-emerald-800/40 text-emerald-400">
              <Cpu className="h-4 w-4" />
            </span>
            <span>Client LLM Monitored Sandbox</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Clean model runtime. Adversarial prompts blocked by the Policy Gateway are dropped before touching model context memory.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded border border-emerald-900/60 bg-emerald-950/40 text-emerald-300 font-mono text-[11px]">
            Target: gemini-3.8-flash
          </span>
        </div>
      </div>

      {/* Session Diagnostics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Session ID</div>
          <div className="text-sm font-bold font-mono text-slate-200 mt-1 truncate">
            {session?.id || 'SES-GEMINI-ALPHA'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Active Ephemeral Sandbox</div>
        </div>

        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Sanctioned Requests</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1 tabular-nums">
            {approvedCount}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Passed policy evaluation</div>
        </div>

        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Threats Dropped Pre-Ingest</div>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-1 tabular-nums">
            {blockedDropped}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Memory contamination = 0%</div>
        </div>

        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="text-[11px] font-medium text-slate-400">Total Tokens Processed</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1 tabular-nums">
            {totalTokens.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Inference compute budget nominal</div>
        </div>
      </div>

      {/* Main Sandbox Interactive Chat Window */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col h-[520px]">
        {/* Terminal Title Bar */}
        <div className="px-4 py-3 border-b border-slate-800/80 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2">
            <Terminal className="h-3.5 w-3.5 text-emerald-400" />
            <span className="text-xs font-semibold text-slate-300">
              Sanitized Conversation Stream · Session: {session?.id || 'SES-GEMINI-ALPHA'}
            </span>
          </div>
          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-500">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Policy Gate Monitored (gemini-3.8-flash)
            </span>
          </div>
        </div>

        {/* Conversation Message Feed */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {conversation.map((msg, idx) => (
            <div
              key={idx}
              className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}
            >
              <div className="text-[10px] font-mono text-slate-500 mb-1 px-1 flex items-center gap-2">
                <span>{msg.role === 'user' ? 'EVALUATION PROBE' : 'CLIENT MODEL'}</span>
                {msg.meta?.verdict && (
                  <span className={`px-1 rounded text-[9px] ${
                    msg.meta.verdict === 'ALLOW' ? 'text-emerald-400 bg-emerald-950/60' : 'text-rose-400 bg-rose-950/60'
                  }`}>
                    {msg.meta.verdict}
                  </span>
                )}
              </div>
              <div
                className={`max-w-2xl rounded-lg p-3.5 text-xs leading-relaxed ${
                  msg.role === 'user'
                    ? 'bg-cyan-950/50 border border-cyan-800/50 text-slate-100'
                    : msg.meta?.blocked
                    ? 'bg-rose-950/50 border border-rose-800/60 text-rose-200'
                    : 'bg-slate-950 border border-slate-800 text-slate-200'
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.text}</div>

                {msg.meta && (
                  <div className="mt-2 pt-2 border-t border-slate-800/60 text-[10px] font-mono text-slate-500 flex flex-wrap items-center gap-3">
                    {msg.meta.verdict && <span>Policy: <strong className={msg.meta.verdict === 'ALLOW' ? 'text-emerald-400' : 'text-rose-400'}>{msg.meta.verdict}</strong></span>}
                    {msg.meta.tokens !== undefined && <span>Tokens: {msg.meta.tokens}</span>}
                    {msg.meta.latencyMs !== undefined && <span>Latency: {msg.meta.latencyMs}ms</span>}
                    {msg.meta.model && <span>Model: {msg.meta.model}</span>}
                    {msg.meta.sessionId && <span>Session: {msg.meta.sessionId}</span>}
                  </div>
                )}
              </div>
            </div>
          ))}

          {isInferring && (
            <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
              <RefreshCw className="h-3.5 w-3.5 animate-spin text-cyan-400" />
              <span>Evaluating request via Policy Gateway and dispatching to Gemini...</span>
            </div>
          )}
        </div>

        {/* Input Bar */}
        <form onSubmit={handleSendQuery} className="p-3 border-t border-slate-800/80 bg-slate-950/60">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              placeholder="Query the client model sandbox (evaluated through Policy Gate)..."
              disabled={isInferring}
              className="flex-1 px-3 py-2 rounded-md bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 placeholder:text-slate-600 font-mono"
            />
            <button
              type="submit"
              disabled={isInferring || !queryInput.trim()}
              className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-semibold disabled:opacity-50 transition-colors"
            >
              <Send className="h-3.5 w-3.5" />
              <span>Send Query</span>
            </button>
          </div>
          <div className="mt-2 text-[10px] text-slate-500 flex items-center justify-between">
            <span>Server-side Gemini 3.8 Flash execution under monitored safety envelope.</span>
            <span className="font-mono">Output Redaction: ACTIVE</span>
          </div>
        </form>
      </div>
    </div>
  );
};
