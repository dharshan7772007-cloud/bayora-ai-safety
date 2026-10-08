/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { AppProvider, useApp } from './context/AppContext.tsx';
import { TopBar } from './components/TopBar.tsx';
import { DashboardView } from './components/DashboardView.tsx';
import { EvaluationPipelineView } from './components/EvaluationPipelineView.tsx';
import { RedTeamConsole } from './components/RedTeamConsole.tsx';
import { ClientLlmConsole } from './components/ClientLlmConsole.tsx';
import { BlueTeamConsole } from './components/BlueTeamConsole.tsx';
import { PolicyGatewayView } from './components/PolicyGatewayView.tsx';
import { AuditLedgerView } from './components/AuditLedgerView.tsx';
import { SecurityTestsView } from './components/SecurityTestsView.tsx';
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';

const AppContent: React.FC = () => {
  const { currentView, notification, setNotification } = useApp();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col bg-security-grid bg-radial-vignette selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header */}
      <TopBar />

      {/* Global Notification Banner */}
      {notification && (
        <div className="fixed bottom-6 right-6 z-50 max-w-md animate-in fade-in slide-in-from-bottom-3 duration-200">
          <div className={`p-3.5 rounded-lg border shadow-2xl flex items-start justify-between gap-3 text-xs backdrop-blur-md ${
            notification.type === 'error' ? 'bg-rose-950/90 border-rose-800 text-rose-200' :
            notification.type === 'warn' ? 'bg-amber-950/90 border-amber-800 text-amber-200' :
            notification.type === 'success' ? 'bg-emerald-950/90 border-emerald-800 text-emerald-200' :
            'bg-slate-900/95 border-slate-700 text-slate-200'
          }`}>
            <div className="flex items-start gap-2.5">
              {notification.type === 'error' && <AlertCircle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />}
              {notification.type === 'warn' && <AlertCircle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />}
              {notification.type === 'success' && <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />}
              {notification.type === 'info' && <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />}
              <span className="leading-snug">{notification.message}</span>
            </div>
            <button
              onClick={() => setNotification(null)}
              className="text-slate-400 hover:text-white shrink-0 ml-2"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Main Viewport Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {currentView === 'dashboard' && <DashboardView />}
        {currentView === 'evaluations' && <EvaluationPipelineView />}
        {currentView === 'security_tests' && <SecurityTestsView />}
        {currentView === 'red_team' && <RedTeamConsole />}
        {currentView === 'client_llm' && <ClientLlmConsole />}
        {currentView === 'blue_team' && <BlueTeamConsole />}
        {currentView === 'policy_gateway' && <PolicyGatewayView />}
        {currentView === 'audit_ledger' && <AuditLedgerView />}
      </main>

      {/* Clean Unboxed Editorial Footer */}
      <footer className="w-full border-t border-slate-800/80 bg-slate-950/80 py-4 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-400">BAYORA</span>
            <span aria-hidden="true">·</span>
            <span>Zero-Trust Adversarial AI Safety Infrastructure</span>
            <span aria-hidden="true">·</span>
            <span>SHA-256 Ledger Verified</span>
          </div>

          <div className="text-[11px] text-slate-500">
            Application-Level Policy Engine & Isolation Boundary PoC
          </div>
        </div>
      </footer>
    </div>
  );
};

export default function App() {
  return (
    <AppProvider>
      <AppContent />
    </AppProvider>
  );
}
