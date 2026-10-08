import React, { useState } from 'react';
import { useApp, AppView } from '../context/AppContext.tsx';
import { Role } from '../types.ts';
import { Shield, ShieldAlert, Cpu, Lock, CheckCircle2, ChevronDown, UserCheck } from 'lucide-react';

const NAV_ITEMS: { id: AppView; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'evaluations', label: 'Evaluations' },
  { id: 'security_tests', label: 'Security Tests' },
  { id: 'red_team', label: 'Red Team' },
  { id: 'client_llm', label: 'Client LLM' },
  { id: 'blue_team', label: 'Blue Team' },
  { id: 'policy_gateway', label: 'Policy Gateway' },
  { id: 'audit_ledger', label: 'Audit Ledger' },
];

const ROLES: { id: Role; label: string; zone: string; icon: any; color: string }[] = [
  { id: 'SYSTEM_ADMIN', label: 'System Admin', zone: 'Root Governance', icon: Shield, color: 'text-cyan-400' },
  { id: 'RED_TEAM', label: 'Red Team Operator', zone: 'Isolated Attack Bench', icon: ShieldAlert, color: 'text-rose-400' },
  { id: 'BLUE_TEAM', label: 'Blue Team Analyst', zone: 'Heuristic Shield', icon: Lock, color: 'text-indigo-400' },
  { id: 'CLIENT_LLM', label: 'Model Auditor', zone: 'Sanitized Sandbox', icon: Cpu, color: 'text-emerald-400' },
];

export const TopBar: React.FC = () => {
  const { currentView, setCurrentView, activeRole, setActiveRole, status, setNotification } = useApp();
  const [roleMenuOpen, setRoleMenuOpen] = useState(false);

  const currentRoleObj = ROLES.find(r => r.id === activeRole) || ROLES[0];
  const isLedgerIntact = status?.zones?.auditLedger?.isValid ?? true;

  const handleRoleChange = (role: Role) => {
    setActiveRole(role);
    setRoleMenuOpen(false);
    setNotification({
      message: `Enclave context switched to ${role}. Cross-perimeter access rules enforced.`,
      type: 'info',
    });
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
        {/* Zone 1: Single text element wordmark */}
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setCurrentView('dashboard')}
            className="flex items-center gap-2.5 text-left group focus:outline-none"
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-950/80 border border-cyan-500/30 text-cyan-400 transition-colors group-hover:border-cyan-400/60">
              <Shield className="h-4 w-4" />
            </div>
            <span className="text-base font-bold tracking-tight text-slate-100 group-hover:text-cyan-400 transition-colors">
              BAYORA
            </span>
          </button>
          <span className="hidden xl:inline text-xs text-slate-500 border-l border-slate-800 pl-3">
            Secure Adversarial AI Infrastructure
          </span>
        </div>

        {/* Zone 2: Navigation links */}
        <nav className="hidden md:flex items-center gap-1 lg:gap-1.5 text-xs font-medium text-slate-400">
          {NAV_ITEMS.map((item) => {
            const isActive = currentView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentView(item.id)}
                className={`px-3 py-1.5 rounded-md whitespace-nowrap transition-colors ${
                  isActive
                    ? 'bg-slate-800/80 text-cyan-300 font-semibold shadow-xs'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: Actions & Role switcher */}
        <div className="flex items-center gap-2.5">
          {/* Security Status Indicator */}
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 text-xs border border-slate-800 rounded-md bg-slate-900/60">
            <span className={`h-2 w-2 rounded-full ${isLedgerIntact ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]' : 'bg-rose-500 animate-pulse'}`} />
            <span className="text-slate-400 text-[11px]">
              {isLedgerIntact ? 'Zero-Trust Enforced' : 'Integrity Alert'}
            </span>
          </div>

          {/* Role selector dropdown */}
          <div className="relative">
            <button
              onClick={() => setRoleMenuOpen(!roleMenuOpen)}
              className="flex items-center gap-2 rounded-md border border-slate-800 bg-slate-900/90 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-700 hover:bg-slate-850 transition-colors"
            >
              <currentRoleObj.icon className={`h-3.5 w-3.5 ${currentRoleObj.color}`} />
              <span className="hidden lg:inline">{currentRoleObj.label}</span>
              <span className="lg:hidden">{activeRole.split('_')[0]}</span>
              <ChevronDown className="h-3 w-3 text-slate-400" />
            </button>

            {roleMenuOpen && (
              <div className="absolute right-0 mt-2 w-64 rounded-lg border border-slate-800 bg-slate-900/95 p-1.5 shadow-xl backdrop-blur-md z-50">
                <div className="px-2.5 py-1.5 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Select Security Role
                </div>
                <div className="space-y-0.5 mt-1">
                  {ROLES.map((r) => {
                    const isSelected = r.id === activeRole;
                    const Icon = r.icon;
                    return (
                      <button
                        key={r.id}
                        onClick={() => handleRoleChange(r.id)}
                        className={`flex w-full items-start gap-2.5 rounded-md px-2.5 py-2 text-left text-xs transition-colors ${
                          isSelected
                            ? 'bg-slate-800/90 text-cyan-300'
                            : 'text-slate-300 hover:bg-slate-800/50 hover:text-white'
                        }`}
                      >
                        <Icon className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${r.color}`} />
                        <div className="flex-1">
                          <div className="font-medium">{r.label}</div>
                          <div className="text-[10px] text-slate-500">{r.zone}</div>
                        </div>
                        {isSelected && <CheckCircle2 className="h-3.5 w-3.5 text-cyan-400 shrink-0 self-center" />}
                      </button>
                    );
                  })}
                </div>
                <div className="mt-2 border-t border-slate-800/80 p-2 text-[10px] text-slate-500 leading-tight">
                  Cross-zone access is verified server-side. Private payloads remain shielded.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
