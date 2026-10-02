import { NavLink, Outlet, Link, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  LayoutDashboard, Globe, Smartphone, Code2, Boxes, Bot,
  Terminal, ShieldCheck, ExternalLink, Radar, Fingerprint, Swords, Wrench, Usb,
  Network, Share2, Binary, BookOpen, Hand, FileText, Bug, Target, LogOut, Cpu, Search,
  PanelLeftClose, PanelLeftOpen, KeyRound, Link2, Settings as SettingsIcon, Crosshair, ShieldAlert, Layers, Activity, Scale,
} from "lucide-react";
import { GestureProvider } from "@/context/GestureContext";
import { api, clearToken } from "@/lib/api";
import { OperatorLocationProvider } from "@/context/OperatorLocationContext";
import { LlmStatusChip } from "@/components/LlmStatusChip";
import { CommandPalette } from "@/components/CommandPalette";
import { AccentSwitcher } from "@/components/AccentSwitcher";

const NAV = [
  { to: "/app", end: true, label: "Command", icon: LayoutDashboard, id: "dashboard" },
  { to: "/app/bugbounty", label: "Bug Bounty", icon: Target, id: "bugbounty" },
  { to: "/app/scanner", label: "Attack Surface", icon: Radar, id: "scanner" },
  { to: "/app/vuln-suite", label: "Vuln Suite", icon: ShieldAlert, id: "vuln-suite" },
  { to: "/app/vapt", label: "VAPT", icon: ShieldAlert, id: "vapt" },
  { to: "/app/wapt", label: "WAPT", icon: Globe, id: "wapt" },
  { to: "/app/playbooks", label: "Playbooks", icon: Layers, id: "playbooks" },
  { to: "/app/soc", label: "SOC", icon: Activity, id: "soc" },
  { to: "/app/kill-chain", label: "Kill Chain", icon: Target, id: "kill-chain" },
  { to: "/app/proxy-chain", label: "Proxy Chain", icon: Network, id: "proxy-chain" },
  { to: "/app/legal", label: "NDA / Legal", icon: Scale, id: "legal" },
  { to: "/app/recon", label: "Recon Lab", icon: Radar, id: "recon" },
  { to: "/app/osint", label: "OSINT", icon: Fingerprint, id: "osint" },
  { to: "/app/redteam", label: "Red Team Ops", icon: Swords, id: "redteam" },
  { to: "/app/ad-enum", label: "AD / LDAP", icon: Network, id: "ad-enum" },
  { to: "/app/netmap", label: "Network Map", icon: Share2, id: "netmap" },
  { to: "/app/binre", label: "Reverse Eng", icon: Binary, id: "binre" },
  { to: "/app/operation", label: "Operation Report", icon: FileText, id: "operation" },
  { to: "/app/findings", label: "Findings", icon: Bug, id: "findings" },
  { to: "/app/toolkit", label: "Hacker Toolkit", icon: Wrench, id: "toolkit" },
  { to: "/app/all-tools", label: "All Tools", icon: Wrench, id: "all-tools" },
  { to: "/app/arsenal", label: "Arsenal", icon: Crosshair, id: "arsenal" },
  { to: "/app/crypto", label: "Crypto Lab", icon: KeyRound, id: "crypto" },
  { to: "/app/web-inspect", label: "Web Inspector", icon: Link2, id: "web-inspect" },
  { to: "/app/device", label: "USB Bridge", icon: Usb, id: "device" },
  { to: "/app/web", label: "Web App", icon: Globe, id: "web" },
  { to: "/app/mobile", label: "Mobile App", icon: Smartphone, id: "mobile" },
  { to: "/app/code-review", label: "Code Review", icon: Code2, id: "code-review" },
  { to: "/app/sca", label: "Composition (SCA)", icon: Boxes, id: "sca" },
  { to: "/app/ai-pentest", label: "AI Pentest", icon: Bot, id: "ai-pentest" },
  { to: "/app/ai-agent", label: "AI Agent", icon: Bot, id: "ai-agent" },
  { to: "/app/agents", label: "Agent Desk", icon: Cpu, id: "agents" },
  { to: "/app/gesture", label: "Gesture Control", icon: Hand, id: "gesture" },
  { to: "/app/settings", label: "Settings", icon: SettingsIcon, id: "settings" },
  { to: "/app/guide", label: "How to Use", icon: BookOpen, id: "guide" },
];

export const DashboardLayout = () => {
  const navigate = useNavigate();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("insafe_sidebar_collapsed") === "1");
  useEffect(() => { localStorage.setItem("insafe_sidebar_collapsed", collapsed ? "1" : "0"); }, [collapsed]);
  const logout = async () => {
    try { await api.post("/auth/logout"); } catch (e) { /* revoke best-effort */ }
    clearToken();
    navigate("/login", { replace: true });
  };

  // Last-login telemetry — surfaced once on console entry.
  useEffect(() => {
    const raw = localStorage.getItem("insafelabs_prev_login");
    if (!raw) return;
    localStorage.removeItem("insafelabs_prev_login");
    try {
      const p = JSON.parse(raw);
      if (p && (p.at || p.ip)) {
        const when = p.at ? new Date(p.at).toLocaleString() : "unknown time";
        toast.success(`Last login: ${when}`, { description: p.ip ? `from IP ${p.ip}` : undefined });
      }
    } catch (e) { /* ignore */ }
  }, []);

  // Auto session-lock after inactivity.
  useEffect(() => {
    const IDLE_MS = 15 * 60 * 1000;
    let timer;
    const onIdle = () => {
      clearToken();
      toast.warning("Console locked due to inactivity");
      navigate("/login", { replace: true });
    };
    const reset = () => { clearTimeout(timer); timer = setTimeout(onIdle, IDLE_MS); };
    const events = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => { clearTimeout(timer); events.forEach((e) => window.removeEventListener(e, reset)); };
  }, [navigate]);

  // Command palette (Ctrl/⌘ + K)
  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <GestureProvider>
    <OperatorLocationProvider>
    <div className="min-h-screen flex bg-background">
      {/* Sidebar */}
      <aside className={`hidden md:flex ${collapsed ? "w-16" : "w-64"} flex-col border-r border-border bg-[#0c0c0c] fixed h-screen z-30 transition-[width] duration-200`}>
        <Link to="/" className={`flex items-center ${collapsed ? "justify-center" : "gap-2.5 px-6"} h-16 border-b border-border`} data-testid="sidebar-brand">
          <div className="w-8 h-8 bg-primary flex items-center justify-center shrink-0">
            <Terminal className="w-4.5 h-4.5 text-black" strokeWidth={2.5} />
          </div>
          {!collapsed && <><span className="font-heading font-black text-lg tracking-tight text-white">InsafeLabs</span><span className="data-label mt-1">console</span></>}
        </Link>

        <nav className="flex-1 py-6 px-3 space-y-1 overflow-y-auto">
          {!collapsed && <p className="data-label px-3 mb-3">Offensive Modules</p>}
          {NAV.map(({ to, end, label, icon: Icon, id }) => (
            <NavLink
              key={id} to={to} end={end} data-testid={`nav-${id}`} title={collapsed ? label : undefined}
              className={({ isActive }) =>
                `flex items-center ${collapsed ? "justify-center" : "gap-3"} px-3 py-2.5 text-sm font-medium border-l-2 transition-colors duration-200 ${
                  isActive
                    ? "border-primary bg-primary/10 text-white"
                    : "border-transparent text-zinc-400 hover:text-white hover:bg-white/[0.03]"
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              {!collapsed && label}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-border p-3 space-y-2">
          <button onClick={logout} data-testid="logout-btn" title="Lock Console"
            className={`w-full flex items-center justify-center ${collapsed ? "" : "gap-2"} py-2 text-xs font-mono uppercase tracking-widest text-zinc-400 border border-border hover:border-severity-high/50 hover:text-severity-high transition-colors`}>
            <LogOut className="w-3.5 h-3.5" /> {!collapsed && "Lock Console"}
          </button>
          <button onClick={() => setCollapsed((c) => !c)} data-testid="sidebar-collapse" title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className={`w-full flex items-center justify-center ${collapsed ? "" : "gap-2"} py-2 text-xs font-mono uppercase tracking-widest text-zinc-400 border border-border hover:border-primary/50 hover:text-primary transition-colors`}>
            {collapsed ? <PanelLeftOpen className="w-3.5 h-3.5" /> : <><PanelLeftClose className="w-3.5 h-3.5" /> Collapse</>}
          </button>
          <a href="/" data-testid="sidebar-home" title="Back to site"
            className={`w-full flex items-center justify-center ${collapsed ? "" : "gap-2"} py-2 text-xs font-mono uppercase tracking-widest text-zinc-400 border border-border hover:border-primary/50 hover:text-primary transition-colors`}>
            <ExternalLink className="w-3.5 h-3.5" /> {!collapsed && "Back to site"}
          </a>
          {!collapsed && <p className="data-label text-center pt-2">InsafeLabs v2 · private ops</p>}
        </div>
      </aside>

      {/* Mobile top bar */}
      <div className="md:hidden fixed top-0 left-0 right-0 h-14 glass-header border-b border-border z-40 flex items-center justify-between px-4">
        <Link to="/app" className="flex items-center gap-2" data-testid="mobile-brand">
          <div className="w-7 h-7 bg-primary flex items-center justify-center">
            <Terminal className="w-4 h-4 text-black" strokeWidth={2.5} />
          </div>
          <span className="font-heading font-black text-white">InsafeLabs</span>
        </Link>
        <Link to="/" className="text-zinc-400" data-testid="mobile-home"><ExternalLink className="w-5 h-5" /></Link>
      </div>

      {/* Mobile bottom nav */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 h-16 glass-header border-t border-border z-40 flex items-stretch overflow-x-auto">
        {NAV.map(({ to, end, label, icon: Icon, id }) => (
          <NavLink
            key={id} to={to} end={end} data-testid={`mnav-${id}`}
            className={({ isActive }) =>
              `flex-1 min-w-[68px] flex flex-col items-center justify-center gap-1 text-[10px] ${isActive ? "text-primary" : "text-zinc-500"}`
            }
          >
            <Icon className="w-4 h-4" />
            {label.split(" ")[0]}
          </NavLink>
        ))}
      </nav>

      <main className={`flex-1 ${collapsed ? "md:ml-16" : "md:ml-64"} pt-14 md:pt-0 pb-20 md:pb-0 min-w-0 transition-[margin] duration-200`}>
        <div className="flex items-center gap-3 h-16 px-5 md:px-8 border-b border-border bg-[#0a0a0a]/60">
          <ShieldCheck className="w-4 h-4 text-primary" />
          <span className="data-label hidden sm:inline">InsafeLabs Private Ops · Authorized Testing Only</span>
          <div className="ml-auto flex items-center gap-3">
            <button onClick={() => setPaletteOpen(true)} data-testid="command-palette-open"
              className="hidden sm:inline-flex items-center gap-2 border border-border px-2.5 py-1 text-[11px] font-mono text-zinc-400 hover:text-primary hover:border-primary/50 transition-colors">
              <Search className="w-3.5 h-3.5" /> jump <kbd className="text-[10px] text-zinc-600 border border-border px-1">⌘K</kbd>
            </button>
            <AccentSwitcher />
            <LlmStatusChip />
            <span className="hidden lg:flex items-center gap-1.5 data-label"><span className="w-1.5 h-1.5 bg-emerald-400 rounded-full" /> engine online</span>
          </div>
        </div>
        <Outlet />
      </main>
      <CommandPalette items={NAV} open={paletteOpen} setOpen={setPaletteOpen} />
    </div>
    </OperatorLocationProvider>
    </GestureProvider>
  );
};
