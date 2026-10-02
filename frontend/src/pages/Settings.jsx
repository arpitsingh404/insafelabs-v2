import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { ACCENTS, applyAccent, getAccent } from "@/lib/theme";
import { Settings as SettingsIcon, Palette, PanelLeft, LayoutGrid, Download, Trash2, Cpu, Keyboard, Loader2 } from "lucide-react";

const PANEL_KEYS = [
  ["threatMap", "Threat Map"],
  ["gesture", "Gesture card"],
  ["console", "Operator console"],
  ["timekeeping", "Timekeeping"],
  ["heatmap", "Activity heatmap"],
];
const SHORTCUTS = [
  ["⌘ / Ctrl + K", "Open command palette"],
  ["R", "Refresh the overview"],
  ["/", "Focus the quick-launch filter"],
  ["Esc", "Close palette / dialogs"],
];

function Card({ icon: Icon, title, kicker, children, right }) {
  return (
    <div className="bg-[#121212] border border-border p-5">
      <div className="flex items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2.5">
          <Icon className="w-4 h-4 text-primary" />
          <div>
            {kicker ? <p className="data-label">{kicker}</p> : null}
            <h3 className="font-heading text-base font-semibold">{title}</h3>
          </div>
        </div>
        {right}
      </div>
      {children}
    </div>
  );
}

const Toggle = ({ on, onClick, label, testid }) => (
  <button onClick={onClick} data-testid={testid}
    className="w-full flex items-center justify-between py-2 border-b border-border/40 last:border-0 text-left">
    <span className="text-sm text-zinc-300">{label}</span>
    <span className={`w-9 h-5 border transition-colors relative ${on ? "bg-primary/20 border-primary/50" : "border-border bg-[#0a0a0a]"}`}>
      <span className={`absolute top-0.5 w-3.5 h-3.5 transition-all ${on ? "left-[18px] bg-primary" : "left-0.5 bg-zinc-600"}`} />
    </span>
  </button>
);

export default function Settings() {
  const [accent, setAccent] = useState(() => getAccent().id);
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("insafe_sidebar_collapsed") === "1");
  const [panels, setPanels] = useState(() => {
    try { return { threatMap: true, gesture: true, console: true, timekeeping: true, heatmap: true, ...JSON.parse(localStorage.getItem("insafe_panels") || "{}") }; }
    catch { return { threatMap: true, gesture: true, console: true, timekeeping: true, heatmap: true }; }
  });
  const [refreshMs, setRefreshMs] = useState(() => Number(localStorage.getItem("insafe_refresh_ms") || 15000));
  const [ai, setAi] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { localStorage.setItem("insafe_panels", JSON.stringify(panels)); }, [panels]);
  useEffect(() => { localStorage.setItem("insafe_sidebar_collapsed", collapsed ? "1" : "0"); }, [collapsed]);
  useEffect(() => { localStorage.setItem("insafe_refresh_ms", String(refreshMs)); }, [refreshMs]);
  useEffect(() => { api.get("/ai/status").then(({ data }) => setAi(data)).catch(() => setAi(false)); }, []);

  const pickAccent = (id) => { applyAccent(id); setAccent(id); };
  const exportData = async () => {
    try {
      const res = await api.get("/dashboard/export-history", { responseType: "blob" });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url; a.download = `insafelabs-history-${new Date().toISOString().slice(0, 10)}.json`;
      a.click(); URL.revokeObjectURL(url);
      toast.success("History exported");
    } catch { toast.error("Export failed"); }
  };
  const clearData = async () => {
    if (!window.confirm("Clear ALL history (scans, OSINT, results)? This cannot be undone.")) return;
    setBusy(true);
    try {
      const { data } = await api.post("/dashboard/clear-history");
      toast.success(`Cleared ${data.total_deleted} records`);
    } catch { toast.error("Clear failed"); }
    finally { setBusy(false); }
  };

  return (
    <div className="p-5 md:p-8 space-y-6 max-w-4xl" data-testid="settings-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Console</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><SettingsIcon className="w-7 h-7 text-primary" /> Settings</h1>
        <p className="text-sm text-zinc-500 mt-1.5">Appearance, layout, defaults and data — saved on this device.</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">
        <Card icon={Palette} kicker="Appearance" title="Accent theme">
          <div className="grid grid-cols-1 gap-1.5">
            {ACCENTS.map((a) => (
              <button key={a.id} onClick={() => pickAccent(a.id)} data-testid={`settings-accent-${a.id}`}
                className={`flex items-center gap-3 px-3 py-2 border text-sm font-mono transition-colors ${accent === a.id ? "border-primary/60 text-white bg-primary/5" : "border-transparent text-zinc-400 hover:border-border hover:text-white"}`}>
                <span className="w-4 h-4 border border-border" style={{ background: `hsl(${a.hsl})` }} />
                {a.label}
                {accent === a.id && <span className="ml-auto text-primary data-label">active</span>}
              </button>
            ))}
          </div>
        </Card>

        <Card icon={LayoutGrid} kicker="Layout" title="Overview panels">
          {PANEL_KEYS.map(([k, label]) => (
            <Toggle key={k} on={panels[k]} label={label} testid={`settings-panel-${k}`} onClick={() => setPanels((p) => ({ ...p, [k]: !p[k] }))} />
          ))}
        </Card>

        <Card icon={PanelLeft} kicker="Layout" title="Sidebar & refresh">
          <Toggle on={collapsed} label="Collapse sidebar to icons" testid="settings-sidebar-collapse" onClick={() => setCollapsed((c) => !c)} />
          <div className="pt-3">
            <p className="data-label mb-2">Auto-refresh interval</p>
            <div className="flex border border-border w-fit" data-testid="settings-refresh">
              {[15000, 30000, 60000, 0].map((v) => (
                <button key={v} onClick={() => setRefreshMs(v)} data-testid={`settings-refresh-${v}`}
                  className={`px-3 py-1.5 font-mono text-xs transition-colors ${refreshMs === v ? "bg-primary text-black" : "text-zinc-400 hover:text-primary"}`}>
                  {v ? `${v / 1000}s` : "off"}
                </button>
              ))}
            </div>
          </div>
        </Card>

        <Card icon={Cpu} kicker="AI engine" title="LLM backend">
          {ai === null ? (
            <p className="text-sm text-zinc-500 flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" /> loading…</p>
          ) : ai === false ? (
            <p className="text-sm text-zinc-500">AI status unavailable.</p>
          ) : (
            <div className="font-mono text-xs space-y-1.5" data-testid="settings-ai">
              <Row k="Backend" v={ai.backend} />
              <Row k="Model" v={ai.model} accent />
              <Row k="Key" v={ai.key_present ? "loaded ✓" : "missing ✗"} />
              <Row k="Spend (est.)" v={`$${Number(ai?.usage?.total_cost ?? 0).toFixed(4)}`} />
              <Row k="Calls" v={String(ai?.usage?.calls ?? 0)} />
            </div>
          )}
        </Card>

        <Card icon={Keyboard} kicker="Reference" title="Keyboard shortcuts">
          <div className="space-y-1.5">
            {SHORTCUTS.map(([k, d]) => (
              <div key={k} className="flex items-center gap-3 text-sm">
                <kbd className="font-mono text-[11px] border border-border px-2 py-0.5 text-primary min-w-[92px] text-center">{k}</kbd>
                <span className="text-zinc-400">{d}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card icon={Download} kicker="Data" title="Export & reset">
          <div className="flex flex-wrap gap-2">
            <button onClick={exportData} data-testid="settings-export"
              className="inline-flex items-center gap-2 border border-border px-3 py-2 text-xs font-mono uppercase tracking-wider text-zinc-300 hover:text-primary hover:border-primary/50 transition-colors">
              <Download className="w-3.5 h-3.5" /> export history
            </button>
            <button onClick={clearData} disabled={busy} data-testid="settings-clear"
              className="inline-flex items-center gap-2 border border-severity-critical/40 px-3 py-2 text-xs font-mono uppercase tracking-wider text-severity-critical hover:bg-severity-critical/10 transition-colors disabled:opacity-50">
              {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />} clear all history
            </button>
          </div>
          <p className="text-[11px] text-zinc-600 mt-3">Clears every stored scan, OSINT lookup and result. Scheduled monitors are kept.</p>
        </Card>
      </div>
    </div>
  );
}

const Row = ({ k, v, accent }) => (
  <div className="flex items-center justify-between gap-3 border-b border-border/40 pb-1">
    <span className="text-zinc-500">{k}</span>
    <span className={`truncate max-w-[62%] ${accent ? "text-primary" : "text-zinc-300"}`}>{v}</span>
  </div>
);
