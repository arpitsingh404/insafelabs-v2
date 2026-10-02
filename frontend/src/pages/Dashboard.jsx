import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip, LabelList,
  AreaChart, Area, CartesianGrid, RadialBarChart, RadialBar, PolarAngleAxis,
  RadarChart, PolarGrid, Radar,
} from "recharts";
import {
  Bug, ShieldAlert, Flame, Boxes, Bot, Globe, Smartphone, Code2, Radar as RadarIcon,
  Loader2, Fingerprint, Swords, Wrench, Gauge, Cloud, Activity as ActivityIcon,
  TrendingUp, Crosshair, ChevronRight, Coins, Hand, ShieldHalf, Server, KeyRound,
  Network, CalendarDays, Radar as RadarLucide, Terminal, Volume2, VolumeX, Trash2,
  Loader2 as Spinner, Clock, Layers, RefreshCw, Rows, Timer, Download, Copy, LayoutGrid,
} from "lucide-react";
import {
  AlertDialog, AlertDialogTrigger, AlertDialogContent, AlertDialogHeader, AlertDialogTitle,
  AlertDialogDescription, AlertDialogFooter, AlertDialogCancel, AlertDialogAction,
} from "@/components/ui/alert-dialog";
import { LiveCommandBar } from "@/components/OperatorConsole";
import { ExportHistoryButton } from "@/components/ClearHistoryControls";
import { ThreatMap, AlertsFeed } from "@/components/ThreatMap";
import { ChronoDeck } from "@/components/ChronoDeck";

const SEV_COLORS = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#A1A1AA" };
const POSTURE = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#71717A" };
const SEV_LEGEND = [["critical", "#EF4444"], ["high", "#F97316"], ["medium", "#F59E0B"], ["low", "#3B82F6"]];

const ACT_META = {
  scanner: { icon: RadarIcon, color: "#FACC15" }, osint: { icon: Fingerprint, color: "#3B82F6" },
  cloud: { icon: Cloud, color: "#F59E0B" }, redteam: { icon: Swords, color: "#EF4444" },
  web: { icon: Globe, color: "#A1A1AA" }, mobile: { icon: Smartphone, color: "#A1A1AA" },
  "code-review": { icon: Code2, color: "#A1A1AA" },
};

const LAUNCH = [
  { id: "scanner", to: "/app/scanner", icon: RadarIcon, label: "Scanner" },
  { id: "osint", to: "/app/osint", icon: Fingerprint, label: "OSINT" },
  { id: "redteam", to: "/app/redteam", icon: Swords, label: "Red Team" },
  { id: "toolkit", to: "/app/toolkit", icon: Wrench, label: "Toolkit" },
  { id: "web", to: "/app/web", icon: Globe, label: "Web App" },
  { id: "mobile", to: "/app/mobile", icon: Smartphone, label: "Mobile" },
  { id: "code-review", to: "/app/code-review", icon: Code2, label: "Code Review" },
  { id: "sca", to: "/app/sca", icon: Boxes, label: "SCA" },
  { id: "ai-pentest", to: "/app/ai-pentest", icon: Bot, label: "AI Pentest" },
];

// Quick section navigation for the long overview page. Slugs match the
// `section-<slug>` data-testid emitted by <SectionTitle>.
const SECTION_NAV = [
  ["operator-console-&-timekeeping", "Console"],
  ["key-metrics", "Metrics"],
  ["live-telemetry", "Telemetry"],
  ["analytics", "Analytics"],
  ["coverage-&-attack-surface", "Coverage"],
  ["module-breakdown-&-pipeline", "Pipeline"],
  ["operations", "Operations"],
];

// ---------------------------------------------------------------- shared bits
const SectionTitle = ({ icon: Icon, children, right }) => (
  <div className="flex items-center gap-2.5 pt-1" data-testid={`section-${String(children).toLowerCase().replace(/\s+/g, "-")}`}>
    <Icon className="w-4 h-4 text-primary shrink-0" />
    <h2 className="font-heading text-xs uppercase tracking-[0.2em] text-zinc-300 whitespace-nowrap">{children}</h2>
    <span className="flex-1 h-px bg-border" />
    {right}
  </div>
);

const Legend = ({ items }) => (
  <div className="flex flex-wrap items-center gap-3">
    {items.map(([name, color]) => (
      <span key={name} className="inline-flex items-center gap-1.5 data-label !tracking-normal">
        <span className="w-2.5 h-2.5" style={{ background: color }} /> {name}
      </span>
    ))}
  </div>
);

const Panel = ({ className = "", children, ...rest }) => (
  <div className={`bg-[#121212] border border-border ${className}`} {...rest}>{children}</div>
);

// Optional dashboard blocks the operator can show/hide (persisted).
const PANEL_DEFAULTS = { threatMap: true, gesture: true, console: true, timekeeping: true, heatmap: true };
const PANEL_LABELS = [
  ["threatMap", "Threat Map"],
  ["gesture", "Gesture card"],
  ["console", "Operator console"],
  ["timekeeping", "Timekeeping"],
  ["heatmap", "Activity heatmap"],
];

function PanelToggles({ panels, toggle }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button onClick={() => setOpen((o) => !o)} data-testid="panel-toggles" title="Show / hide panels"
        className="inline-flex items-center gap-1.5 border border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400 hover:text-primary hover:border-primary/50 transition-colors">
        <LayoutGrid className="w-3.5 h-3.5 text-primary" /> panels
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-[60]" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-9 z-[61] w-48 border border-border bg-[#0c0c0c] shadow-2xl p-2" data-testid="panel-menu">
            {PANEL_LABELS.map(([k, label]) => (
              <button key={k} onClick={() => toggle(k)} data-testid={`panel-${k}`}
                className="w-full flex items-center gap-2 px-2 py-1.5 text-xs font-mono text-zinc-400 hover:text-white transition-colors">
                <span className={`w-3.5 h-3.5 border border-border grid place-items-center text-[9px] ${panels[k] ? "bg-primary text-black" : ""}`}>{panels[k] ? "✓" : ""}</span>
                {label}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

const PanelHead = ({ icon: Icon, kicker, title, right, iconColor = "text-primary" }) => (
  <div className="flex items-center justify-between gap-3 mb-4">
    <div className="flex items-center gap-2.5 min-w-0">
      <Icon className={`w-4 h-4 shrink-0 ${iconColor}`} />
      <div className="min-w-0">
        {kicker ? <p className="data-label truncate">{kicker}</p> : null}
        <h3 className="font-heading text-lg font-semibold truncate">{title}</h3>
      </div>
    </div>
    {right}
  </div>
);

function useCountUp(target, dur = 700) {
  const [v, setV] = useState(0);
  const prev = useRef(0);
  useEffect(() => {
    const from = prev.current, to = Number(target) || 0;
    prev.current = to;
    if (from === to) { setV(to); return; }
    let raf, start;
    const step = (t) => {
      if (!start) start = t;
      const p = Math.min(1, (t - start) / dur);
      setV(Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => raf && cancelAnimationFrame(raf);
  }, [target, dur]);
  return v;
}

const Kpi = ({ icon: Icon, label, value, accent, testId, to }) => {
  const shown = useCountUp(value);
  const color = accent || "#e4e4e7";
  const cls = "group relative overflow-hidden bg-[#121212] border border-border p-4 hover:border-primary/45 hover:bg-[#151515] transition-colors block" + (to ? " cursor-pointer" : "");
  const body = (
    <>
      <span className="absolute inset-y-0 left-0 w-[3px] opacity-70 group-hover:opacity-100 transition-opacity" style={{ background: color }} />
      <div className="flex items-start justify-between gap-2">
        <span className="data-label leading-tight">{label}</span>
        <span className="w-7 h-7 shrink-0 grid place-items-center border" style={{ borderColor: color + "55", color }}>
          <Icon className="w-3.5 h-3.5" />
        </span>
      </div>
      <p className="font-mono text-3xl font-bold mt-3 tabular-nums leading-none" style={{ color }}>{shown}</p>
      {to ? <ChevronRight className="absolute bottom-3 right-3 w-3.5 h-3.5 text-zinc-600 group-hover:text-primary group-hover:translate-x-0.5 transition-all" /> : null}
    </>
  );
  return to
    ? <Link to={to} className={cls} data-testid={testId}>{body}</Link>
    : <div className={cls} data-testid={testId}>{body}</div>;
};

function playBeep() {
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    const ctx = new AC();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.type = "sine"; o.frequency.setValueAtTime(760, ctx.currentTime);
    o.connect(g); g.connect(ctx.destination);
    g.gain.setValueAtTime(0.0001, ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.14, ctx.currentTime + 0.02);
    o.frequency.exponentialRampToValueAtTime(1280, ctx.currentTime + 0.16);
    g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.42);
    o.start(); o.stop(ctx.currentTime + 0.44);
    setTimeout(() => ctx.close().catch(() => {}), 700);
  } catch { /* ignore */ }
}

function LiveClockChip() {
  const [now, setNow] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs text-white tabular-nums" data-testid="header-clock" title="Local time">
      <Clock className="w-3.5 h-3.5 text-primary" /> {now.toLocaleTimeString("en-GB", { hour12: false })}
    </span>
  );
}

function LiveTicker() {
  const [lines, setLines] = useState([]);
  const [buf, setBuf] = useState([]);
  const idxRef = useRef(0);
  const scrollRef = useRef(null);

  useEffect(() => {
    let active = true;
    const load = () => api.get("/dashboard/livefeed").then(({ data }) => active && setLines(data.lines || [])).catch(() => {});
    load();
    const id = setInterval(load, 12000);
    return () => { active = false; clearInterval(id); };
  }, []);

  useEffect(() => {
    if (!lines.length) return;
    const iv = setInterval(() => {
      setBuf((b) => {
        const line = lines[idxRef.current % lines.length];
        idxRef.current += 1;
        return [...b, { ...line, k: idxRef.current }].slice(-60);
      });
    }, 800);
    return () => clearInterval(iv);
  }, [lines]);

  useEffect(() => { if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight; }, [buf]);

  return (
    <div className="bg-[#050505] border border-border flex flex-col h-full" data-testid="live-ticker">
      <div className="px-4 py-3 border-b border-border flex items-center gap-2">
        <Terminal className="w-4 h-4 text-primary" />
        <span className="font-mono text-xs uppercase tracking-widest text-zinc-300">Live Attack Feed</span>
        <span className="ml-auto flex items-center gap-1.5 data-label text-emerald-400"><span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" /> streaming</span>
      </div>
      <div ref={scrollRef} className="p-4 font-mono text-[11px] leading-relaxed flex-1 min-h-[180px] max-h-[300px] overflow-y-auto">
        {buf.length === 0 ? (
          <p className="text-zinc-600">// waiting for scan telemetry… run a scan to populate the feed</p>
        ) : buf.map((l) => (
          <div key={l.k} className="flex items-start gap-2">
            <span className="text-zinc-600 shrink-0">{l.t}</span>
            {l.tag ? <span className="shrink-0 font-bold" style={{ color: SEV_COLORS[(l.tag || "").toLowerCase()] || "#A1A1AA" }}>{l.tag}</span> : null}
            <span style={{ color: l.c || "#9ca3af" }} className="truncate">{l.m}</span>
          </div>
        ))}
        {buf.length > 0 && <span className="inline-block w-2 h-3.5 bg-primary animate-pulse align-middle" />}
      </div>
    </div>
  );
}

const ChartTip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((a, p) => a + (Number(p.value) || 0), 0);
  return (
    <div className="bg-[#121212] border border-border p-2.5 font-mono text-[11px]">
      <p className="text-zinc-400 mb-1">{label}</p>
      {payload.map((p, i) => <p key={i} style={{ color: p.color || p.fill }}>{p.name}: {p.value}</p>)}
      {payload.length > 1 && <p className="text-zinc-300 border-t border-border mt-1 pt-1">total: {total}</p>}
    </div>
  );
};

const postureColor = (v) => v >= 80 ? "#EF4444" : v >= 60 ? "#F97316" : v >= 40 ? "#F59E0B" : v >= 20 ? "#3B82F6" : "#22C55E";
const postureLabel = (v) => v >= 80 ? "CRITICAL" : v >= 60 ? "HIGH" : v >= 40 ? "ELEVATED" : v >= 20 ? "GUARDED" : "LOW";

// ---- DEFCON threat-level banner ----
const DEFCON = {
  1: { label: "SEVERE", color: "#EF4444", desc: "Critical exposure — immediate remediation required" },
  2: { label: "HIGH", color: "#F97316", desc: "High-risk exposure detected across the surface" },
  3: { label: "ELEVATED", color: "#F59E0B", desc: "Elevated risk — active review recommended" },
  4: { label: "GUARDED", color: "#3B82F6", desc: "Minor exposure — under monitoring" },
  5: { label: "SECURE", color: "#22C55E", desc: "Nominal — no major exposure detected" },
};
function defconLevel(avgRisk, critical) {
  if (critical > 0 && avgRisk >= 65) return 1;
  if (avgRisk >= 60 || critical > 0) return 2;
  if (avgRisk >= 40) return 3;
  if (avgRisk >= 20) return 4;
  return 5;
}

function DefconBanner({ avgRisk, critical, high }) {
  const lvl = defconLevel(avgRisk, critical);
  const d = DEFCON[lvl];
  return (
    <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
      className="relative overflow-hidden border p-5 flex items-center gap-5 flex-wrap"
      style={{ borderColor: d.color + "55", background: `linear-gradient(90deg, ${d.color}12, transparent 60%)` }}
      data-testid="defcon-banner">
      <div className="absolute inset-0 pointer-events-none opacity-[0.06]" style={{ background: `repeating-linear-gradient(90deg, ${d.color} 0 1px, transparent 1px 10px)` }} />
      <div className="relative flex items-center gap-4">
        <div className="relative">
          <span className="absolute inline-flex h-full w-full rounded-full opacity-40 animate-ping" style={{ background: d.color }} />
          <ShieldHalf className="relative w-10 h-10" style={{ color: d.color }} strokeWidth={1.75} />
        </div>
        <div>
          <p className="data-label" style={{ color: d.color }}>Threat Condition</p>
          <div className="flex items-end gap-2">
            <span className="font-heading text-4xl font-black tabular-nums" style={{ color: d.color }}>DEFCON {lvl}</span>
            <span className="font-mono text-sm font-bold mb-1" style={{ color: d.color }}>{d.label}</span>
          </div>
          <p className="text-xs text-zinc-500 mt-0.5">{d.desc}</p>
        </div>
      </div>
      <div className="relative ml-auto flex items-center gap-2" data-testid="defcon-scale">
        {[1, 2, 3, 4, 5].map((n) => (
          <div key={n} className="flex flex-col items-center gap-1">
            <div className="w-8 h-2 transition-all" style={{ background: n === lvl ? DEFCON[n].color : "#27272a", boxShadow: n === lvl ? `0 0 12px ${DEFCON[n].color}` : "none" }} />
            <span className="font-mono text-[9px]" style={{ color: n === lvl ? DEFCON[n].color : "#52525b" }}>{n}</span>
          </div>
        ))}
      </div>
      <div className="relative flex items-center gap-6 pl-5 border-l border-border">
        <Link to="/app/findings?severity=critical" data-testid="defcon-critical" className="text-center hover:opacity-70 transition-opacity"><p className="font-mono text-2xl font-bold text-severity-critical tabular-nums">{critical}</p><p className="data-label">critical</p></Link>
        <Link to="/app/findings?severity=high" data-testid="defcon-high" className="text-center hover:opacity-70 transition-opacity"><p className="font-mono text-2xl font-bold text-severity-high tabular-nums">{high}</p><p className="data-label">high</p></Link>
        <div className="text-center"><p className="font-mono text-2xl font-bold text-primary tabular-nums">{avgRisk}</p><p className="data-label">avg risk</p></div>
      </div>
    </motion.div>
  );
}

function PostureGauge({ value }) {
  const color = postureColor(value);
  return (
    <Panel className="p-5" data-testid="posture-gauge">
      <PanelHead icon={Gauge} kicker="Aggregate" title="Security Posture" />
      <div className="relative h-36">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart innerRadius="72%" outerRadius="100%" data={[{ value }]} startAngle={220} endAngle={-40}>
            <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
            <RadialBar background={{ fill: "#1a1a1a" }} dataKey="value" cornerRadius={6} fill={color} angleAxisId={0} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="font-mono text-4xl font-bold tabular-nums" style={{ color }}>{value}</span>
          <span className="font-mono text-[10px] font-bold tracking-widest mt-1" style={{ color }}>{postureLabel(value)}</span>
        </div>
      </div>
    </Panel>
  );
}

function ModuleRadar({ data }) {
  const has = (data || []).some((d) => d.count > 0);
  const total = (data || []).reduce((a, d) => a + (d.count || 0), 0);
  return (
    <Panel className="p-5 h-full" data-testid="module-radar">
      <PanelHead icon={RadarLucide} kicker="Operational" title="Module Coverage" right={<span className="data-label">{total} ops</span>} />
      <div className="h-64">
        {has ? (
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart data={data} outerRadius="70%">
              <PolarGrid stroke="#27272a" />
              <PolarAngleAxis dataKey="module" tick={{ fill: "#a1a1aa", fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <Radar dataKey="count" name="ops" stroke="#FACC15" strokeWidth={2} fill="#FACC15" fillOpacity={0.22} />
              <Tooltip content={<ChartTip />} />
            </RadarChart>
          </ResponsiveContainer>
        ) : <div className="h-full flex items-center justify-center text-sm text-zinc-600">No module activity yet.</div>}
      </div>
    </Panel>
  );
}

function AttackSurface({ ports, secrets, secretsTotal }) {
  const maxP = Math.max(1, ...(ports || []).map((p) => p.count));
  return (
    <Panel className="p-5 md:p-6 grid sm:grid-cols-2 gap-6 h-full" data-testid="attack-surface">
      <div>
        <div className="mb-4 flex items-center gap-2.5"><Server className="w-4 h-4 text-primary" /><div><p className="data-label">Aggregate exposure</p><h3 className="font-heading text-base font-semibold">Top Exposed Services</h3></div></div>
        {(ports || []).length === 0 ? <p className="text-sm text-zinc-600">No open services recorded.</p> : (
          <div className="space-y-2.5">
            {ports.map((p, i) => (
              <div key={i} data-testid={`port-bar-${i}`}>
                <div className="flex items-center justify-between mb-1"><span className="font-mono text-xs text-zinc-300 truncate">{p.label}</span><span className="font-mono text-xs text-primary">{p.count}</span></div>
                <div className="h-2 bg-[#0a0a0a] border border-border overflow-hidden"><div className="h-full bg-primary" style={{ width: `${(p.count / maxP) * 100}%` }} /></div>
              </div>
            ))}
          </div>
        )}
      </div>
      <div>
        <div className="mb-4 flex items-center gap-2.5"><KeyRound className="w-4 h-4 text-severity-critical" /><div><p className="data-label">{secretsTotal} total leaked</p><h3 className="font-heading text-base font-semibold">Leaked Secret Types</h3></div></div>
        {(secrets || []).length === 0 ? <p className="text-sm text-zinc-600">No secrets exposed. Clean.</p> : (
          <div className="flex flex-wrap gap-2">
            {secrets.map((s, i) => (
              <span key={i} data-testid={`secret-chip-${i}`} className="inline-flex items-center gap-1.5 border border-severity-critical/40 bg-severity-critical/10 px-2.5 py-1.5 font-mono text-[11px] text-severity-critical">
                {s.type} <span className="text-white/70">×{s.count}</span>
              </span>
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}

function ActivityHeatmap({ data }) {
  const max = Math.max(1, ...(data || []).map((d) => d.count));
  const cols = [];
  for (let i = 0; i < (data || []).length; i += 7) cols.push(data.slice(i, i + 7));
  const total = (data || []).reduce((a, d) => a + d.count, 0);
  return (
    <Panel className="p-5 md:p-6" data-testid="activity-heatmap">
      <div className="mb-4 flex items-center gap-2.5">
        <CalendarDays className="w-4 h-4 text-primary" />
        <div><p className="data-label">Last 13 weeks</p><h3 className="font-heading text-lg font-semibold">Operation Activity</h3></div>
        <span className="ml-auto font-mono text-xs text-zinc-500">{total} ops</span>
      </div>
      <div className="flex gap-1 overflow-x-auto pb-1">
        {cols.map((week, wi) => (
          <div key={wi} className="flex flex-col gap-1">
            {week.map((day) => {
              const on = day.count > 0;
              const alpha = on ? 0.2 + 0.8 * (day.count / max) : 0;
              return <div key={day.date} title={`${day.date} · ${day.count} ops`}
                className="w-3.5 h-3.5 rounded-sm" style={{ background: on ? `rgba(250,204,21,${alpha})` : "#18181b", border: "1px solid #0d0d0d" }} />;
            })}
          </div>
        ))}
      </div>
      <div className="flex items-center gap-1.5 mt-3 justify-end">
        <span className="data-label">less</span>
        {[0, 0.25, 0.5, 0.75, 1].map((a) => <div key={a} className="w-3 h-3 rounded-sm" style={{ background: a === 0 ? "#18181b" : `rgba(250,204,21,${0.2 + 0.8 * a})`, border: "1px solid #0d0d0d" }} />)}
        <span className="data-label">more</span>
      </div>
    </Panel>
  );
}

function ClearHistoryButton() {
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const clear = async () => {
    setBusy(true);
    try {
      const { data } = await api.post("/dashboard/clear-history");
      toast.success(`Cleared ${data.total_deleted} records — fresh start`);
      setOpen(false);
      setTimeout(() => window.location.reload(), 700);
    } catch {
      toast.error("Could not clear history");
    } finally {
      setBusy(false);
    }
  };
  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <button data-testid="clear-history-btn" title="Clear all search / scan / lookup history"
          className="inline-flex items-center gap-1.5 border border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400 hover:text-severity-critical hover:border-severity-critical/50 transition-colors">
          <Trash2 className="w-3.5 h-3.5" /> clear history
        </button>
      </AlertDialogTrigger>
      <AlertDialogContent className="bg-[#0a0a0a] border-border" data-testid="clear-history-dialog">
        <AlertDialogHeader>
          <AlertDialogTitle className="font-heading flex items-center gap-2"><Trash2 className="w-4 h-4 text-severity-critical" /> Clear all history?</AlertDialogTitle>
          <AlertDialogDescription className="text-zinc-400">
            This permanently deletes every stored search, site check, scan, OSINT lookup, network map,
            code review, bug-bounty scan and AI session — a completely fresh start. Scheduled monitors are kept.
            This cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="flex items-center gap-3 border border-border bg-[#121212] px-3 py-2" data-testid="clear-history-export-row">
          <ExportHistoryButton testId="clear-history-export" />
          <span className="text-[11px] text-zinc-600 font-mono">download a full backup first</span>
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel data-testid="clear-history-cancel" className="border-border">Cancel</AlertDialogCancel>
          <AlertDialogAction data-testid="clear-history-confirm" disabled={busy} onClick={(e) => { e.preventDefault(); clear(); }}
            className="bg-severity-critical text-white hover:bg-red-600">
            {busy ? <Spinner className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />} Yes, wipe everything
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}


export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loadError, setLoadError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [tokens, setTokens] = useState(null);
  const navigate = useNavigate();
  const [soundOn, setSoundOn] = useState(() => localStorage.getItem("insafe_sound") !== "off");
  const [refreshMs, setRefreshMs] = useState(() => {
    const v = Number(localStorage.getItem("insafe_refresh_ms"));
    return [0, 15000, 30000, 60000].includes(v) ? v : 15000;
  });
  const [kpiGroup, setKpiGroup] = useState(() => localStorage.getItem("insafe_kpi_group") || "security");
  const [dense, setDense] = useState(() => localStorage.getItem("insafe_dense") === "1");
  const [trendDays, setTrendDays] = useState(() => (Number(localStorage.getItem("insafe_trend_days")) === 7 ? 7 : 14));
  const [launchFilter, setLaunchFilter] = useState("");
  const [panels, setPanels] = useState(() => {
    try { return { ...PANEL_DEFAULTS, ...JSON.parse(localStorage.getItem("insafe_panels") || "{}") }; }
    catch { return PANEL_DEFAULTS; }
  });
  const prevLevelRef = useRef(null);

  const fetchStats = useCallback(() => (
    api.get("/dashboard/stats")
      .then(({ data }) => { setLoadError(false); setStats(data); setLastUpdated(new Date()); })
      .catch(() => setLoadError(true))
  ), []);

  useEffect(() => { fetchStats(); }, [fetchStats]);

  useEffect(() => {
    if (!refreshMs) return undefined;
    const id = setInterval(fetchStats, refreshMs);
    return () => clearInterval(id);
  }, [refreshMs, fetchStats]);

  useEffect(() => {
    let active = true;
    api.get("/toolkit/imei/account").then(({ data }) => active && setTokens(data?.balance)).catch(() => {});
    return () => { active = false; };
  }, []);

  useEffect(() => { localStorage.setItem("insafe_sound", soundOn ? "on" : "off"); }, [soundOn]);
  useEffect(() => { localStorage.setItem("insafe_dense", dense ? "1" : "0"); }, [dense]);
  useEffect(() => { localStorage.setItem("insafe_kpi_group", kpiGroup); }, [kpiGroup]);
  useEffect(() => { localStorage.setItem("insafe_trend_days", String(trendDays)); }, [trendDays]);
  useEffect(() => { localStorage.setItem("insafe_panels", JSON.stringify(panels)); }, [panels]);
  useEffect(() => { localStorage.setItem("insafe_refresh_ms", String(refreshMs)); }, [refreshMs]);
  const togglePanel = (k) => setPanels((p) => ({ ...p, [k]: !p[k] }));

  // Keyboard shortcuts: R = refresh now, / = focus the quick-launch filter.
  useEffect(() => {
    const onKey = (e) => {
      const tag = (e.target?.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || e.target?.isContentEditable || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key.toLowerCase() === "r") { fetchStats(); }
      else if (e.key === "/") { e.preventDefault(); document.querySelector("[data-testid=quick-launch-filter]")?.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [fetchStats]);

  const goSection = (slug) => {
    const el = document.querySelector(`[data-testid="section-${slug}"]`);
    if (el) window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 80, behavior: "smooth" });
  };

  const exportSnapshot = () => {
    try {
      const blob = new Blob([JSON.stringify(stats, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `insafelabs-overview-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Snapshot exported");
    } catch { toast.error("Export failed"); }
  };

  const copySummary = async () => {
    const txt = [
      `InsafeLabs — Operations Overview (${new Date().toLocaleString()})`,
      `Findings: ${stats.total_findings} (critical ${stats.critical_findings}, high ${stats.high_findings})`,
      `Avg risk: ${stats.avg_risk}  ·  DEFCON ${defconLevel(stats.avg_risk ?? 0, stats.critical_findings)}`,
      `Recon scans: ${stats.recon_scans}  ·  OSINT: ${stats.osint_lookups ?? 0}  ·  Secrets: ${stats.secrets_total ?? 0}`,
      `Monitors: ${stats.monitors_active ?? 0}`,
    ].join("\n");
    try { await navigator.clipboard.writeText(txt); toast.success("Summary copied"); }
    catch { toast.error("Copy failed"); }
  };

  useEffect(() => { localStorage.setItem("insafe_sound", soundOn ? "on" : "off"); }, [soundOn]);

  // threat sound alert — beep when DEFCON escalates (more severe = lower number)
  useEffect(() => {
    if (!stats) return;
    const lvl = defconLevel(stats.avg_risk ?? 0, stats.critical_findings);
    if (prevLevelRef.current == null) { prevLevelRef.current = lvl; return; }
    if (lvl < prevLevelRef.current) {
      if (soundOn) playBeep();
      toast.error(`Threat escalated → DEFCON ${lvl} (${DEFCON[lvl].label})`);
    }
    prevLevelRef.current = lvl;
  }, [stats, soundOn]);

  if (loadError && !stats) {
    return (
      <div className="flex flex-col items-center justify-center h-96 gap-4" data-testid="dashboard-error">
        <ShieldAlert className="w-8 h-8 text-severity-critical" />
        <p className="text-zinc-300">Couldn't load dashboard telemetry.</p>
        <button onClick={() => { setLoadError(false); fetchStats(); }} data-testid="dashboard-retry"
          className="border border-primary/40 text-primary px-4 py-2 font-mono text-xs uppercase tracking-wider hover:bg-primary/10 transition-colors">
          Retry
        </button>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="flex flex-col items-center justify-center h-96 gap-5" data-testid="dashboard-loading">
        <div className="relative w-28 h-28 flex items-center justify-center">
          <div className="absolute inset-0 rounded-full border border-primary/20" />
          <div className="absolute inset-0 rounded-full radar-sweep overflow-hidden" />
          <motion.div
            className="relative w-10 h-10 bg-primary flex items-center justify-center glow-primary"
            animate={{ scale: [1, 1.12, 1] }} transition={{ duration: 1.4, repeat: Infinity, ease: "easeInOut" }}
          >
            <ActivityIcon className="w-5 h-5 text-black" strokeWidth={2.5} />
          </motion.div>
        </div>
        <span className="data-label">syncing telemetry…</span>
        <div className="w-64 h-0.5 bg-white/5 overflow-hidden">
          <motion.div className="h-full w-1/3 bg-primary" animate={{ x: ["-110%", "310%"] }}
            transition={{ duration: 1.2, repeat: Infinity, ease: "easeInOut" }} />
        </div>
      </div>
    );
  }

  const bySev = stats.by_severity || {};
  const sevData = ["critical", "high", "medium", "low", "info"].map((k) => ({ name: k, value: bySev[k] || 0, color: SEV_COLORS[k] }));
  const maxSev = Math.max(1, ...sevData.map((d) => d.value));
  const totalSev = sevData.reduce((a, d) => a + d.value, 0);

  const securityKpis = [
    { icon: Bug, label: "Findings", value: stats.total_findings, testId: "stat-total", to: "/app/findings" },
    { icon: Flame, label: "Critical", value: stats.critical_findings, accent: "#EF4444", testId: "stat-critical", to: "/app/findings?severity=critical" },
    { icon: ShieldAlert, label: "High", value: stats.high_findings, accent: "#F97316", testId: "stat-high", to: "/app/findings?severity=high" },
    { icon: Gauge, label: "Avg Risk", value: stats.avg_risk ?? 0, accent: "#FACC15", testId: "stat-avgrisk" },
    { icon: RadarIcon, label: "Recon Scans", value: stats.recon_scans, testId: "stat-recon" },
    { icon: Fingerprint, label: "OSINT", value: stats.osint_lookups ?? 0, accent: "#3B82F6", testId: "stat-osint" },
    { icon: Network, label: "Network Maps", value: stats.network_scans ?? 0, accent: "#8B5CF6", testId: "stat-network" },
    { icon: KeyRound, label: "Secrets Found", value: stats.secrets_total ?? 0, accent: "#EF4444", testId: "stat-secrets" },
  ];

  const platformKpis = [
    { icon: Boxes, label: "SCA Scans", value: stats.sca_scans ?? 0, testId: "stat-sca" },
    { icon: Bug, label: "SCA Vulns", value: stats.sca_vulnerabilities ?? 0, accent: "#F97316", testId: "stat-sca-vulns" },
    { icon: Smartphone, label: "APK Scans", value: stats.apk_scans ?? 0, accent: "#3B82F6", testId: "stat-apk" },
    { icon: Cloud, label: "Cloud Scans", value: stats.cloud_scans ?? 0, accent: "#F59E0B", testId: "stat-cloud" },
    { icon: Bot, label: "Pentest Sessions", value: stats.pentest_sessions ?? 0, testId: "stat-pentest" },
    { icon: Server, label: "Binary Scans", value: stats.binary_scans_count ?? 0, accent: "#8B5CF6", testId: "stat-binary" },
    { icon: ShieldAlert, label: "VDP Reports", value: stats.vdp_total ?? 0, accent: "#22C55E", testId: "stat-vdp" },
    { icon: ActivityIcon, label: "Monitors", value: stats.monitors_active ?? 0, accent: "#EF4444", testId: "stat-monitors" },
  ];

  const moduleData = Object.entries(stats.by_module || {}).map(([name, value]) => ({ name, value: value || 0 }));
  const trendData = (stats.severity_trend || []).slice(trendDays === 7 ? -7 : -14);
  const pipeline = [
    ["SCA scans", stats.sca_scans ?? 0],
    ["SCA vulnerabilities", stats.sca_vulnerabilities ?? 0],
    ["APK scans", stats.apk_scans ?? 0],
    ["Cloud scans", stats.cloud_scans ?? 0],
    ["Binary scans", stats.binary_scans_count ?? 0],
    ["Pentest sessions", stats.pentest_sessions ?? 0],
    ["VDP reports", stats.vdp_total ?? 0],
    ["Open alerts", stats.alerts_count ?? 0],
  ];

  const chip = "inline-flex items-center gap-1.5 border border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400";

  return (
    <div className={`${dense ? "p-4 md:p-5 space-y-4" : "p-5 md:p-8 space-y-6"}`} data-testid="dashboard-page">
      {/* ---- Page header ---- */}
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="data-label mb-2">/ Command Center</p>
            <h1 className="font-heading text-3xl md:text-4xl font-bold leading-tight">Operations Overview</h1>
            <p className="text-sm text-zinc-500 mt-1.5 max-w-xl">Real-time posture, live telemetry and coverage across your offensive surface.</p>
            {lastUpdated && <p className="font-mono text-[10px] text-zinc-600 mt-1.5">last updated {lastUpdated.toLocaleTimeString("en-GB", { hour12: false })}</p>}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={chip} data-testid="header-clock-wrap"><LiveClockChip /></span>
            {tokens != null && <span className={chip} data-testid="token-balance"><Coins className="w-3.5 h-3.5 text-primary" /> {tokens} tokens</span>}
            <span className={chip}><ActivityIcon className="w-3.5 h-3.5 text-primary" /> {stats.monitors_active ?? 0} monitors</span>
            <button onClick={() => fetchStats()} data-testid="refresh-btn" title="Refresh now"
              className={`${chip} hover:text-primary hover:border-primary/50 transition-colors`}>
              <RefreshCw className="w-3.5 h-3.5 text-primary" /> refresh
            </button>
            <span className={chip} title="Auto-refresh interval">
              <Timer className="w-3.5 h-3.5 text-primary" />
              <select value={refreshMs} onChange={(e) => setRefreshMs(Number(e.target.value))} data-testid="autorefresh-select"
                className="bg-transparent text-zinc-300 outline-none cursor-pointer">
                <option value={15000}>15s</option>
                <option value={30000}>30s</option>
                <option value={60000}>60s</option>
                <option value={0}>off</option>
              </select>
            </span>
            <button onClick={() => setSoundOn((s) => !s)} data-testid="sound-toggle" title="Threat sound alerts"
              className={`${chip} hover:text-primary hover:border-primary/50 transition-colors`}>
              {soundOn ? <Volume2 className="w-3.5 h-3.5 text-primary" /> : <VolumeX className="w-3.5 h-3.5 text-zinc-500" />} alert {soundOn ? "on" : "off"}
            </button>
            <button onClick={() => setDense((d) => !d)} data-testid="density-toggle" title="Toggle compact layout"
              className={`${chip} hover:text-primary hover:border-primary/50 transition-colors`}>
              <Rows className="w-3.5 h-3.5 text-primary" /> {dense ? "compact" : "comfortable"}
            </button>
            <button onClick={exportSnapshot} data-testid="export-snapshot" title="Export snapshot (JSON)"
              className={`${chip} hover:text-primary hover:border-primary/50 transition-colors`}>
              <Download className="w-3.5 h-3.5 text-primary" /> export
            </button>
            <button onClick={copySummary} data-testid="copy-summary" title="Copy summary to clipboard"
              className={`${chip} hover:text-primary hover:border-primary/50 transition-colors`}>
              <Copy className="w-3.5 h-3.5 text-primary" /> copy
            </button>
            <PanelToggles panels={panels} toggle={togglePanel} />
            <ClearHistoryButton />
          </div>
        </div>
      </header>

      {/* Section quick-nav + shortcut hints (sticky) */}
      <div className="sticky top-0 z-20 py-2.5 glass-header border-b border-border flex items-center gap-2 overflow-x-auto" data-testid="section-nav">
        <span className="data-label shrink-0 hidden sm:inline">sections</span>
        {SECTION_NAV.map(([slug, label]) => (
          <button key={slug} onClick={() => goSection(slug)} data-testid={`sectionnav-${label.toLowerCase()}`}
            className="shrink-0 border border-border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-zinc-400 hover:text-primary hover:border-primary/50 transition-colors">
            {label}
          </button>
        ))}
        <span className="ml-auto shrink-0 hidden lg:flex items-center gap-2 data-label">
          <kbd className="border border-border px-1">R</kbd> refresh
          <kbd className="border border-border px-1">/</kbd> filter
          <kbd className="border border-border px-1">⌘K</kbd> jump
        </span>
      </div>

      <DefconBanner avgRisk={stats.avg_risk ?? 0} critical={stats.critical_findings} high={stats.high_findings} />

      {/* Severity quick filters → Findings */}
      <div className="flex items-center gap-2 flex-wrap" data-testid="severity-quickfilters">
        <span className="data-label mr-1">jump to findings</span>
        {sevData.map((s) => (
          <button key={s.name} onClick={() => navigate(`/app/findings?severity=${s.name}`)} data-testid={`quickfilter-${s.name}`}
            className="inline-flex items-center gap-1.5 border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors hover:bg-white/[0.05]"
            style={{ borderColor: s.color + "66", color: s.color }}>
            {s.name} <span className="text-white/80">{s.value}</span>
          </button>
        ))}
      </div>

      {/* ---- Operator console + timekeeping (kept near the top) ---- */}
      {(panels.console || panels.timekeeping) && (
        <SectionTitle icon={Clock}>Operator Console &amp; Timekeeping</SectionTitle>
      )}
      {panels.console && <LiveCommandBar />}
      {panels.timekeeping && <ChronoDeck />}

      {/* ---- Key metrics ---- */}
      <SectionTitle icon={Layers} right={
        <div className="flex items-center gap-3">
          <span className="data-label hidden sm:inline">{stats.total_findings} findings tracked</span>
          <div className="flex border border-border" data-testid="kpi-group-toggle">
            {[["security", "Security"], ["platform", "Platform"]].map(([k, label]) => (
              <button key={k} onClick={() => setKpiGroup(k)} data-testid={`kpi-group-${k}`}
                className={`px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors ${kpiGroup === k ? "bg-primary text-black" : "text-zinc-400 hover:text-primary"}`}>
                {label}
              </button>
            ))}
          </div>
        </div>
      }>Key Metrics</SectionTitle>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 md:gap-4 nova-stagger">
        {(kpiGroup === "security" ? securityKpis : platformKpis).map((k) => <Kpi key={k.testId} {...k} />)}
      </div>

      {/* ---- Live telemetry ---- */}
      <SectionTitle icon={Terminal}>Live Telemetry</SectionTitle>
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 md:gap-6">
        <div className="lg:col-span-8"><LiveTicker /></div>
        <div className="lg:col-span-4"><AlertsFeed alerts={stats.alerts || []} /></div>
      </div>

      {panels.threatMap && <ThreatMap points={stats.threat_points || []} />}

      {panels.gesture && (
      <Link to="/app/gesture" data-testid="dash-gesture-card"
        className="group flex items-center gap-4 border border-primary/25 bg-gradient-to-r from-primary/[0.07] to-transparent p-4 hover:border-primary/50 transition-colors">
        <div className="w-11 h-11 border border-primary/40 bg-primary/10 flex items-center justify-center shrink-0"><Hand className="w-5 h-5 text-primary" /></div>
        <div className="min-w-0 flex-1">
          <p className="font-heading text-base font-semibold text-white">Gesture Control Deck <span className="ml-2 font-mono text-[10px] uppercase tracking-widest text-primary border border-primary/40 px-1.5 py-0.5">new</span></p>
          <p className="text-sm text-zinc-500">Webcam-based hand + face tracking — pinch to click, 🤲 two hands to zoom, say "scan example.com". 100% on-device.</p>
        </div>
        <ChevronRight className="w-5 h-5 text-zinc-600 group-hover:text-primary group-hover:translate-x-1 transition-all" />
      </Link>
      )}

      {/* ---- Analytics ---- */}
      <SectionTitle icon={TrendingUp}>Analytics</SectionTitle>
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 md:gap-6">
        <Panel className="lg:col-span-5 p-5 md:p-6" data-testid="risk-trend">
          <PanelHead icon={TrendingUp} kicker={`Last ${trendDays} days · by severity`} title="Findings Trend"
            right={
              <div className="flex items-center gap-3">
                <Legend items={SEV_LEGEND} />
                <div className="flex border border-border" data-testid="trend-range">
                  {[7, 14].map((d) => (
                    <button key={d} onClick={() => setTrendDays(d)} data-testid={`trend-${d}d`}
                      className={`px-2 py-0.5 font-mono text-[10px] transition-colors ${trendDays === d ? "bg-primary text-black" : "text-zinc-400 hover:text-primary"}`}>
                      {d}d
                    </button>
                  ))}
                </div>
              </div>
            } />
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 6, right: 6, left: -22, bottom: 0 }}>
                <defs>
                  {["critical", "high", "medium", "low"].map((k) => (
                    <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={SEV_COLORS[k]} stopOpacity={0.5} />
                      <stop offset="100%" stopColor={SEV_COLORS[k]} stopOpacity={0.02} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid stroke="#1f1f22" vertical={false} />
                <XAxis dataKey="date" tick={{ fill: "#71717a", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={{ stroke: "#27272a" }} tickLine={false} interval={1} />
                <YAxis allowDecimals={false} tick={{ fill: "#71717a", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
                <Tooltip content={<ChartTip />} />
                {["low", "medium", "high", "critical"].map((k) => (
                  <Area key={k} type="monotone" dataKey={k} name={k} stackId="1" stroke={SEV_COLORS[k]} strokeWidth={1.5} fill={`url(#g-${k})`} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel className="lg:col-span-4 p-5 md:p-6" data-testid="severity-chart">
          <PanelHead icon={Bug} kicker={`${totalSev} aggregated`} title="Risk Distribution"
            right={<span className="data-label hidden sm:block">click a bar →</span>} />
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevData} margin={{ top: 18, right: 6, left: -22, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fill: "#71717a", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={{ stroke: "#27272a" }} tickLine={false} />
                <YAxis allowDecimals={false} domain={[0, maxSev]} tick={{ fill: "#71717a", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={<ChartTip />} />
                <Bar dataKey="value" name="findings" cursor="pointer" onClick={(d) => d && d.name && navigate(`/app/findings?severity=${d.name}`)}>
                  {sevData.map((d) => <Cell key={d.name} fill={d.color} />)}
                  <LabelList dataKey="value" position="top" fill="#a1a1aa" fontSize={10} fontFamily="JetBrains Mono" />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <div className="lg:col-span-3 space-y-4 md:space-y-6">
          <PostureGauge value={stats.avg_risk ?? 0} />
          <Panel className="p-5 md:p-6" data-testid="top-targets">
            <PanelHead icon={Crosshair} kicker="Highest risk" title="Top Targets" />
            {(stats.top_targets || []).length === 0 ? (
              <p className="text-sm text-zinc-600">No scans yet.</p>
            ) : (
              <div className="space-y-3">
                {stats.top_targets.map((t, i) => (
                  <div key={i} data-testid={`top-target-${i}`}>
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="font-mono text-xs text-white truncate">{t.host}</span>
                      <span className="font-mono text-xs shrink-0" style={{ color: POSTURE[t.posture] }}>{t.risk_score}</span>
                    </div>
                    <div className="h-1.5 bg-[#0a0a0a] border border-border overflow-hidden">
                      <div className="h-full" style={{ width: `${Math.min(100, t.risk_score)}%`, background: POSTURE[t.posture] }} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>

      {/* ---- Coverage ---- */}
      <SectionTitle icon={RadarLucide}>Coverage &amp; Attack Surface</SectionTitle>
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 md:gap-6">
        <div className="lg:col-span-4"><ModuleRadar data={stats.module_coverage || []} /></div>
        <div className="lg:col-span-8"><AttackSurface ports={stats.top_ports || []} secrets={stats.secrets_exposed || []} secretsTotal={stats.secrets_total || 0} /></div>
      </div>

      {/* ---- Module breakdown + delivery pipeline ---- */}
      <SectionTitle icon={Boxes}>Module Breakdown &amp; Pipeline</SectionTitle>
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 md:gap-6">
        <Panel className="lg:col-span-7 p-5 md:p-6" data-testid="findings-by-module">
          <PanelHead icon={Layers} kicker="Web / Mobile / Code review" title="Findings by Module"
            right={<span className="data-label">{moduleData.reduce((a, d) => a + d.value, 0)} total</span>} />
          <div className="h-56">
            {moduleData.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={moduleData} layout="vertical" margin={{ top: 6, right: 24, left: 8, bottom: 0 }}>
                  <CartesianGrid stroke="#1f1f22" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} tick={{ fill: "#71717a", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" width={90} tick={{ fill: "#a1a1aa", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
                  <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={<ChartTip />} />
                  <Bar dataKey="value" name="findings" fill="#FACC15">
                    <LabelList dataKey="value" position="right" fill="#a1a1aa" fontSize={10} fontFamily="JetBrains Mono" />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : <div className="h-full flex items-center justify-center text-sm text-zinc-600">No module activity yet.</div>}
          </div>
        </Panel>
        <Panel className="lg:col-span-5 p-5 md:p-6" data-testid="pipeline">
          <PanelHead icon={Boxes} kicker="Engagements &amp; delivery" title="Pipeline" />
          <div className="divide-y divide-border">
            {pipeline.map(([label, value]) => (
              <div key={label} className="flex items-center justify-between py-2" data-testid={`pipeline-${label.toLowerCase().replace(/\s+/g, "-")}`}>
                <span className="text-sm text-zinc-400">{label}</span>
                <span className="font-mono text-sm text-white tabular-nums">{value}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* ---- Operations ---- */}
      <SectionTitle icon={ActivityIcon}>Operations</SectionTitle>
      {panels.heatmap && <ActivityHeatmap data={stats.scan_calendar || []} />}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 md:gap-6">
        <div className="lg:col-span-7" data-testid="quick-launch">
          <div className="flex items-center gap-2.5 mb-4">
            <Swords className="w-4 h-4 text-primary" /><h3 className="font-heading text-lg font-semibold">Quick Launch</h3>
            <input value={launchFilter} onChange={(e) => setLaunchFilter(e.target.value)} data-testid="quick-launch-filter"
              placeholder="filter…"
              className="ml-auto w-28 sm:w-36 bg-[#0a0a0a] border border-zinc-800 text-white px-2 py-1 text-xs font-mono focus:outline-none focus:border-primary transition-colors" />
          </div>
          <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-5 gap-3">
            {LAUNCH.filter((m) => m.label.toLowerCase().includes(launchFilter.trim().toLowerCase())).map((m) => (
              <Link key={m.id} to={m.to} data-testid={`quick-launch-${m.id}`}
                className="group bg-[#121212] border border-border p-4 flex flex-col items-center justify-center gap-2 hover:border-primary/50 hover:bg-primary/[0.04] transition-colors aspect-square">
                <span className="w-10 h-10 grid place-items-center border border-border group-hover:border-primary/40 transition-colors">
                  <m.icon className="w-5 h-5 text-zinc-400 group-hover:text-primary transition-colors" />
                </span>
                <span className="data-label text-center leading-tight">{m.label}</span>
              </Link>
            ))}
          </div>
        </div>

        <div className="lg:col-span-5 bg-[#0c0c0c] border border-border flex flex-col" data-testid="activity-log">
          <div className="px-5 py-4 border-b border-border flex items-center gap-2">
            <ActivityIcon className="w-4 h-4 text-primary" />
            <h3 className="font-heading text-sm font-semibold">Operations Log</h3>
            <span className="ml-auto data-label">{(stats.activity || []).length}</span>
          </div>
          <div className="p-4 font-mono text-[11px] space-y-1.5 overflow-y-auto max-h-[300px]">
            {(stats.activity || []).length === 0 ? (
              <p className="text-zinc-600">No operations logged yet.</p>
            ) : stats.activity.map((a, i) => {
              const meta = ACT_META[a.type] || { icon: Bug, color: "#71717a" };
              const t = (a.created_at || "").slice(11, 19) || "--:--:--";
              return (
                <div key={i} className="flex items-start gap-2" data-testid={`activity-${i}`}>
                  <span className="text-primary shrink-0">[{t}]</span>
                  <meta.icon className="w-3 h-3 mt-0.5 shrink-0" style={{ color: meta.color }} />
                  <span className="text-zinc-400 truncate">{a.text}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent assessments */}
      {stats.recent?.length > 0 && (
        <div className="bg-[#121212] border border-border" data-testid="recent-assessments">
          <div className="flex items-center justify-between p-5 border-b border-border">
            <div><p className="data-label">Latest activity</p><h3 className="font-heading text-lg font-semibold mt-1">Recent Assessments</h3></div>
          </div>
          <div className="divide-y divide-border">
            {stats.recent.map((a) => (
              <Link key={a.id} to={`/app/${a.module}`} className="flex items-center gap-4 px-5 py-3.5 hover:bg-white/[0.02] transition-colors group" data-testid={`recent-${a.id}`}>
                <SeverityBadge severity={a.posture} />
                <span className="text-sm text-white flex-1 truncate">{a.title}</span>
                <span className="data-label hidden md:block">{a.module}</span>
                <span className="font-mono text-xs text-zinc-400">{a.finding_count} findings</span>
                <span className="font-mono text-xs text-primary hidden sm:block">risk {a.risk_score}</span>
                <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-primary transition-colors" />
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
