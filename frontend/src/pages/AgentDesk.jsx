import { useEffect, useRef, useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { toast } from "sonner";
import { Markdown } from "@/components/Markdown";
import {
  Play, Loader2, Target, Terminal, ChevronDown, Cpu, Square, Clock,
  Brain, Radar, Share2, Network, Bug, Monitor, Swords, FileText,
} from "lucide-react";
import { AgentArena } from "@/components/AgentArena";

const ICONS = { brain: Brain, radar: Radar, share2: Share2, network: Network, bug: Bug, monitor: Monitor, swords: Swords, filetext: FileText };
const STATUS = {
  queued: "text-zinc-500 border-zinc-700",
  working: "text-primary border-primary/50",
  done: "text-emerald-400 border-emerald-400/40",
  failed: "text-severity-high border-severity-high/40",
  stopped: "text-amber-400 border-amber-400/40",
};

const DOT = { queued: "bg-zinc-600", working: "bg-primary animate-pulse", done: "bg-emerald-400", failed: "bg-severity-high", stopped: "bg-amber-400" };
const durMs = (a, b) => { if (!a) return null; const end = b ? new Date(b) : new Date(); const ms = end - new Date(a); return ms >= 0 ? ms : null; };
const fmtDur = (ms) => ms == null ? "—" : ms < 1000 ? `${ms}ms` : ms < 60000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;

function AgentCard({ a, selected }) {
  const [open, setOpen] = useState(false);
  const Icon = ICONS[a.icon] || Cpu;
  const cls = STATUS[a.status] || STATUS.queued;
  const logRef = useRef(null);
  const rootRef = useRef(null);
  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [a.log?.length]);
  useEffect(() => { if (selected) { setOpen(true); rootRef.current?.scrollIntoView({ behavior: "smooth", block: "center" }); } }, [selected]);
  return (
    <div ref={rootRef} data-agent-card={a.id} className={`border bg-[#121212] transition-all ${selected ? "border-cyan-400 ring-1 ring-cyan-400/40" : a.status === "working" ? "border-primary/40" : "border-border"}`} data-testid={`agent-card-${a.id}`}>
      <div className="flex items-center gap-3 px-4 py-3">
        <div className={`w-8 h-8 flex items-center justify-center border ${cls}`}>
          {a.status === "working" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Icon className="w-4 h-4" />}
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm text-white font-medium truncate">{a.name}</p>
          {a.objective ? <p className="text-[11px] text-zinc-500 truncate">{a.objective}</p> : null}
        </div>
        <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 border ${cls}`} data-testid={`agent-status-${a.id}`}>{a.status}</span>
      </div>
      {a.status === "working" && (
        <div className="h-1 bg-black/40 overflow-hidden"><div className="h-full bg-primary transition-all duration-500" style={{ width: `${a.progress || 10}%` }} /></div>
      )}
      {(a.log?.length > 0 || a.result_md) && (
        <div className="border-t border-border">
          <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-2 px-4 py-1.5 text-[11px] font-mono text-zinc-500 hover:text-zinc-300 transition-colors" data-testid={`agent-toggle-${a.id}`}>
            <Terminal className="w-3 h-3" /> activity ({a.log?.length || 0})
            <ChevronDown className={`w-3 h-3 ml-auto transition-transform ${open ? "rotate-180" : ""}`} />
          </button>
          {open && (
            <div className="px-4 pb-3">
              <div ref={logRef} className="max-h-40 overflow-y-auto bg-[#0a0a0a] border border-border p-2 space-y-0.5 font-mono text-[11px]">
                {(a.log || []).map((l, i) => <div key={i} className="text-zinc-400"><span className="text-zinc-600">›</span> {l.msg}</div>)}
                {(!a.log || a.log.length === 0) && <div className="text-zinc-600">no activity yet</div>}
              </div>
              {a.result_md && <div className="mt-2 border border-border p-3 bg-[#0a0a0a]"><Markdown>{a.result_md}</Markdown></div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AgentDesk() {
  const [task, setTask] = useState("");
  const [target, setTarget] = useState("");
  const [opId, setOpId] = useState(null);
  const [op, setOp] = useState(null);
  const [launching, setLaunching] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [resuming, setResuming] = useState(false);
  const [pollTick, setPollTick] = useState(0);
  const [sel, setSel] = useState(null);

  useEffect(() => {
    if (!opId) return;
    let stop = false, timer;
    const loop = async () => {
      try {
        const { data } = await api.get(`/agents/operations/${opId}`);
        if (!stop) setOp(data);
        if (["done", "failed", "stopped"].includes(data.status)) return;
      } catch (e) { /* transient */ }
      if (!stop) timer = setTimeout(loop, 1500);
    };
    loop();
    return () => { stop = true; clearTimeout(timer); };
  }, [opId, pollTick]);

  const launch = async () => {
    if (!task.trim() || launching) return;
    setLaunching(true); setOp(null); setOpId(null);
    try {
      const { data } = await api.post("/agents/run", { task: task.trim(), target: target.trim() });
      setOpId(data.id);
    } catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Launch failed"); }
    finally { setLaunching(false); }
  };

  const stopOp = async () => {
    if (!opId || stopping) return;
    setStopping(true);
    try { await api.post(`/agents/stop/${opId}`); toast.success("Operation stopped"); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Stop failed"); }
    finally { setStopping(false); }
  };

  const resumeOp = async () => {
    if (!opId || resuming) return;
    setResuming(true);
    try { await api.post(`/agents/resume/${opId}`); toast.success("Operation resumed"); setPollTick((t) => t + 1); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Resume failed"); }
    finally { setResuming(false); }
  };

  const running = op && ["planning", "running", "queued"].includes(op.status);

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="agent-desk">
      <div>
        <h1 className="font-heading text-3xl sm:text-4xl font-black tracking-tighter">Agent Desk</h1>
        <p className="text-zinc-400 text-sm mt-1">Give a task — the orchestrator plans it and deploys autonomous agents that work in real time.</p>
      </div>

      <div className="border border-border bg-[#0c0c0c] p-4 space-y-3">
        <div className="grid md:grid-cols-[1fr_320px] gap-3">
          <div>
            <label className="data-label flex items-center gap-1.5 mb-1"><Terminal className="w-3 h-3 text-primary" /> Task / Objective</label>
            <input value={task} onChange={(e) => setTask(e.target.value)} data-testid="agent-task-input"
              onKeyDown={(e) => { if (e.key === "Enter") launch(); }}
              placeholder="e.g. Recon this target and surface the top risks"
              className="w-full bg-black/60 border border-border px-3 py-2.5 text-sm text-white focus:outline-none focus:border-primary" />
          </div>
          <div>
            <label className="data-label flex items-center gap-1.5 mb-1"><Target className="w-3 h-3 text-primary" /> Target (optional)</label>
            <input value={target} onChange={(e) => setTarget(e.target.value)} data-testid="agent-target-input"
              onKeyDown={(e) => { if (e.key === "Enter") launch(); }}
              placeholder="example.com (authorized only)"
              className="w-full bg-black/60 border border-border px-3 py-2.5 text-sm text-white font-mono focus:outline-none focus:border-primary" />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button onClick={launch} disabled={launching || !task.trim() || running} data-testid="agent-launch-btn"
            className="bg-primary text-black font-mono font-bold uppercase tracking-widest px-5 py-2.5 inline-flex items-center gap-2 hover:bg-yellow-400 transition-colors disabled:opacity-60">
            {launching || running ? <><Loader2 className="w-4 h-4 animate-spin" /> {running ? "Agents working…" : "Launching…"}</> : <><Play className="w-4 h-4" /> Deploy Agents</>}
          </button>
          {running && (
            <button onClick={stopOp} disabled={stopping} data-testid="agent-stop-btn"
              className="border border-severity-high/50 text-severity-high font-mono font-bold uppercase tracking-widest px-5 py-2.5 inline-flex items-center gap-2 hover:bg-severity-high/10 transition-colors disabled:opacity-60">
              {stopping ? <><Loader2 className="w-4 h-4 animate-spin" /> Stopping…</> : <><Square className="w-4 h-4 fill-current" /> Stop</>}
            </button>
          )}
          {op?.status === "stopped" && (
            <button onClick={resumeOp} disabled={resuming} data-testid="agent-resume-btn"
              className="border border-emerald-400/50 text-emerald-400 font-mono font-bold uppercase tracking-widest px-5 py-2.5 inline-flex items-center gap-2 hover:bg-emerald-400/10 transition-colors disabled:opacity-60">
              {resuming ? <><Loader2 className="w-4 h-4 animate-spin" /> Resuming…</> : <><Play className="w-4 h-4" /> Resume</>}
            </button>
          )}
          <span className="text-[11px] font-mono text-zinc-600">Authorized targets only · agents run real recon + AI analysis</span>
        </div>
      </div>

      {op && (
        <div className="space-y-4" data-testid="agent-operation">
          {op.plan && (
            <div className="border border-primary/20 bg-primary/[0.04] px-4 py-2.5 flex items-start gap-2" data-testid="agent-plan">
              <Brain className="w-4 h-4 text-primary mt-0.5 shrink-0" />
              <div className="min-w-0"><span className="data-label !text-primary">Orchestrator plan</span><p className="text-sm text-zinc-300">{op.plan}</p></div>
              <span className={`ml-auto text-[10px] font-mono uppercase px-1.5 py-0.5 border shrink-0 ${op.status === "done" ? "text-emerald-400 border-emerald-400/40" : op.status === "failed" ? "text-severity-high border-severity-high/40" : op.status === "stopped" ? "text-amber-400 border-amber-400/40" : "text-primary border-primary/50"}`} data-testid="agent-op-status">{op.status}</span>
            </div>
          )}
          {op.agents?.length > 0 && <AgentArena agents={op.agents} selected={sel} onSelect={setSel} />}
          <div className="grid md:grid-cols-2 gap-3">
            {(op.agents || []).map((a) => <AgentCard key={a.id} a={a} selected={sel === a.id} />)}
          </div>
          {op.agents?.length > 0 && (
            <div className="border border-border bg-[#0c0c0c]" data-testid="agent-timeline">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-1 px-4 py-2.5 border-b border-border">
                <span className="data-label flex items-center gap-1.5"><Clock className="w-3 h-3 text-primary" /> Operation Timeline</span>
                <span className="text-[11px] font-mono text-zinc-400">Total: <span className="text-white" data-testid="op-total-time">{fmtDur(durMs(op.started_at, op.finished_at))}</span></span>
                <span className="text-[11px] font-mono text-zinc-400">Est. Zen spend: <span className="text-primary" data-testid="op-spend">${(op.spend || 0).toFixed(4)}</span></span>
              </div>
              <div className="p-3 space-y-1.5">
                {(op.agents || []).map((a) => (
                  <div key={a.id} className="flex items-center gap-3 text-[11px] font-mono" data-testid={`timeline-${a.id}`}>
                    <span className={`w-2 h-2 rounded-full shrink-0 ${DOT[a.status] || DOT.queued}`} />
                    <span className="w-36 sm:w-44 truncate text-zinc-300">{a.name}</span>
                    <span className={`uppercase w-16 ${(STATUS[a.status] || STATUS.queued).split(" ")[0]}`}>{a.status}</span>
                    <span className="ml-auto text-zinc-600 hidden sm:inline">{a.started_at ? new Date(a.started_at).toLocaleTimeString() : "—"}</span>
                    <span className="text-zinc-400 w-16 text-right">{a.status === "working" ? fmtDur(durMs(a.started_at)) : fmtDur(durMs(a.started_at, a.finished_at))}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {op.report && (
            <div className="border border-border bg-[#0c0c0c]" data-testid="agent-report">
              <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border"><FileText className="w-4 h-4 text-primary" /><span className="data-label">Operation Report</span></div>
              <div className="p-4"><Markdown>{op.report}</Markdown></div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
