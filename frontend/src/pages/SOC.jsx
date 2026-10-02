import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  Activity, ShieldAlert, Radar, Database, Cpu, Loader2, Plus, Trash2, CheckCircle2, XCircle, Bell, Search,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm";

const Chip = ({ ok, label, value }) => (
  <span className={`inline-flex items-center gap-1.5 border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider ${ok ? "border-emerald-400/40 text-emerald-400" : "border-severity-critical/40 text-severity-critical"}`}>
    {ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />} {label}: {value}
  </span>
);

const Stat = ({ k, v, accent }) => (
  <div className="border border-border bg-[#0a0a0a] px-3 py-2">
    <p className="data-label">{k}</p>
    <p className="font-mono text-lg font-bold mt-0.5 tabular-nums" style={{ color: accent || "#e4e4e7" }}>{v}</p>
  </div>
);

export default function SOC() {
  const [ov, setOv] = useState(null);
  const [ioc, setIoc] = useState("");
  const [iocRes, setIocRes] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = () => api.get("/soc/overview").then(({ data }) => setOv(data)).catch(() => setOv(false));
  useEffect(() => { load(); const id = setInterval(load, 20000); return () => clearInterval(id); }, []);

  const checkIoc = async () => {
    if (!ioc.trim()) return toast.error("Enter an IP, domain or email");
    setBusy(true); setIocRes(null);
    try { setIocRes((await api.post("/blacklist/check", { target: ioc.trim() })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Check failed"); }
    finally { setBusy(false); }
  };
  const addWatch = async () => {
    if (!iocRes) return;
    try {
      await api.post("/soc/watchlist", { target: iocRes.target, kind: iocRes.kind, listed_count: iocRes.listed_count });
      toast.success("Added to watchlist"); load();
    } catch { toast.error("Failed to add"); }
  };
  const delWatch = async (id) => { try { await api.delete(`/soc/watchlist/${id}`); load(); } catch {} };

  if (!ov) return <div className="flex items-center justify-center h-96 text-zinc-500 gap-2"><Loader2 className="w-5 h-5 animate-spin" /> <span className="data-label">loading SOC…</span></div>;

  const h = ov.health || {};
  const c = ov.counts || {};

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="soc-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><Activity className="w-7 h-7 text-primary" /> Security Operations Center</h1>
        <p className="text-sm text-zinc-500 mt-1.5">Live posture, IOC reputation (blacklists), alert triage and watchlist in one console.</p>
        <div className="flex flex-wrap gap-2 mt-3">
          <Chip ok={h.server === "ok"} label="server" value={h.server} />
          <Chip ok={h.mongo === "ok"} label="mongo" value={h.mongo} />
          <Chip ok={h.ai_key} label="ai key" value={h.ai_key ? "loaded" : "missing"} />
          <Chip ok={true} label="model" value={h.ai_model} />
        </div>
      </header>

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-2">
        <Stat k="Findings" v={c.findings} />
        <Stat k="Critical" v={c.critical} accent="#EF4444" />
        <Stat k="High" v={c.high} accent="#F97316" />
        <Stat k="Avg risk" v={c.avg_risk} accent="#FACC15" />
        <Stat k="Monitors" v={c.monitors} />
        <Stat k="Alerts" v={c.alerts} accent="#8B5CF6" />
      </div>

      {/* IOC / blacklist check */}
      <div className="bg-[#121212] border border-border p-5" data-testid="soc-ioc">
        <div className="flex items-center gap-2.5 mb-3"><Radar className="w-4 h-4 text-primary" /><h3 className="font-heading text-base font-semibold">IOC / Blacklist check</h3>
          <span className="data-label ml-2">RBL · DNSBL · URIBL</span></div>
        <div className="flex flex-col sm:flex-row gap-2">
          <input value={ioc} onChange={(e) => setIoc(e.target.value)} data-testid="soc-ioc-input" placeholder="IP, domain or email — e.g. 1.2.3.4 / example.com / user@example.com" className={inputCls} />
          <button onClick={checkIoc} disabled={busy} data-testid="soc-ioc-check" className={btnCls}>
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Check
          </button>
        </div>
        {iocRes && (
          <div className="mt-4 space-y-3" data-testid="soc-ioc-result">
            <div className="flex items-center gap-3">
              <span className={`font-mono text-lg font-bold ${iocRes.clean ? "text-emerald-400" : "text-severity-critical"}`}>{iocRes.clean ? "CLEAN" : `LISTED (${iocRes.listed_count})`}</span>
              <span className="data-label">{iocRes.kind} · {iocRes.target}</span>
              <button onClick={addWatch} data-testid="soc-ioc-watch" className="ml-auto inline-flex items-center gap-1.5 border border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400 hover:text-primary hover:border-primary/50"><Plus className="w-3.5 h-3.5" /> watchlist</button>
            </div>
            {iocRes.resolved_ips?.length > 0 && <p className="font-mono text-[11px] text-zinc-500">resolved: {iocRes.resolved_ips.join(", ")}</p>}
            {iocRes.ip_blocklists?.map((grp, i) => (
              <div key={i} className="border border-border bg-[#0a0a0a] p-3">
                <p className="data-label mb-1">IP {grp.ip}</p>
                <div className="flex flex-wrap gap-1.5">
                  {grp.lists.map((l, j) => (
                    <span key={j} title={l.codes.join(", ") || "not listed"} className={`text-[10px] font-mono border px-2 py-0.5 ${l.listed ? "border-severity-critical/50 text-severity-critical" : "border-border text-zinc-600"}`}>{l.label}{l.listed ? " ⛔" : ""}</span>
                  ))}
                </div>
              </div>
            ))}
            {iocRes.domain_blocklists?.length > 0 && (
              <div className="border border-border bg-[#0a0a0a] p-3">
                <p className="data-label mb-1">Domain / URI</p>
                <div className="flex flex-wrap gap-1.5">
                  {iocRes.domain_blocklists.map((l, j) => (
                    <span key={j} className={`text-[10px] font-mono border px-2 py-0.5 ${l.listed ? "border-severity-critical/50 text-severity-critical" : "border-border text-zinc-600"}`}>{l.label}{l.listed ? " ⛔" : ""}</span>
                  ))}
                </div>
              </div>
            )}
            {iocRes.mx?.length > 0 && <p className="font-mono text-[11px] text-zinc-500">MX: {iocRes.mx.map((m) => m.host).join(", ")}</p>}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 md:gap-6">
        {/* Alerts */}
        <div className="lg:col-span-7 bg-[#121212] border border-border" data-testid="soc-alerts">
          <div className="px-5 py-3 border-b border-border flex items-center gap-2"><Bell className="w-4 h-4 text-primary" /><h3 className="font-heading text-sm font-semibold">Alert Triage</h3><span className="ml-auto data-label">{(ov.alerts || []).length}</span></div>
          <div className="divide-y divide-border max-h-[320px] overflow-y-auto">
            {(ov.alerts || []).length === 0 ? <p className="p-5 text-sm text-zinc-600">No alerts.</p> : ov.alerts.map((a, i) => (
              <div key={i} className="px-5 py-3" data-testid={`soc-alert-${i}`}>
                <div className="flex items-center gap-2"><ShieldAlert className="w-3.5 h-3.5 text-severity-high" /><span className="font-mono text-xs text-white truncate">{a.target}</span><span className="ml-auto data-label">{a.count} new</span></div>
                <p className="text-[11px] text-zinc-500 mt-1">{(a.new_findings || []).slice(0, 3).join(" · ")}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Watchlist */}
        <div className="lg:col-span-5 bg-[#121212] border border-border" data-testid="soc-watchlist">
          <div className="px-5 py-3 border-b border-border flex items-center gap-2"><Database className="w-4 h-4 text-primary" /><h3 className="font-heading text-sm font-semibold">IOC Watchlist</h3><span className="ml-auto data-label">{(ov.watchlist || []).length}</span></div>
          <div className="divide-y divide-border max-h-[320px] overflow-y-auto">
            {(ov.watchlist || []).length === 0 ? <p className="p-5 text-sm text-zinc-600">Nothing watched yet.</p> : ov.watchlist.map((w) => (
              <div key={w.id} className="px-5 py-2.5 flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${w.listed_count ? "bg-severity-critical" : "bg-emerald-400"}`} />
                <span className="font-mono text-xs text-zinc-300 truncate">{w.target}</span>
                <span className="data-label ml-auto">{w.kind}</span>
                <button onClick={() => delWatch(w.id)} className="text-zinc-600 hover:text-severity-critical"><Trash2 className="w-3.5 h-3.5" /></button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Activity */}
      <div className="bg-[#121212] border border-border p-5" data-testid="soc-activity">
        <div className="flex items-center gap-2 mb-3"><Activity className="w-4 h-4 text-primary" /><h3 className="font-heading text-sm font-semibold">Operations Log</h3></div>
        <div className="font-mono text-[11px] space-y-1 max-h-64 overflow-y-auto">
          {(ov.activity || []).length === 0 ? <p className="text-zinc-600">No recent activity.</p> : ov.activity.map((a, i) => (
            <p key={i} className="text-zinc-400"><span className="text-primary">[{(a.created_at || "").slice(11, 19)}]</span> {a.text}</p>
          ))}
        </div>
      </div>
    </div>
  );
}
