import { useEffect, useRef, useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { safeHttpUrl } from "@/lib/safeUrl";
import { toast } from "sonner";
import { SeverityBadge } from "@/components/SeverityBadge";
import { ClearModuleButton } from "@/components/ClearHistoryControls";
import {
  Target, Loader2, Play, ShieldAlert, Globe, Server, KeyRound, FileCode2,
  ChevronDown, Download, Sparkles, RefreshCw, ShieldCheck, Bug, Wifi, Zap, History,
  Braces, Copy, Search, Lock, Flag, Package, FileWarning, GitCompare,
} from "lucide-react";

const SEV_COLORS = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#A1A1AA" };
const METHOD_COLORS = { GET: "#22C55E", POST: "#F59E0B", PUT: "#3B82F6", DELETE: "#EF4444", PATCH: "#A855F7" };
const SEVS = ["critical", "high", "medium", "low", "info"];
const STAGES = [
  { k: "subdomains", label: "Subdomains" },
  { k: "probing", label: "Probing" },
  { k: "vuln_checks", label: "Vuln Checks" },
  { k: "js_recon", label: "JS Recon" },
  { k: "api_recon", label: "API Recon" },
  { k: "done", label: "Done" },
];
const TABS = [
  { k: "findings", label: "Findings", icon: ShieldAlert },
  { k: "hosts", label: "Live Hosts", icon: Server },
  { k: "subs", label: "Subdomains", icon: Globe },
  { k: "apis", label: "API Inventory", icon: Braces },
  { k: "js", label: "JS Recon", icon: FileCode2 },
  { k: "report", label: "AI Report", icon: Sparkles },
  { k: "diff", label: "Recon Diff", icon: GitCompare },
];

const DeltaChip = ({ label, n }) => (
  <span className={`font-mono text-[11px] px-2 py-0.5 border ${n > 0 ? "text-emerald-400 border-emerald-400/30 bg-emerald-400/5" : "text-zinc-600 border-border"}`}>
    {n > 0 ? "+" : ""}{n} {label}
  </span>
);

const DiffList = ({ title, testid, items, tone }) => (
  <div className="border border-border bg-[#121212] p-4" data-testid={testid}>
    <p className="data-label mb-3">{title} ({(items || []).length})</p>
    {(items || []).length === 0 ? <p className="text-sm text-zinc-600">Nothing new.</p> : (
      <div className={`font-mono text-[11px] space-y-0.5 max-h-80 overflow-y-auto pr-1 ${tone === "muted" ? "text-zinc-500 line-through" : "text-zinc-300"}`}>
        {items.map((x, i) => <p key={i} className="truncate">{x}</p>)}
      </div>
    )}
  </div>
);

function renderMd(md) {
  return md.split("\n").map((line, i) => {
    const l = line.trim();
    if (!l) return <div key={i} className="h-2" />;
    if (l.startsWith("### ")) return <h4 key={i} className="font-heading text-sm font-bold text-primary mt-3">{l.slice(4)}</h4>;
    if (l.startsWith("## ")) return <h3 key={i} className="font-heading text-base font-bold text-white mt-4">{l.slice(3)}</h3>;
    if (l.startsWith("# ")) return <h2 key={i} className="font-heading text-lg font-bold text-white mt-4">{l.slice(2)}</h2>;
    if (/^[-*]\s/.test(l)) return <p key={i} className="text-sm text-zinc-300 pl-4 relative before:content-['▸'] before:absolute before:left-0 before:text-primary">{l.replace(/^[-*]\s/, "").replace(/\*\*/g, "")}</p>;
    return <p key={i} className="text-sm text-zinc-400 leading-relaxed">{l.replace(/\*\*/g, "")}</p>;
  });
}

export default function BugBounty() {
  const [target, setTarget] = useState("");
  const [scope, setScope] = useState(false);
  const [scan, setScan] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [starting, setStarting] = useState(false);
  const [tab, setTab] = useState("findings");
  const [sevFilter, setSevFilter] = useState("");
  const [apiMethod, setApiMethod] = useState("");
  const [apiQuery, setApiQuery] = useState("");
  const [report, setReport] = useState("");
  const [genning, setGenning] = useState(false);
  const [recent, setRecent] = useState([]);
  const [open, setOpen] = useState(null);
  const [triaging, setTriaging] = useState(false);
  const [hideNoise, setHideNoise] = useState(false);
  const pollRef = useRef(null);

  const loadRecent = () => api.get("/bugbounty/scans").then(({ data }) => setRecent(data.scans || [])).catch(() => {});
  useEffect(() => { loadRecent(); }, []);

  useEffect(() => {
    if (!scanId) return;
    const poll = () => api.get(`/bugbounty/scan/${scanId}`).then(({ data }) => {
      setScan(data);
      if (data.ai_report && !report) setReport(data.ai_report);
      if (data.status === "done" || data.status === "error") {
        clearInterval(pollRef.current);
        loadRecent();
        if (data.status === "done") toast.success(`Scan complete — ${data.finding_count} findings`);
        if (data.status === "error") toast.error("Scan error: " + (data.error || "unknown"));
      }
    }).catch(() => {});
    poll();
    pollRef.current = setInterval(poll, 3000);
    return () => clearInterval(pollRef.current);
  }, [scanId]); // eslint-disable-line

  const start = async () => {
    if (!scope) { toast.error("Confirm the target is in-scope / authorized first"); return; }
    if (!target.trim()) { toast.error("Enter a target domain"); return; }
    setStarting(true); setReport(""); setScan(null); setSevFilter("");
    try {
      const { data } = await api.post("/bugbounty/scan", { target });
      setScanId(data.id);
      toast.success(`Recon started on ${data.target}`);
    } catch (e) { toast.error(formatApiError(e?.response?.data?.detail) || "Could not start scan"); }
    finally { setStarting(false); }
  };

  const openScan = (id) => { setReport(""); setSevFilter(""); setScanId(id); };

  const genReport = async () => {
    if (!scanId) return;
    setGenning(true);
    try {
      const { data } = await api.post(`/bugbounty/report/${scanId}`);
      setReport(data.markdown || "");
      toast.success("AI report generated");
    } catch (e) { toast.error(formatApiError(e?.response?.data?.detail) || "Report failed"); }
    finally { setGenning(false); }
  };

  const downloadPdf = async () => {
    if (!scanId) return;
    try {
      const { data } = await api.get(`/bugbounty/report/${scanId}/pdf`, { responseType: "blob", timeout: 60000 });
      const u = URL.createObjectURL(data);
      const a = document.createElement("a");
      a.href = u; a.download = `bugbounty-${scan?.target || "report"}.pdf`; a.click();
      setTimeout(() => URL.revokeObjectURL(u), 4000);
    } catch { toast.error("PDF download failed"); }
  };

  const downloadBlob = async (path, filename) => {
    try {
      const { data } = await api.get(path, { responseType: "blob", timeout: 60000 });
      const u = URL.createObjectURL(data);
      const a = document.createElement("a");
      a.href = u; a.download = filename; a.click();
      setTimeout(() => URL.revokeObjectURL(u), 4000);
    } catch { toast.error("Download failed"); }
  };
  const exportJson = () => scanId && downloadBlob(`/bugbounty/export/${scanId}/apis`, `insafelabs-apis-${scan?.target || "scan"}.json`);
  const exportPostman = () => scanId && downloadBlob(`/bugbounty/export/${scanId}/postman`, `insafelabs-postman-${scan?.target || "scan"}.json`);
  const exportSources = () => scanId && downloadBlob(`/bugbounty/export/${scanId}/sources`, `insafelabs-sources-${scan?.target || "scan"}.zip`);

  const runTriage = async () => {
    if (!scanId) return;
    setTriaging(true);
    try {
      const { data } = await api.post(`/bugbounty/triage/${scanId}`);
      setScan((s) => ({ ...s, triage: data }));
      const su = data.summary || {};
      toast.success("AI triage complete", { description: `${su.unique ?? 0} unique · ${su.duplicates ?? 0} dupes · ${su.false_positives ?? 0} likely false-positive` });
    } catch (e) {
      toast.error(formatApiError(e.response?.data?.detail) || "AI triage failed");
    } finally { setTriaging(false); }
  };

  const copyCurl = async (a) => {
    let curl = `curl -sk -X ${a.method} '${a.url}'`;
    if (a.method !== "GET" && (a.params || []).length) {
      const body = JSON.stringify(Object.fromEntries((a.params || []).map((p) => [p, ""])));
      curl += ` -H 'Content-Type: application/json' -d '${body}'`;
    }
    try {
      await navigator.clipboard.writeText(curl);
      toast.success("cURL copied to clipboard");
    } catch {
      toast.error("Clipboard blocked — copy manually");
    }
  };

  const running = scan && (scan.status === "queued" || scan.status === "running");
  const counts = scan?.counts || {};
  const triage = scan?.triage || null;
  const verdicts = triage ? Object.fromEntries((triage.triaged || []).map((t) => [t.id, t])) : {};
  const isNoise = (f) => verdicts[f.id] && (verdicts[f.id].verdict === "false_positive" || verdicts[f.id].duplicate_of);
  const findings = (scan?.findings || []).filter((f) => (!sevFilter || f.severity === sevFilter) && !(hideNoise && isNoise(f)));
  const stageIdx = STAGES.findIndex((s) => s.k === scan?.stage);
  const apiMethods = [...new Set((scan?.api_inventory || []).map((a) => a.method))];
  const apis = (scan?.api_inventory || []).filter(
    (a) => (!apiMethod || a.method === apiMethod) && (!apiQuery || (a.url || "").toLowerCase().includes(apiQuery.toLowerCase()))
  );

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="bugbounty-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary"><Target className="w-6 h-6 text-primary" /></div>
        <div className="flex-1">
          <p className="data-label mb-1">/ Offensive · Automated Recon Pipeline</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">Bug Bounty Engine</h1>
          <p className="text-sm text-zinc-500 mt-1">One domain in → subdomain enum, live-host probing, automated vuln checks, JS secret recon, and an AI-written submittable report.</p>
        </div>
      </div>

      {/* target form */}
      <div className="border border-border bg-[#121212] p-4 space-y-3" data-testid="bb-form">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input value={target} onChange={(e) => setTarget(e.target.value)} data-testid="bb-target-input"
              onKeyDown={(e) => e.key === "Enter" && start()}
              placeholder="target domain — e.g. example.com"
              className="w-full bg-[#0a0a0a] border border-border pl-9 pr-3 py-2.5 text-sm text-white placeholder:text-zinc-600 focus:border-primary/50 outline-none" />
          </div>
          <button onClick={start} disabled={starting || running} data-testid="bb-start"
            className="bg-primary text-black font-semibold px-6 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-50 glow-primary whitespace-nowrap">
            {starting || running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {running ? "Scanning…" : "Launch Recon"}
          </button>
          {recent.length > 0 && (
            <div className="relative">
              <History className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <select data-testid="bb-recent-select" onChange={(e) => e.target.value && openScan(e.target.value)} value=""
                className="bg-[#0a0a0a] border border-border pl-9 pr-3 py-2.5 text-sm text-zinc-300 focus:border-primary/50 outline-none sm:w-52">
                <option value="">Recent scans…</option>
                {recent.map((s) => <option key={s.id} value={s.id}>{`${s.target} · ${s.finding_count ?? 0}f`}</option>)}
              </select>
            </div>
          )}
          {recent.length > 0 && <ClearModuleButton module="bugbounty" onCleared={loadRecent} testId="bb-clear" />}
        </div>
        <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer" data-testid="bb-scope-label">
          <input type="checkbox" checked={scope} onChange={(e) => setScope(e.target.checked)} data-testid="bb-scope-checkbox" className="accent-primary w-4 h-4" />
          <ShieldCheck className="w-3.5 h-3.5 text-primary" /> I confirm this target is <b className="text-zinc-200">in-scope / authorized</b> for security testing.
        </label>
      </div>

      {/* progress */}
      {scan && (
        <div className="border border-border bg-[#121212] p-4 space-y-3" data-testid="bb-summary">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-sm text-white">{scan.target}</span>
            <span className={`data-label ${scan.status === "done" ? "text-emerald-400" : scan.status === "error" ? "text-severity-critical" : "text-primary"}`} data-testid="bb-stage">
              {running && <Loader2 className="w-3 h-3 inline animate-spin mr-1" />}{scan.stage}
            </span>
            <div className="ml-auto flex items-center gap-3 font-mono text-xs">
              <span className="text-zinc-400"><Globe className="w-3 h-3 inline text-zinc-500" /> {scan.sub_count ?? 0} subs</span>
              <span className="text-zinc-400"><Wifi className="w-3 h-3 inline text-emerald-400" /> {scan.live_count ?? 0} live</span>
              <span className="text-zinc-400"><Bug className="w-3 h-3 inline text-primary" /> {scan.finding_count ?? 0} findings</span>
              <span className="text-zinc-400"><Braces className="w-3 h-3 inline text-sky-400" /> {scan.api_count ?? 0} APIs</span>
              {scan.diff && (scan.diff.counts.new_subdomains + scan.diff.counts.new_apis + scan.diff.counts.new_hosts) > 0 && (
                <span className="text-emerald-400" data-testid="bb-diff-chip"><GitCompare className="w-3 h-3 inline" /> +{scan.diff.counts.new_subdomains} subs · +{scan.diff.counts.new_apis} APIs vs last scan</span>
              )}
            </div>
          </div>
          {/* stage stepper */}
          <div className="flex items-center gap-1" data-testid="bb-progress">
            {STAGES.map((s, i) => (
              <div key={s.k} className="flex-1">
                <div className="h-1.5" style={{ background: i <= stageIdx ? "#FACC15" : "#27272a" }} />
                <span className={`text-[9px] font-mono ${i <= stageIdx ? "text-primary" : "text-zinc-600"}`}>{s.label}</span>
              </div>
            ))}
          </div>
          {/* severity totals */}
          <div className="flex flex-wrap gap-2">
            {SEVS.map((s) => (
              <span key={s} className="inline-flex items-center gap-1.5 border border-border px-2.5 py-1 font-mono text-[11px]" style={{ color: SEV_COLORS[s] }}>
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEV_COLORS[s] }} /> {s} {counts[s] ?? 0}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* tabs */}
      {scan && (
        <>
          <div className="flex gap-1 border-b border-border overflow-x-auto">
            {TABS.map((t) => (
              <button key={t.k} onClick={() => setTab(t.k)} data-testid={`bb-tab-${t.k}`}
                className={`px-4 py-2.5 text-sm font-mono inline-flex items-center gap-2 border-b-2 transition-colors whitespace-nowrap ${tab === t.k ? "border-primary text-primary" : "border-transparent text-zinc-500 hover:text-zinc-300"}`}>
                <t.icon className="w-3.5 h-3.5" /> {t.label}
              </button>
            ))}
          </div>

          {/* Findings */}
          {tab === "findings" && (
            <div className="space-y-3" data-testid="bb-findings">
              <div className="flex flex-wrap items-center gap-2">
                <button onClick={() => setSevFilter("")} data-testid="bb-chip-all"
                  className={`px-3 py-1 text-xs font-mono uppercase border ${sevFilter === "" ? "border-primary text-primary" : "border-border text-zinc-400"}`}>all</button>
                {SEVS.map((s) => (
                  <button key={s} onClick={() => setSevFilter(s)} data-testid={`bb-chip-${s}`}
                    className={`px-3 py-1 text-xs font-mono uppercase border ${sevFilter === s ? "text-black" : "border-border text-zinc-400"}`}
                    style={sevFilter === s ? { background: SEV_COLORS[s], borderColor: SEV_COLORS[s] } : {}}>{s} {counts[s] ?? 0}</button>
                ))}
                <button onClick={runTriage} disabled={triaging || (scan?.findings || []).length === 0} data-testid="bb-triage-btn"
                  className="ml-auto inline-flex items-center gap-1.5 px-3 py-1 text-xs font-mono uppercase border border-primary/50 text-primary hover:bg-primary/10 transition-colors disabled:opacity-50">
                  {triaging ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />} AI Triage
                </button>
              </div>
              {triage && (
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border border-primary/20 bg-primary/[0.04] px-3 py-2" data-testid="bb-triage-summary">
                  <span className="data-label !text-primary inline-flex items-center gap-1"><Sparkles className="w-3 h-3" /> AI Triage</span>
                  <span className="text-xs font-mono text-emerald-400 inline-flex items-center gap-1"><ShieldCheck className="w-3 h-3" /> {triage.summary.confirmed} confirmed</span>
                  <span className="text-xs font-mono text-primary inline-flex items-center gap-1"><Zap className="w-3 h-3" /> {triage.summary.likely} likely</span>
                  <span className="text-xs font-mono text-zinc-400 inline-flex items-center gap-1"><ShieldAlert className="w-3 h-3" /> {triage.summary.false_positives} false-pos</span>
                  <span className="text-xs font-mono text-zinc-400 inline-flex items-center gap-1"><Copy className="w-3 h-3" /> {triage.summary.duplicates} dupes</span>
                  <label className="ml-auto flex items-center gap-1.5 text-xs text-zinc-400 cursor-pointer" data-testid="bb-hide-noise">
                    <input type="checkbox" checked={hideNoise} onChange={(e) => setHideNoise(e.target.checked)} className="accent-primary w-3.5 h-3.5" />
                    Hide noise
                  </label>
                </div>
              )}
              {findings.length === 0 ? (
                <div className="border border-border bg-[#121212] p-12 text-center text-zinc-500">
                  {running ? "Scanning in progress…" : "No findings in this view."}
                </div>
              ) : findings.map((f, i) => { const v = verdicts[f.id]; return (
                <div key={f.id} className={`border border-border bg-[#121212] ${v && (v.verdict === "false_positive" || v.duplicate_of) ? "opacity-60" : ""}`} data-testid={`bb-finding-${i}`}>
                  <button onClick={() => setOpen(open === f.id ? null : f.id)} className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/[0.02]">
                    <SeverityBadge severity={f.severity} />
                    <span className="font-mono text-xs w-9 shrink-0" style={{ color: SEV_COLORS[f.severity] }}>{f.cvss}</span>
                    <span className="text-sm text-white flex-1 truncate">{f.title}</span>
                    {v && (
                      <span data-testid={`bb-verdict-${i}`} className={`text-[10px] font-mono uppercase px-1.5 py-0.5 border shrink-0 ${
                        v.verdict === "confirmed" ? "text-emerald-400 border-emerald-400/40"
                        : v.verdict === "false_positive" ? "text-zinc-500 border-zinc-600"
                        : "text-primary border-primary/40"}`}>
                        {v.verdict === "confirmed" ? "confirmed" : v.verdict === "false_positive" ? "false-pos" : "likely"}{v.duplicate_of ? " · dupe" : ""}
                      </span>
                    )}
                    <span className="font-mono text-[11px] text-zinc-500 hidden md:inline truncate max-w-[200px]">{f.host}</span>
                    <ChevronDown className={`w-4 h-4 text-zinc-600 shrink-0 transition-transform ${open === f.id ? "rotate-180" : ""}`} />
                  </button>
                  {open === f.id && (
                    <div className="px-4 pb-4 pt-1 border-t border-border space-y-2 text-sm">
                      {v && (
                        <div className="border border-primary/20 bg-primary/[0.04] px-2.5 py-1.5" data-testid={`bb-verdict-detail-${i}`}>
                          <span className="font-mono uppercase text-[10px] text-primary">AI · {v.verdict.replace("_", " ")} · {v.confidence}% confidence</span>
                          {v.reason && <span className="block text-[12px] text-zinc-400 mt-0.5">{v.reason}</span>}
                          {v.duplicate_of && <span className="block text-[12px] text-zinc-500 mt-0.5">Marked as a duplicate of another finding.</span>}
                        </div>
                      )}
                      <p className="text-zinc-400">{f.detail}</p>
                      {f.evidence && <pre className="bg-[#0a0a0a] border border-border p-2 text-[11px] text-zinc-400 overflow-x-auto whitespace-pre-wrap break-all">{f.evidence}</pre>}
                      {f.remediation && <p className="text-[13px] text-emerald-400/90"><b>Fix:</b> {f.remediation}</p>}
                      <p className="data-label">{f.type} · {f.host}</p>
                    </div>
                  )}
                </div>
              ); })}
            </div>
          )}

          {/* Hosts */}
          {tab === "hosts" && (
            <div className="border border-border bg-[#121212] overflow-x-auto" data-testid="bb-hosts">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border text-left data-label">
                  <th className="px-4 py-2.5 font-normal">Host</th><th className="px-4 py-2.5 font-normal">Status</th>
                  <th className="px-4 py-2.5 font-normal">Server / Tech</th><th className="px-4 py-2.5 font-normal">WAF</th>
                </tr></thead>
                <tbody>
                  {(scan.live_hosts || []).map((h, i) => (
                    <tr key={i} className="border-b border-border/50" data-testid={`bb-host-${i}`}>
                      <td className="px-4 py-2.5"><a href={safeHttpUrl(h.url)} target="_blank" rel="noreferrer" className="font-mono text-xs text-primary hover:underline">{h.host}</a>{h.title && <span className="block text-[11px] text-zinc-600 truncate max-w-xs">{h.title}</span>}</td>
                      <td className="px-4 py-2.5"><span className="font-mono text-xs" style={{ color: h.status < 400 ? "#22C55E" : "#F97316" }}>{h.status}</span></td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-zinc-400">{[h.server, ...(h.tech || [])].filter(Boolean).join(" · ") || "—"}</td>
                      <td className="px-4 py-2.5">{h.waf ? <span className="font-mono text-[11px] text-severity-medium">{h.waf}</span> : <span className="text-zinc-600 text-xs">—</span>}</td>
                    </tr>
                  ))}
                  {(scan.live_hosts || []).length === 0 && <tr><td colSpan={4} className="px-4 py-10 text-center text-zinc-500">{running ? "Probing…" : "No live hosts."}</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {/* Subdomains */}
          {tab === "subs" && (
            <div className="border border-border bg-[#121212] p-4" data-testid="bb-subs">
              <p className="data-label mb-3">{(scan.subdomains || []).length} discovered</p>
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-1 font-mono text-xs text-zinc-400">
                {(scan.subdomains || []).map((s, i) => <span key={i} className="truncate">{s}</span>)}
              </div>
            </div>
          )}

          {/* API Inventory */}
          {tab === "apis" && (
            <div className="space-y-3" data-testid="bb-apis">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input value={apiQuery} onChange={(e) => setApiQuery(e.target.value)} data-testid="bb-api-search"
                    placeholder="filter by URL / path…"
                    className="w-full bg-[#0a0a0a] border border-border pl-9 pr-3 py-2 text-sm text-white placeholder:text-zinc-600 focus:border-primary/50 outline-none" />
                </div>
                <div className="flex gap-1 flex-wrap">
                  <button onClick={() => setApiMethod("")} data-testid="bb-api-method-all"
                    className={`px-3 py-1.5 text-xs font-mono uppercase border ${apiMethod === "" ? "border-primary text-primary" : "border-border text-zinc-400"}`}>all</button>
                  {apiMethods.map((m) => (
                    <button key={m} onClick={() => setApiMethod(m)} data-testid={`bb-api-method-${m}`}
                      className={`px-3 py-1.5 text-xs font-mono uppercase border ${apiMethod === m ? "text-black" : "border-border"}`}
                      style={apiMethod === m ? { background: METHOD_COLORS[m] || "#A1A1AA", borderColor: METHOD_COLORS[m] || "#A1A1AA" } : { color: METHOD_COLORS[m] || "#A1A1AA" }}>{m}</button>
                  ))}
                </div>
                <div className="ml-auto flex gap-2">
                  <button onClick={exportJson} disabled={(scan.api_inventory || []).length === 0} data-testid="bb-export-json"
                    className="border border-border px-3 py-1.5 text-xs text-zinc-300 hover:text-primary hover:border-primary/50 inline-flex items-center gap-1.5 disabled:opacity-40">
                    <FileCode2 className="w-3.5 h-3.5" /> Export JSON
                  </button>
                  <button onClick={exportPostman} disabled={(scan.api_inventory || []).length === 0} data-testid="bb-export-postman"
                    className="border border-border px-3 py-1.5 text-xs text-zinc-300 hover:text-primary hover:border-primary/50 inline-flex items-center gap-1.5 disabled:opacity-40">
                    <Download className="w-3.5 h-3.5" /> Postman Collection
                  </button>
                </div>
              </div>

              {(scan.api_specs || []).length > 0 && (
                <div className="border border-sky-500/30 bg-sky-500/5 p-3" data-testid="bb-api-specs">
                  <p className="data-label mb-2 text-sky-400">Exposed API specs ({scan.api_specs.length})</p>
                  <div className="font-mono text-[11px] text-zinc-300 space-y-0.5">
                    {scan.api_specs.map((s, i) => <a key={i} href={s} target="_blank" rel="noreferrer" className="block truncate hover:text-sky-400">{s}</a>)}
                  </div>
                </div>
              )}

              {apis.length === 0 ? (
                <div className="border border-border bg-[#121212] p-12 text-center text-zinc-500">
                  {running ? "Discovering APIs…" : "No API endpoints discovered in this view."}
                </div>
              ) : (
                <div className="border border-border bg-[#121212] overflow-x-auto">
                  <p className="data-label px-3 pt-3">{apis.length} endpoints{apiMethod || apiQuery ? ` (filtered from ${(scan.api_inventory || []).length})` : ""}</p>
                  <table className="w-full text-sm mt-2">
                    <thead><tr className="border-b border-border text-left data-label">
                      <th className="px-3 py-2.5 font-normal">Method</th>
                      <th className="px-3 py-2.5 font-normal">Endpoint</th>
                      <th className="px-3 py-2.5 font-normal">Status</th>
                      <th className="px-3 py-2.5 font-normal">Type</th>
                      <th className="px-3 py-2.5 font-normal text-right">Copy</th>
                    </tr></thead>
                    <tbody>
                      {apis.map((a, i) => (
                        <tr key={i} className="border-b border-border/50 hover:bg-white/[0.02] align-top" data-testid={`bb-api-${i}`}>
                          <td className="px-3 py-2.5">
                            <span className="font-mono text-[11px] font-bold px-2 py-0.5 border inline-block" style={{ color: METHOD_COLORS[a.method] || "#A1A1AA", borderColor: (METHOD_COLORS[a.method] || "#A1A1AA") + "55" }}>{a.method}</span>
                          </td>
                          <td className="px-3 py-2.5">
                            <span className="font-mono text-[11px] text-zinc-200 break-all">{a.url}</span>
                            <span className="flex items-center gap-2 mt-0.5 flex-wrap">
                              <span className="text-[10px] text-zinc-600">{a.source}</span>
                              {a.summary && <span className="text-[10px] text-zinc-500 truncate max-w-[220px]">· {a.summary}</span>}
                              {(a.params || []).length > 0 && <span className="text-[10px] text-primary/70">· {a.params.length} params</span>}
                            </span>
                          </td>
                          <td className="px-3 py-2.5">
                            {a.status ? <span className="font-mono text-xs" style={{ color: a.status < 400 ? "#22C55E" : a.status < 500 ? "#F59E0B" : "#EF4444" }}>{a.status}</span> : <span className="text-zinc-600 text-xs">—</span>}
                          </td>
                          <td className="px-3 py-2.5">
                            <span className="flex items-center gap-1.5 flex-wrap">
                              {a.is_json && <span className="font-mono text-[10px] text-sky-400 border border-sky-400/30 px-1.5">JSON</span>}
                              {a.auth && <span className="font-mono text-[10px] text-severity-medium border border-severity-medium/30 px-1.5 inline-flex items-center gap-1"><Lock className="w-2.5 h-2.5" /> auth</span>}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-right">
                            <button onClick={() => copyCurl(a)} data-testid={`bb-api-curl-${i}`} className="text-zinc-500 hover:text-primary inline-flex items-center gap-1 text-[11px]">
                              <Copy className="w-3.5 h-3.5" /> cURL
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* JS recon */}
          {tab === "js" && (
            <div className="space-y-4" data-testid="bb-js">
              <div className="grid lg:grid-cols-2 gap-4">
                {/* Leaked secrets */}
                <div className="border border-border bg-[#121212] p-4" data-testid="bb-js-secrets">
                  <p className="data-label mb-3 flex items-center gap-1.5"><KeyRound className="w-3.5 h-3.5 text-severity-critical" /> Hardcoded secrets & API keys ({(scan.js_recon?.secrets || []).length})</p>
                  {(scan.js_recon?.secrets || []).length === 0 ? <p className="text-sm text-zinc-600">No secrets found in client-side JS.</p> : (
                    <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                      {scan.js_recon.secrets.map((s, i) => (
                        <div key={i} className="border border-severity-critical/30 bg-severity-critical/5 p-2">
                          <p className="font-mono text-[11px] text-severity-critical">{s.type}</p>
                          <p className="font-mono text-[11px] text-zinc-300 break-all">{s.match}</p>
                          <p className="text-[10px] text-zinc-600 truncate">{s.source}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                {/* Vulnerable libraries */}
                <div className="border border-border bg-[#121212] p-4" data-testid="bb-js-libs">
                  <p className="data-label mb-3 flex items-center gap-1.5"><Package className="w-3.5 h-3.5 text-severity-high" /> Third-party libraries ({(scan.js_recon?.libraries || []).length})</p>
                  {(scan.js_recon?.libraries || []).length === 0 ? <p className="text-sm text-zinc-600">No versioned libraries detected.</p> : (
                    <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                      {scan.js_recon.libraries.map((l, i) => (
                        <div key={i} className={`border p-2 ${l.vulnerable ? "border-severity-high/40 bg-severity-high/5" : "border-border"}`}>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-xs text-white">{l.name} <b className="text-zinc-300">{l.version}</b></span>
                            {l.vulnerable
                              ? <span className="font-mono text-[10px] text-black bg-severity-high px-1.5">VULN · CVSS {l.cvss}</span>
                              : <span className="font-mono text-[10px] text-emerald-400 border border-emerald-400/30 px-1.5">ok</span>}
                          </div>
                          {l.vulnerable && <p className="text-[11px] text-zinc-400 mt-1">{l.note} — fixed in {l.fixed}.</p>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div className="grid lg:grid-cols-2 gap-4">
                {/* Admin panels */}
                <div className="border border-border bg-[#121212] p-4" data-testid="bb-js-admin">
                  <p className="data-label mb-3 flex items-center gap-1.5"><Lock className="w-3.5 h-3.5 text-primary" /> Admin / management panels ({(scan.js_recon?.admin_panels || []).length})</p>
                  {(scan.js_recon?.admin_panels || []).length === 0 ? <p className="text-sm text-zinc-600">No admin interfaces referenced.</p> : (
                    <div className="space-y-1 max-h-96 overflow-y-auto pr-1">
                      {scan.js_recon.admin_panels.map((a, i) => (
                        <div key={i} className="flex items-center gap-2 font-mono text-[11px]">
                          {a.status ? <span className="w-8 shrink-0" style={{ color: a.status < 400 ? "#22C55E" : "#71717a" }}>{a.status}</span> : <span className="w-8 shrink-0 text-zinc-600">—</span>}
                          <a href={safeHttpUrl(a.url)} target="_blank" rel="noreferrer" className="text-zinc-300 hover:text-primary truncate flex-1">{a.url}</a>
                          {a.exposed && <span className="text-[9px] text-black bg-severity-high px-1 shrink-0">OPEN</span>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                {/* Source maps */}
                <div className="border border-border bg-[#121212] p-4" data-testid="bb-js-sourcemaps">
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <p className="data-label flex items-center gap-1.5"><FileWarning className="w-3.5 h-3.5 text-severity-medium" /> Exposed source maps ({(scan.js_recon?.source_maps || []).length})</p>
                    {(scan.js_recon?.source_maps || []).length > 0 && (
                      <button onClick={exportSources} data-testid="bb-export-sources"
                        className="border border-severity-medium/40 text-severity-medium px-2 py-1 text-[10px] inline-flex items-center gap-1 hover:bg-severity-medium/10 shrink-0">
                        <Download className="w-3 h-3" /> Export sources (.zip)
                      </button>
                    )}
                  </div>
                  {(scan.js_recon?.source_maps || []).length === 0 ? <p className="text-sm text-zinc-600">No exposed .js.map files (source code not disclosed).</p> : (
                    <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                      {scan.js_recon.source_maps.map((m, i) => (
                        <div key={i} className="border border-severity-medium/30 bg-severity-medium/5 p-2">
                          <a href={safeHttpUrl(m.url)} target="_blank" rel="noreferrer" className="font-mono text-[11px] text-severity-medium break-all hover:underline">{m.url}</a>
                          <p className="text-[10px] text-zinc-500 mt-0.5">{m.sources_count} original source files exposed</p>
                          {(m.sample || []).length > 0 && <p className="font-mono text-[10px] text-zinc-600 truncate">{m.sample.join(" · ")}</p>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div className="grid lg:grid-cols-3 gap-4">
                {/* Hidden endpoints */}
                <div className="border border-border bg-[#121212] p-4" data-testid="bb-js-endpoints">
                  <p className="data-label mb-3 flex items-center gap-1.5"><FileCode2 className="w-3.5 h-3.5 text-primary" /> Hidden endpoints ({(scan.js_recon?.endpoints || []).length})</p>
                  {(scan.js_recon?.endpoints || []).length === 0 ? <p className="text-sm text-zinc-600">None extracted.</p> : (
                    <div className="font-mono text-[11px] text-zinc-400 space-y-0.5 max-h-80 overflow-y-auto pr-1">
                      {scan.js_recon.endpoints.map((e, i) => <p key={i} className="truncate">{e}</p>)}
                    </div>
                  )}
                </div>
                {/* Feature flags */}
                <div className="border border-border bg-[#121212] p-4" data-testid="bb-js-flags">
                  <p className="data-label mb-3 flex items-center gap-1.5"><Flag className="w-3.5 h-3.5 text-sky-400" /> Feature flags ({(scan.js_recon?.feature_flags || []).length})</p>
                  {(scan.js_recon?.feature_flags || []).length === 0 ? <p className="text-sm text-zinc-600">None found.</p> : (
                    <div className="flex flex-wrap gap-1.5 max-h-80 overflow-y-auto pr-1">
                      {scan.js_recon.feature_flags.map((f, i) => <span key={i} className="font-mono text-[10px] text-sky-300 border border-sky-400/20 px-1.5 py-0.5 break-all">{f}</span>)}
                    </div>
                  )}
                </div>
                {/* Internal / staging domains */}
                <div className="border border-border bg-[#121212] p-4" data-testid="bb-js-internal">
                  <p className="data-label mb-3 flex items-center gap-1.5"><Globe className="w-3.5 h-3.5 text-severity-high" /> Internal / staging domains ({(scan.js_recon?.internal_domains || []).length})</p>
                  {(scan.js_recon?.internal_domains || []).length === 0 ? <p className="text-sm text-zinc-600">None leaked.</p> : (
                    <div className="font-mono text-[11px] text-zinc-300 space-y-0.5 max-h-80 overflow-y-auto pr-1">
                      {scan.js_recon.internal_domains.map((d, i) => <p key={i} className="truncate">{d}</p>)}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* AI report */}
          {tab === "report" && (
            <div className="border border-border bg-[#121212] p-5" data-testid="bb-report">
              <div className="flex items-center gap-3 mb-4 flex-wrap">
                <button onClick={genReport} disabled={genning || running} data-testid="bb-generate-report"
                  className="bg-primary text-black font-semibold px-5 py-2 inline-flex items-center gap-2 hover:bg-yellow-500 disabled:opacity-50">
                  {genning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />} {report ? "Regenerate" : "Generate AI Report"}
                </button>
                <button onClick={downloadPdf} data-testid="bb-download-pdf" className="border border-border px-4 py-2 text-sm text-zinc-300 hover:text-primary hover:border-primary/50 inline-flex items-center gap-2">
                  <Download className="w-4 h-4" /> Download PDF
                </button>
              </div>
              {report ? (
                <div className="prose-invert max-w-none space-y-1 border-t border-border pt-4" data-testid="bb-report-md">{renderMd(report)}</div>
              ) : (
                <p className="text-sm text-zinc-600">Generate an AI-written, submittable HackerOne/Bugcrowd-style report from these findings.</p>
              )}
            </div>
          )}

          {/* Recon Diff */}
          {tab === "diff" && (
            <div className="space-y-4" data-testid="bb-diff">
              {!scan.diff ? (
                <div className="border border-border bg-[#121212] p-12 text-center text-zinc-500">
                  <GitCompare className="w-8 h-8 mx-auto mb-3 text-zinc-700" />
                  No previous completed scan of <b className="text-zinc-300">{scan.target}</b> to compare against yet.
                  <br />Run this scan again later to see what changed since the baseline.
                </div>
              ) : (
                <>
                  <div className="border border-border bg-[#121212] p-4 flex flex-wrap items-center gap-3">
                    <GitCompare className="w-4 h-4 text-primary" />
                    <span className="text-sm text-zinc-300">Changes since baseline
                      <span className="font-mono text-xs text-zinc-500 ml-2">{scan.diff.baseline_date ? new Date(scan.diff.baseline_date).toLocaleString() : "—"}</span>
                    </span>
                    <div className="ml-auto flex gap-2 flex-wrap">
                      <DeltaChip label="subdomains" n={scan.diff.counts.new_subdomains} />
                      <DeltaChip label="hosts" n={scan.diff.counts.new_hosts} />
                      <DeltaChip label="APIs" n={scan.diff.counts.new_apis} />
                      <DeltaChip label="libraries" n={scan.diff.counts.new_libraries} />
                    </div>
                  </div>
                  <div className="grid lg:grid-cols-2 gap-4">
                    <DiffList title="New subdomains" testid="bb-diff-subs" items={scan.diff.new_subdomains} />
                    <DiffList title="New live hosts" testid="bb-diff-hosts" items={scan.diff.new_hosts} />
                    <DiffList title="New API endpoints" testid="bb-diff-apis" items={scan.diff.new_apis} />
                    <DiffList title="New / changed libraries" testid="bb-diff-libs" items={scan.diff.new_libraries} />
                  </div>
                  {(scan.diff.removed_subdomains || []).length > 0 && (
                    <DiffList title="Removed subdomains (gone since baseline)" testid="bb-diff-removed" items={scan.diff.removed_subdomains} tone="muted" />
                  )}
                </>
              )}
            </div>
          )}
        </>
      )}

      {!scan && (
        <div className="border border-dashed border-border p-12 text-center text-zinc-600" data-testid="bb-empty">
          <Zap className="w-8 h-8 mx-auto mb-3 text-zinc-700" />
          Enter a target, confirm scope, and launch recon to build the full attack surface.
        </div>
      )}
    </div>
  );
}
