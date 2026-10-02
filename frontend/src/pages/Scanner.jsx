import { useEffect, useState, useCallback, useRef } from "react";
import { api, formatApiError } from "@/lib/api";
import { safeHttpUrl } from "@/lib/safeUrl";
import { SeverityBadge } from "@/components/SeverityBadge";
import { toast } from "sonner";
import { Monitors } from "@/components/Monitors";
import { ScanCompare } from "@/components/ScanDiff";
import { ClearModuleButton } from "@/components/ClearHistoryControls";
import {
  Radar, Play, Loader2, Trash2, FileDown, Server, Lock, ShieldAlert,
  FolderSearch, Network, CheckCircle2, XCircle, Cpu, KeyRound, GitBranch,
  Bug, Globe, Camera, Boxes, Link2, FileWarning, Share2, Cookie, Terminal,
  ShieldCheck, ScanFace, Braces, Crosshair, FileSearch, Layers,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm focus:outline-none focus:border-primary transition-colors";
const POSTURE_COLOR = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#71717A" };
const GRADE_COLOR = { A: "#22C55E", B: "#84CC16", C: "#FACC15", D: "#F59E0B", E: "#F97316", F: "#EF4444" };

const CHECKS = [
  { key: "scan_ports", label: "Port Scan", icon: Network },
  { key: "scan_ssl", label: "SSL/TLS", icon: Lock },
  { key: "scan_headers", label: "Headers", icon: Server },
  { key: "scan_endpoints", label: "Endpoints", icon: FolderSearch },
  { key: "scan_tech", label: "Tech/CMS", icon: Cpu },
  { key: "scan_secrets", label: "Secrets/JS", icon: KeyRound },
  { key: "scan_config", label: "Config Files", icon: FileWarning },
  { key: "scan_subdomains", label: "Subdomains", icon: GitBranch },
  { key: "scan_takeover", label: "Takeover", icon: Crosshair },
  { key: "scan_webvulns", label: "Web Vulns", icon: Bug },
  { key: "scan_deepvulns", label: "Deep Vulns", icon: ScanFace },
  { key: "scan_api", label: "API Test", icon: Boxes },
  { key: "scan_graphql", label: "GraphQL", icon: Braces },
  { key: "scan_cors", label: "CORS", icon: Share2 },
  { key: "scan_cookies", label: "Cookies", icon: Cookie },
  { key: "scan_methods", label: "HTTP Methods", icon: Terminal },
  { key: "scan_csp", label: "CSP Audit", icon: ShieldCheck },
  { key: "scan_waf", label: "WAF Detect", icon: ShieldAlert },
  { key: "scan_network", label: "Network/DNS", icon: Globe },
  { key: "scan_dns_ext", label: "DNS+ (DKIM/CAA)", icon: Globe },
  { key: "scan_wellknown", label: "Well-Known", icon: FileSearch },
  { key: "scan_templates", label: "Template Engine", icon: Layers },
  { key: "scan_content", label: "Content Discovery", icon: FileSearch },
  { key: "capture_screenshot", label: "Screenshot", icon: Camera },
];

function Section({ icon: Icon, title, children, testId }) {
  return (
    <div className="bg-[#121212] border border-border" data-testid={testId}>
      <div className="flex items-center gap-2 px-5 py-3 border-b border-border">
        <Icon className="w-4 h-4 text-primary" />
        <h3 className="font-heading text-sm font-semibold text-white">{title}</h3>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

export default function Scanner() {
  const [target, setTarget] = useState("");
  const [opts, setOpts] = useState({
    scan_ports: true, scan_ssl: true, scan_headers: true, scan_endpoints: true,
    scan_tech: true, scan_secrets: true, scan_subdomains: true, scan_webvulns: true,
    scan_api: true, scan_network: true, capture_screenshot: true,
    scan_config: true, scan_takeover: true, scan_deepvulns: true, scan_graphql: true,
    scan_cors: true, scan_cookies: true, scan_methods: true, scan_csp: true,
    scan_waf: true, scan_dns_ext: true, scan_wellknown: true, scan_templates: true,
    scan_content: true,
  });
  const [scanning, setScanning] = useState(false);
  const [active, setActive] = useState(null);
  const [history, setHistory] = useState([]);
  const pollRef = useRef(null);

  const load = useCallback(async () => {
    const { data } = await api.get("/scanner/scans");
    setHistory(data);
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => () => { if (pollRef.current) clearTimeout(pollRef.current); }, []);

  const run = async (e) => {
    e.preventDefault();
    if (!target.trim()) { toast.error("Enter a target host or URL"); return; }
    setScanning(true);
    setActive(null);
    try {
      const { data } = await api.post("/scanner/scan", { target: target.trim(), ...opts });
      const id = data.id;
      load();
      const started = Date.now();
      const poll = async () => {
        try {
          const { data: d } = await api.get(`/scanner/scans/${id}`);
          if (d.status === "completed") {
            setActive(d); setScanning(false);
            toast.success(`Scan complete — ${d.finding_count} findings`, { description: d.executive_summary?.slice(0, 90) });
            load(); return;
          }
          if (d.status === "failed") {
            setScanning(false); toast.error(d.error || "Scan failed"); load(); return;
          }
          if (Date.now() - started > 300000) { setScanning(false); toast.error("Scan timed out"); return; }
          pollRef.current = setTimeout(poll, 2500);
        } catch {
          pollRef.current = setTimeout(poll, 3500);
        }
      };
      pollRef.current = setTimeout(poll, 2500);
    } catch (err) {
      setScanning(false);
      toast.error(formatApiError(err.response?.data?.detail) || "Scan failed");
    }
  };

  const open = async (id) => {
    const { data } = await api.get(`/scanner/scans/${id}`);
    setActive(data);
  };

  const remove = async (id, e) => {
    e.stopPropagation();
    await api.delete(`/scanner/scans/${id}`);
    if (active?.id === id) setActive(null);
    load();
    toast.success("Scan deleted");
  };

  const ssl = active?.ssl || {};
  const headers = active?.headers?.security_headers || {};

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="scanner-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0">
          <Radar className="w-6 h-6 text-primary" />
        </div>
        <div>
          <p className="data-label mb-1">/ Active Reconnaissance</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">Attack Surface Scanner</h1>
          <p className="text-sm text-zinc-500 mt-1">Live port scan · SSL/TLS analysis · header audit · endpoint enumeration · CVSS scoring · PDF report</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Controls + history */}
        <div className="space-y-6">
          <form onSubmit={run} className="bg-[#121212] border border-border p-6 space-y-4" data-testid="scanner-form">
            <div>
              <label className="data-label block mb-1.5">Target (host or URL)</label>
              <input className={inputCls} value={target} onChange={(e) => setTarget(e.target.value)} data-testid="scanner-target" placeholder="example.com or https://app.target.com" />
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="data-label">Checks <span className="text-zinc-600">({CHECKS.filter((c) => opts[c.key]).length}/{CHECKS.length})</span></label>
                <div className="flex gap-1.5">
                  <button type="button" data-testid="checks-all" onClick={() => setOpts(Object.fromEntries(CHECKS.map((c) => [c.key, true])))}
                    className="text-[10px] font-mono uppercase tracking-wider border border-zinc-800 px-2 py-0.5 text-zinc-400 hover:border-primary/50 hover:text-primary transition-colors">All</button>
                  <button type="button" data-testid="checks-none" onClick={() => setOpts(Object.fromEntries(CHECKS.map((c) => [c.key, false])))}
                    className="text-[10px] font-mono uppercase tracking-wider border border-zinc-800 px-2 py-0.5 text-zinc-400 hover:border-severity-high/50 hover:text-severity-high transition-colors">None</button>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 max-h-72 overflow-y-auto pr-1">
                {CHECKS.map(({ key, label, icon: Icon }) => (
                  <button type="button" key={key} onClick={() => setOpts((o) => ({ ...o, [key]: !o[key] }))} data-testid={`toggle-${key}`}
                    className={`flex items-center gap-2 px-3 py-2 text-xs border transition-colors ${opts[key] ? "border-primary/50 bg-primary/10 text-white" : "border-zinc-800 text-zinc-500"}`}>
                    <Icon className="w-3.5 h-3.5 shrink-0" /> <span className="truncate">{label}</span>
                  </button>
                ))}
              </div>
            </div>
            <button type="submit" disabled={scanning} data-testid="run-scanner" className="w-full bg-primary text-black font-semibold py-3 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60">
              {scanning ? <><Loader2 className="w-4 h-4 animate-spin" /> Scanning target…</> : <><Play className="w-4 h-4" /> Launch Scan</>}
            </button>
            <p className="text-[11px] text-zinc-600 font-mono">Authorized targets only. Scans run live from the InsafeLabs engine.</p>
          </form>

          <div className="bg-[#121212] border border-border">
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <p className="data-label">Scan History</p>
              <div className="flex items-center gap-2">
                {history.length > 0 && <ClearModuleButton module="scanner" onCleared={load} testId="scanner-clear" />}
                <ScanCompare history={history} />
              </div>
            </div>
            {history.length === 0 ? (
              <p className="p-6 text-sm text-zinc-500 text-center">No scans yet</p>
            ) : (
              <div className="divide-y divide-border max-h-72 overflow-y-auto">
                {history.map((h) => (
                  <button key={h.id} onClick={() => open(h.id)} data-testid={`scan-hist-${h.id}`}
                    className={`w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-white/[0.02] transition-colors group ${active?.id === h.id ? "bg-primary/5 border-l-2 border-primary" : "border-l-2 border-transparent"}`}>
                    {h.status === "running" ? <Loader2 className="w-4 h-4 text-primary animate-spin shrink-0" />
                      : h.status === "failed" ? <XCircle className="w-4 h-4 text-severity-critical shrink-0" />
                      : <SeverityBadge severity={h.posture} />}
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-white truncate">{h.host}</p>
                      <p className="font-mono text-[10px] text-zinc-600">
                        {h.status === "running" ? "scanning…" : h.status === "failed" ? "failed" : `${h.finding_count} findings · risk ${h.risk_score}`}
                      </p>
                    </div>
                    <Trash2 onClick={(e) => remove(h.id, e)} className="w-3.5 h-3.5 text-zinc-600 hover:text-severity-critical opacity-0 group-hover:opacity-100" />
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Results */}
        <div className="lg:col-span-2">
          {!active ? (
            <div className="bg-[#121212] border border-border p-16 text-center text-zinc-500 h-full flex flex-col items-center justify-center" data-testid="scanner-empty">
              <Radar className="w-12 h-12 mb-4 opacity-40" />
              <p className="max-w-xs">Launch a scan to map open ports, TLS posture, security headers, exposed endpoints and CVSS-scored vulnerabilities.</p>
            </div>
          ) : active.status === "running" ? (
            <div className="bg-[#121212] border border-border p-16 text-center h-full flex flex-col items-center justify-center" data-testid="scanner-running">
              <div className="relative mb-6">
                <Radar className="w-14 h-14 text-primary animate-spin" style={{ animationDuration: "3s" }} />
              </div>
              <p className="font-heading text-lg text-white">Scanning {active.host}…</p>
              <p className="text-sm text-zinc-500 mt-2 max-w-xs">Running active reconnaissance across all selected modules. Results stream in live — this can take up to a few minutes on large targets.</p>
              <div className="flex items-center gap-2 mt-4 font-mono text-xs text-primary"><Loader2 className="w-3.5 h-3.5 animate-spin" /> live engine working</div>
            </div>
          ) : (
            <div className="space-y-5" data-testid="scanner-results">
              {/* Header / risk */}
              <div className="bg-[#121212] border border-border p-6">
                <div className="flex items-center justify-between flex-wrap gap-3">
                  <div className="flex items-center gap-4">
                    <div>
                      <p className="font-mono text-4xl font-bold" style={{ color: POSTURE_COLOR[active.posture] }}>{active.risk_score}</p>
                      <p className="data-label">Risk / 100</p>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-1"><span className="data-label">Posture</span><SeverityBadge severity={active.posture} /></div>
                      <p className="font-mono text-sm text-white">{active.host}</p>
                      <p className="font-mono text-[11px] text-zinc-500">{active.ref}</p>
                    </div>
                  </div>
                  <button data-testid="download-report"
                    onClick={async () => {
                      try {
                        const { data } = await api.get(`/scanner/scans/${active.id}/report`, { responseType: "blob", timeout: 60000 });
                        const url = URL.createObjectURL(data);
                        const a = document.createElement("a");
                        a.href = url; a.download = `insafelabs-scan-${active.host || active.id}.pdf`; a.click();
                        URL.revokeObjectURL(url);
                      } catch { toast.error("Report download failed"); }
                    }}
                    className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center gap-2 hover:bg-yellow-500 transition-colors text-sm">
                    <FileDown className="w-4 h-4" /> PDF Report
                  </button>
                </div>
                {active.executive_summary && <p className="text-sm text-zinc-300 leading-relaxed border-t border-border pt-4 mt-4">{active.executive_summary}</p>}
                <div className="grid grid-cols-5 gap-px bg-border border border-border mt-4">
                  {["critical", "high", "medium", "low", "info"].map((s) => (
                    <div key={s} className="bg-[#0a0a0a] p-2 text-center">
                      <p className="font-mono text-lg font-bold" style={{ color: POSTURE_COLOR[s] }}>{active.severity_counts?.[s] || 0}</p>
                      <p className="data-label text-[9px]">{s}</p>
                    </div>
                  ))}
                </div>
              </div>

              {active.scorecard ? (
                <div className="bg-[#121212] border border-border p-6" data-testid="sec-scorecard">
                  <div className="flex items-center gap-4 flex-wrap">
                    <div className="w-20 h-20 border-2 flex items-center justify-center shrink-0" style={{ borderColor: GRADE_COLOR[active.scorecard.overall_grade] }}>
                      <span className="font-heading text-4xl font-bold" style={{ color: GRADE_COLOR[active.scorecard.overall_grade] }}>{active.scorecard.overall_grade}</span>
                    </div>
                    <div>
                      <p className="data-label">Security Scorecard</p>
                      <h3 className="font-heading text-lg font-semibold">Grade {active.scorecard.overall_grade} · {active.scorecard.overall_score}/100</h3>
                      <p className="text-xs text-zinc-500">Synthesized across TLS, headers, email, cookies, CORS & exposure.</p>
                    </div>
                  </div>
                  <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2 mt-4">
                    {active.scorecard.categories.map((c, i) => (
                      <div key={i} className="flex items-center justify-between border border-border bg-[#0a0a0a] px-3 py-2" data-testid={`scorecard-cat-${i}`}>
                        <span className="text-xs text-zinc-300">{c.category}</span>
                        <span className="font-mono text-sm font-bold" style={{ color: GRADE_COLOR[c.grade] }}>{c.grade} · {c.score}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              <div className="grid md:grid-cols-2 gap-5">
                <Section icon={Network} title="Open Ports" testId="sec-ports">
                  {active.ports?.length ? (
                    <div className="space-y-1.5">
                      {active.ports.map((p) => (
                        <div key={p.port} className="flex items-center justify-between font-mono text-xs border-b border-border/50 pb-1">
                          <span className="text-white">{p.port}</span>
                          <span className="text-zinc-400">{p.service}</span>
                          <span className="text-emerald-400">OPEN</span>
                        </div>
                      ))}
                    </div>
                  ) : <p className="text-sm text-zinc-500">No common ports open.</p>}
                </Section>

                <Section icon={Lock} title="SSL / TLS" testId="sec-ssl">
                  {ssl.tls_version ? (
                    <div className="space-y-1.5 font-mono text-xs">
                      <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Protocol</span><span className="text-white">{ssl.tls_version}</span></div>
                      <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Cipher</span><span className="text-white truncate max-w-[55%]">{ssl.cipher}</span></div>
                      <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Valid</span><span className={ssl.valid ? "text-emerald-400" : "text-severity-critical"}>{String(ssl.valid)}</span></div>
                      <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Expires in</span><span className={ssl.days_to_expiry != null && ssl.days_to_expiry < 15 ? "text-severity-high" : "text-white"}>{ssl.days_to_expiry ?? "—"} d</span></div>
                      <div className="flex justify-between"><span className="text-zinc-500">Issuer</span><span className="text-white truncate max-w-[55%]">{(ssl.issuer || {}).organizationName || "—"}</span></div>
                    </div>
                  ) : <p className="text-sm text-zinc-500">No TLS on target (HTTPS not detected).</p>}
                </Section>
              </div>

              <Section icon={Server} title="HTTP Security Headers" testId="sec-headers">
                {Object.keys(headers).length ? (
                  <div className="grid sm:grid-cols-2 gap-x-6 gap-y-1.5">
                    {Object.entries(headers).map(([k, v]) => (
                      <div key={k} className="flex items-center justify-between gap-2 text-xs border-b border-border/50 pb-1">
                        <span className="font-mono text-zinc-400 truncate">{k}</span>
                        {v ? <span className="inline-flex items-center gap-1 text-emerald-400"><CheckCircle2 className="w-3 h-3" /> set</span>
                           : <span className="inline-flex items-center gap-1 text-severity-high"><XCircle className="w-3 h-3" /> missing</span>}
                      </div>
                    ))}
                  </div>
                ) : <p className="text-sm text-zinc-500">Headers not collected.</p>}
              </Section>

              <Section icon={FolderSearch} title="Discovered Endpoints" testId="sec-endpoints">
                {active.endpoints?.length ? (
                  <div className="flex flex-wrap gap-2">
                    {active.endpoints.map((e, i) => (
                      <span key={i} className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2 py-1 text-zinc-300">
                        {e.path} <span className="text-zinc-600">[{e.status}]</span>
                      </span>
                    ))}
                  </div>
                ) : <p className="text-sm text-zinc-500">No sensitive endpoints discovered.</p>}
              </Section>

              <Section icon={ShieldAlert} title={`Vulnerabilities (${active.finding_count})`} testId="sec-findings">
                {active.findings?.length ? (
                  <div className="space-y-4">
                    {active.findings.map((f, i) => (
                      <div key={i} className="border border-border bg-[#0a0a0a] p-4" data-testid={`scan-finding-${i}`}>
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-white text-sm font-medium">{f.title}</span></div>
                          <span className="font-mono text-xs text-zinc-400">CVSS {f.cvss}</span>
                        </div>
                        {f.category && <p className="font-mono text-[11px] text-zinc-500 mt-1.5">{f.category}</p>}
                        {f.evidence && <p className="text-xs text-zinc-400 mt-2 font-mono leading-relaxed">{f.evidence}</p>}
                        {f.recommendation && <p className="text-sm text-zinc-300 mt-2 border-l-2 border-emerald-500/40 pl-3">{f.recommendation}</p>}
                        {f.proof && (
                          <div className="mt-3" data-testid={`finding-proof-${i}`}>
                            <p className="data-label mb-1 flex items-center gap-1.5"><Camera className="w-3 h-3 text-primary" /> Visual proof</p>
                            <img src={f.proof} alt="finding proof" loading="lazy" className="w-full max-w-md border border-border bg-black" />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : <p className="text-sm text-emerald-400/80">No issues identified.</p>}
              </Section>

              {active.screenshot && (
                <Section icon={Camera} title="Visual Proof — Screenshot" testId="sec-screenshot">
                  <img src={active.screenshot} alt="target screenshot" data-testid="scan-screenshot" loading="lazy"
                    className="w-full border border-border bg-black" />
                  <p className="data-label mt-2">Live rendered snapshot of {active.host}</p>
                </Section>
              )}

              {active.tech?.stack?.length ? (
                <Section icon={Cpu} title="Technology Fingerprint" testId="sec-tech">
                  <div className="flex flex-wrap gap-2">
                    {active.tech.stack.map((t, i) => (
                      <span key={i} className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2 py-1 text-zinc-300">{t}</span>
                    ))}
                  </div>
                  {active.cms?.cms && <p className="text-xs text-zinc-400 mt-3">CMS: <span className="text-primary">{active.cms.cms} {active.cms.wp_version || ""}</span></p>}
                </Section>
              ) : null}

              {active.subdomains?.subdomains?.length ? (
                <Section icon={GitBranch} title={`Subdomains (${active.subdomains.total})`} testId="sec-subdomains">
                  <div className="flex flex-wrap gap-2 max-h-52 overflow-y-auto">
                    {active.subdomains.subdomains.map((s, i) => {
                      const hot = active.subdomains.interesting?.includes(s);
                      return <span key={i} className={`font-mono text-[11px] border px-2 py-1 ${hot ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : "border-border bg-[#0a0a0a] text-zinc-300"}`}>{s}</span>;
                    })}
                  </div>
                </Section>
              ) : null}

              {active.secrets?.secrets?.length ? (
                <Section icon={KeyRound} title={`Exposed Secrets (${active.secrets.secrets.length})`} testId="sec-secrets">
                  <div className="space-y-2">
                    {active.secrets.secrets.map((s, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 border-b border-border/50 pb-1.5" data-testid={`secret-${i}`}>
                        <span className="text-sm text-white">{s.type}</span>
                        <span className="font-mono text-[11px] text-zinc-500">{s.source}</span>
                        <span className="font-mono text-[11px] text-severity-critical">{s.match}</span>
                      </div>
                    ))}
                  </div>
                </Section>
              ) : null}

              {active.secrets?.endpoints?.length ? (
                <Section icon={Link2} title="Discovered API Endpoints (from JS)" testId="sec-jsendpoints">
                  <div className="flex flex-wrap gap-2 max-h-40 overflow-y-auto">
                    {active.secrets.endpoints.map((e, i) => (
                      <span key={i} className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2 py-1 text-zinc-400">{e}</span>
                    ))}
                  </div>
                </Section>
              ) : null}

              {active.webvulns && Object.keys(active.webvulns).length ? (
                <Section icon={Bug} title="Web Vulnerability Probes" testId="sec-webvulns">
                  <div className="grid sm:grid-cols-3 gap-3 font-mono text-xs">
                    {[["SQL Injection", "sqli"], ["Reflected XSS", "xss"], ["Open Redirect", "open_redirect"]].map(([label, k]) => (
                      <div key={k} className="border border-border bg-[#0a0a0a] p-3">
                        <p className="data-label">{label}</p>
                        <p className="text-white mt-1">{active.webvulns[k] || "—"}</p>
                      </div>
                    ))}
                  </div>
                </Section>
              ) : null}

              {active.api && (active.api.open_endpoints?.length || active.api.rate_limiting) ? (
                <Section icon={Boxes} title="API Security" testId="sec-api">
                  <p className="text-xs text-zinc-400">Rate limiting: <span className="text-white font-mono">{active.api.rate_limiting}</span></p>
                  {active.api.open_endpoints?.length ? (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {active.api.open_endpoints.map((e, i) => (
                        <span key={i} className="font-mono text-[11px] border border-severity-medium/40 bg-severity-medium/10 text-severity-medium px-2 py-1">{e.path} [{e.status}]</span>
                      ))}
                    </div>
                  ) : <p className="text-xs text-zinc-500 mt-1">No unauthenticated JSON endpoints found.</p>}
                </Section>
              ) : null}

              {active.network?.records && Object.keys(active.network.records).length ? (
                <Section icon={Globe} title="Network Reconnaissance" testId="sec-network">
                  <div className="space-y-1.5 font-mono text-xs">
                    {Object.entries(active.network.records).map(([rt, vals]) => (
                      <div key={rt} className="flex gap-2 border-b border-border/50 pb-1"><span className="text-zinc-500 w-14 shrink-0">{rt}</span><span className="text-zinc-300 break-all">{vals.join(", ")}</span></div>
                    ))}
                    <div className="flex gap-2 border-b border-border/50 pb-1"><span className="text-zinc-500 w-14 shrink-0">SPF</span><span className={active.network.spf ? "text-emerald-400 break-all" : "text-severity-high"}>{active.network.spf || "MISSING"}</span></div>
                    <div className="flex gap-2 border-b border-border/50 pb-1"><span className="text-zinc-500 w-14 shrink-0">DMARC</span><span className={active.network.dmarc ? "text-emerald-400" : "text-severity-high"}>{active.network.dmarc ? `present (p=${active.network.dmarc_policy || "?"})` : "MISSING"}</span></div>
                    <div className="flex gap-2 border-b border-border/50 pb-1"><span className="text-zinc-500 w-14 shrink-0">DKIM</span><span className={(active.network.dkim || []).length ? "text-emerald-400 break-all" : "text-severity-high"}>{(active.network.dkim || []).length ? active.network.dkim.join(", ") : "none found"}</span></div>
                    <div className="flex gap-2"><span className="text-zinc-500 w-14 shrink-0">Spoof</span><span className={active.network.email_spoofable ? "text-severity-critical font-bold" : "text-emerald-400"}>{active.network.email_spoofable ? "SPOOFABLE" : "protected"}</span></div>
                  </div>
                  {active.network.whois?.registrar && <p className="text-[11px] text-zinc-500 mt-3 font-mono">Registrar: {active.network.whois.registrar} · Expires: {active.network.whois.expires}</p>}
                </Section>
              ) : null}

              {active.content?.content_hits?.length ? (
                <Section icon={FileSearch} title={`Content Discovery (${active.content.content_hits.length} hits / ${active.content.probed} probed)`} testId="sec-content">
                  <div className="space-y-1 max-h-72 overflow-y-auto font-mono text-xs">
                    {active.content.content_hits.map((h, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 border-b border-border/40 pb-1" data-testid={`content-hit-${i}`}>
                        <span className={h.status === 200 ? "text-severity-high break-all" : "text-zinc-400 break-all"}>{h.path}</span>
                        <span className="text-zinc-600 shrink-0">{h.status}{h.length ? ` · ${h.length}b` : ""}</span>
                      </div>
                    ))}
                  </div>
                </Section>
              ) : null}

              {active.config?.config_hits?.length ? (
                <Section icon={FileWarning} title={`Exposed Config / Secret Files (${active.config.config_hits.length})`} testId="sec-config">
                  <div className="space-y-2">
                    {active.config.config_hits.map((c, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 border-b border-border/50 pb-1.5" data-testid={`config-hit-${i}`}>
                        <a href={safeHttpUrl(c.url)} target="_blank" rel="noreferrer" className="font-mono text-xs text-severity-critical hover:underline truncate">{c.path}</a>
                        <span className="font-mono text-[10px] text-zinc-500 shrink-0">{c.content_type} · {c.size}b</span>
                      </div>
                    ))}
                  </div>
                  {active.config.config_secrets?.length ? (
                    <div className="mt-4 pt-3 border-t border-border">
                      <p className="data-label mb-2">Credentials found inside files</p>
                      {active.config.config_secrets.map((s, i) => (
                        <div key={i} className="flex items-center justify-between gap-2 text-xs pb-1" data-testid={`config-secret-${i}`}>
                          <span className="text-white">{s.type}</span>
                          <span className="font-mono text-[10px] text-zinc-500">{s.source}</span>
                          <span className="font-mono text-[10px] text-severity-critical">{s.match}</span>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  <p className="text-[10px] text-zinc-600 font-mono mt-3">{active.config.probed} paths probed</p>
                </Section>
              ) : null}

              {active.takeover?.vulnerable?.length ? (
                <Section icon={Crosshair} title={`Subdomain Takeover (${active.takeover.vulnerable.length})`} testId="sec-takeover">
                  <div className="space-y-2">
                    {active.takeover.vulnerable.map((t, i) => (
                      <div key={i} className="border border-severity-critical/30 bg-severity-critical/5 p-3" data-testid={`takeover-${i}`}>
                        <p className="font-mono text-xs text-severity-critical">{t.subdomain}</p>
                        <p className="font-mono text-[10px] text-zinc-500 mt-0.5">→ {t.cname} <span className="text-severity-high">[{t.service}]</span></p>
                      </div>
                    ))}
                  </div>
                </Section>
              ) : null}

              {active.templates?.matched?.length ? (
                <Section icon={Layers} title={`Template Engine Matches (${active.templates.match_count}/${active.templates.total_templates})`} testId="sec-templates">
                  <div className="space-y-2">
                    {active.templates.matched.map((m, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 border border-border bg-[#0a0a0a] p-3" data-testid={`template-${i}`}>
                        <div className="flex items-center gap-2 min-w-0">
                          <SeverityBadge severity={m.severity} />
                          <span className="text-sm text-white truncate">{m.name}</span>
                          {m.cve && <span className="font-mono text-[10px] border border-severity-high/40 text-severity-high px-1.5 py-0.5 shrink-0">{m.cve}</span>}
                        </div>
                        <a href={safeHttpUrl(m.url)} target="_blank" rel="noreferrer" className="font-mono text-[10px] text-zinc-500 hover:text-primary truncate max-w-[42%] shrink-0">{m.url}</a>
                      </div>
                    ))}
                  </div>
                </Section>
              ) : active.templates?.total_templates ? (
                <Section icon={Layers} title={`Template Engine (${active.templates.total_templates} signatures)`} testId="sec-templates">
                  <p className="text-sm text-emerald-400/80">No template signatures matched — no known exposed panels, dev tools or CVE paths detected.</p>
                </Section>
              ) : null}

              {active.deepvulns && Object.keys(active.deepvulns).length ? (
                <Section icon={ScanFace} title="Deep Vulnerability Probes" testId="sec-deepvulns">
                  <div className="grid sm:grid-cols-2 gap-3 font-mono text-xs">
                    {[["Path Traversal / LFI", "path_traversal"], ["Template Injection (SSTI)", "ssti"],
                      ["CRLF Injection", "crlf"], ["Command Injection", "cmd_injection"], ["Host Header Injection", "host_header"]].map(([label, k]) => (
                      <div key={k} className="border border-border bg-[#0a0a0a] p-3">
                        <p className="data-label">{label}</p>
                        <p className={`mt-1 ${active.deepvulns[k] && !["not detected", "probe failed"].includes(active.deepvulns[k]) ? "text-severity-critical" : "text-zinc-400"}`}>{active.deepvulns[k] || "—"}</p>
                      </div>
                    ))}
                  </div>
                </Section>
              ) : null}

              {active.graphql?.endpoints?.length ? (
                <Section icon={Braces} title="GraphQL Introspection" testId="sec-graphql">
                  <div className="flex flex-wrap gap-2">
                    {active.graphql.endpoints.map((e, i) => (
                      <span key={i} className="font-mono text-[11px] border border-severity-medium/40 bg-severity-medium/10 text-severity-medium px-2 py-1">{e.path} · introspection ON</span>
                    ))}
                  </div>
                </Section>
              ) : null}

              {active.cors && Object.keys(active.cors).length ? (
                <Section icon={Share2} title="CORS Policy" testId="sec-cors">
                  <div className="space-y-1.5 font-mono text-xs">
                    <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Allow-Origin</span><span className="text-white truncate max-w-[60%]">{active.cors.acao || "none"}</span></div>
                    <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Allow-Credentials</span><span className={active.cors.acac ? "text-severity-high" : "text-emerald-400"}>{String(!!active.cors.acac)}</span></div>
                    <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Reflects Origin</span><span className={active.cors.reflects_origin ? "text-severity-critical" : "text-emerald-400"}>{String(!!active.cors.reflects_origin)}</span></div>
                    <div className="flex justify-between"><span className="text-zinc-500">Allows null</span><span className={active.cors.allows_null ? "text-severity-high" : "text-emerald-400"}>{String(!!active.cors.allows_null)}</span></div>
                  </div>
                </Section>
              ) : null}

              {active.cookies_audit?.cookies?.length ? (
                <Section icon={Cookie} title={`Cookie Security (${active.cookies_audit.cookies.length})`} testId="sec-cookies">
                  <div className="space-y-2">
                    {active.cookies_audit.cookies.map((c, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 border-b border-border/50 pb-1.5 font-mono text-xs" data-testid={`cookie-${i}`}>
                        <span className="text-white truncate">{c.name}</span>
                        <div className="flex gap-1.5 shrink-0">
                          <span className={`px-1.5 py-0.5 border text-[9px] ${c.httponly ? "border-emerald-500/40 text-emerald-400" : "border-severity-high/40 text-severity-high"}`}>HttpOnly</span>
                          <span className={`px-1.5 py-0.5 border text-[9px] ${c.secure ? "border-emerald-500/40 text-emerald-400" : "border-severity-high/40 text-severity-high"}`}>Secure</span>
                          <span className={`px-1.5 py-0.5 border text-[9px] ${c.samesite && String(c.samesite).toLowerCase() !== "none" ? "border-emerald-500/40 text-emerald-400" : "border-severity-high/40 text-severity-high"}`}>SameSite:{c.samesite || "—"}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Section>
              ) : null}

              {active.methods && (active.methods.allowed?.length || active.methods.trace) ? (
                <Section icon={Terminal} title="HTTP Methods" testId="sec-methods">
                  <div className="flex flex-wrap gap-2">
                    {(active.methods.allowed || []).map((m, i) => (
                      <span key={i} className={`font-mono text-[11px] border px-2 py-1 ${active.methods.dangerous?.includes(m) ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : "border-border bg-[#0a0a0a] text-zinc-300"}`}>{m}</span>
                    ))}
                    {active.methods.trace && <span className="font-mono text-[11px] border border-severity-high/40 bg-severity-high/10 text-severity-high px-2 py-1">TRACE ENABLED</span>}
                    {!active.methods.allowed?.length && !active.methods.trace && <span className="text-sm text-zinc-500">Server did not advertise methods.</span>}
                  </div>
                </Section>
              ) : null}

              {active.csp && active.csp.present !== undefined ? (
                <Section icon={ShieldCheck} title="Content-Security-Policy" testId="sec-csp">
                  {active.csp.present ? (
                    <>
                      <p className="font-mono text-[11px] text-zinc-400 break-all border border-border bg-[#0a0a0a] p-2">{active.csp.policy}</p>
                      {active.csp.issues?.length ? (
                        <ul className="mt-3 space-y-1">
                          {active.csp.issues.map((iss, i) => (
                            <li key={i} className="text-xs text-severity-high flex items-center gap-1.5"><XCircle className="w-3 h-3" /> {iss}</li>
                          ))}
                        </ul>
                      ) : <p className="text-xs text-emerald-400 mt-2">No obvious CSP weaknesses.</p>}
                    </>
                  ) : <p className="text-sm text-severity-high">No Content-Security-Policy header set.</p>}
                </Section>
              ) : null}

              {active.waf && Object.keys(active.waf).length ? (
                <Section icon={ShieldAlert} title="WAF / CDN Detection" testId="sec-waf">
                  {active.waf.detected ? (
                    <p className="text-sm text-white">Detected: <span className="text-primary font-mono">{active.waf.vendor}</span> <span className="text-[11px] text-zinc-500">({active.waf.evidence})</span></p>
                  ) : <p className="text-sm text-zinc-400">No WAF/CDN signature detected — origin may be directly exposed.</p>}
                </Section>
              ) : null}

              {active.dns_ext && Object.keys(active.dns_ext).length ? (
                <Section icon={Globe} title="Extended DNS / Email Security" testId="sec-dnsext">
                  <div className="space-y-1.5 font-mono text-xs">
                    <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">CAA</span><span className={active.dns_ext.caa?.length ? "text-emerald-400" : "text-severity-medium"}>{active.dns_ext.caa?.length ? "present" : "MISSING"}</span></div>
                    <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">DNSSEC</span><span className={active.dns_ext.dnssec ? "text-emerald-400" : "text-severity-medium"}>{active.dns_ext.dnssec ? "enabled" : "OFF"}</span></div>
                    <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">DKIM</span><span className={active.dns_ext.dkim?.length ? "text-emerald-400" : "text-severity-medium"}>{active.dns_ext.dkim?.length ? active.dns_ext.dkim.join(", ") : "none found"}</span></div>
                    <div className="flex justify-between"><span className="text-zinc-500">Zone Transfer (AXFR)</span><span className={active.dns_ext.zone_transfer ? "text-severity-critical" : "text-emerald-400"}>{active.dns_ext.zone_transfer ? `OPEN (${active.dns_ext.axfr_ns})` : "refused"}</span></div>
                  </div>
                </Section>
              ) : null}

              {active.wellknown && Object.keys(active.wellknown).length ? (
                <Section icon={FileSearch} title="Well-Known Files" testId="sec-wellknown">
                  <div className="flex flex-wrap gap-2">
                    {[["robots.txt", active.wellknown.robots], ["sitemap.xml", active.wellknown.sitemap],
                      ["security.txt", active.wellknown.security_txt], ["humans.txt", active.wellknown.humans]].map(([label, ok]) => (
                      <span key={label} className={`font-mono text-[11px] border px-2 py-1 ${ok ? "border-emerald-500/40 text-emerald-400" : "border-border text-zinc-600"}`}>{label} {ok ? "✓" : "✗"}</span>
                    ))}
                  </div>
                  {active.wellknown.disallowed?.length ? (
                    <div className="mt-3">
                      <p className="data-label mb-1.5">robots.txt Disallow paths</p>
                      <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                        {active.wellknown.disallowed.map((d, i) => (
                          <span key={i} className="font-mono text-[10px] border border-border bg-[#0a0a0a] px-1.5 py-0.5 text-zinc-400">{d}</span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </Section>
              ) : null}

              {active.wordpress && (active.wordpress.users?.length || active.wordpress.plugins?.length || active.wordpress.xmlrpc) ? (
                <Section icon={Cpu} title="WordPress Deep Recon" testId="sec-wordpress">
                  {active.wordpress.users?.length ? (
                    <div className="mb-3">
                      <p className="data-label mb-1.5">Enumerated Users</p>
                      <div className="flex flex-wrap gap-1.5">
                        {active.wordpress.users.map((u, i) => (
                          <span key={i} className="font-mono text-[11px] border border-severity-medium/40 bg-severity-medium/10 text-severity-medium px-2 py-1">{u}</span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {active.wordpress.plugins?.length ? (
                    <div className="mb-3">
                      <p className="data-label mb-1.5">Plugins</p>
                      <div className="flex flex-wrap gap-1.5">
                        {active.wordpress.plugins.map((p, i) => (
                          <span key={i} className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2 py-1 text-zinc-300">{p}</span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  <div className="flex gap-2">
                    <span className={`font-mono text-[11px] border px-2 py-1 ${active.wordpress.xmlrpc ? "border-severity-high/40 text-severity-high" : "border-border text-zinc-600"}`}>XML-RPC {active.wordpress.xmlrpc ? "ON" : "off"}</span>
                    <span className={`font-mono text-[11px] border px-2 py-1 ${active.wordpress.upload_listing ? "border-severity-high/40 text-severity-high" : "border-border text-zinc-600"}`}>Uploads listing {active.wordpress.upload_listing ? "OPEN" : "off"}</span>
                  </div>
                </Section>
              ) : null}
            </div>
          )}
        </div>
      </div>

      <Monitors />
    </div>
  );
}
