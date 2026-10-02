import { useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { toast } from "sonner";
import {
  Users, DoorOpen, Wifi, Binary, Network, Bug, Cloud, Swords, Loader2, Send,
  ShieldAlert, Sparkles, Copy, Upload, Link2, Play, KeyRound, FileWarning,
  CheckCircle2, ListChecks, Crosshair,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm focus:outline-none focus:border-primary transition-colors";
const POSTURE_COLOR = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#71717A" };

const DOMAINS = [
  { id: "Social Engineering", icon: Users, tool: "phishing",
    desc: "Test the human layer — pretexting, spear-phishing and awareness campaigns under signed authorization.",
    attack: ["T1566 Phishing", "T1598 Spearphishing", "T1204 User Execution", "T1656 Impersonation"],
    method: ["Define scope + written authorization and safe-word", "OSINT the org (roles, tone, tooling)", "Craft pretext + simulation email (use the generator below)", "Track click / report rates, never store real creds", "Debrief + targeted awareness training"] },
  { id: "Physical Pentest", icon: DoorOpen,
    desc: "Assess facility security — tailgating, badge cloning, drop devices and restricted-area access.",
    attack: ["T1200 Hardware Additions", "T1091 Removable Media", "T1078 Valid Accounts"],
    method: ["Recon entrances, shifts and choke-points", "Pretext + prop kit (hi-vis, clipboard, fake badge)", "Attempt tailgating / piggybacking", "Test reception & escort policy adherence", "Document with photos, report physical gaps"] },
  { id: "Wireless Security", icon: Wifi,
    desc: "Evaluate Wi-Fi/Bluetooth posture — rogue APs, weak PSKs, captive-portal and BLE exposure.",
    attack: ["T1557 Adversary-in-the-Middle", "T1040 Network Sniffing", "T1200 Hardware Additions"],
    method: ["Survey SSIDs, encryption and client density", "Capture WPA2 handshake, offline crack strength test", "Deploy authorized Evil-Twin to test user behaviour", "Check guest/corporate segmentation", "Assess BLE/IoT device pairing security"] },
  { id: "Reverse Engineering", icon: Binary, tool: "apk",
    desc: "Static-analyse mobile apps for hardcoded secrets, insecure config and exposed backends.",
    attack: ["T1552 Unsecured Credentials", "T1005 Data from Local System", "T1426 Software Discovery"],
    method: ["Pull the APK/IPA build", "Decompile & inspect manifest + permissions", "Scan resources/dex for keys & endpoints (analyzer below)", "Review storage, crypto & network config", "Report insecure data storage & backend exposure"] },
  { id: "Active Directory", icon: Network,
    desc: "Enterprise Windows domain attack paths — enumeration to Domain Admin, under scope.",
    attack: ["T1558 Kerberoasting", "T1550 Pass-the-Hash", "T1003 DCSync", "T1069 Group Discovery"],
    method: ["Enumerate domain (BloodHound / SharpHound)", "Identify Kerberoastable SPNs, request & crack offline", "Map ACL/priv-esc paths to high-value groups", "Test lateral movement (PtH) within scope", "Report tiering, LAPS, and detection gaps"] },
  { id: "Malware Analysis", icon: Bug,
    desc: "Understand a sample's behaviour for detection engineering — static & dynamic triage (analysis, not development).",
    attack: ["T1055 Process Injection", "T1547 Persistence", "T1027 Obfuscated Files"],
    method: ["Hash + reputation lookup (never detonate on prod)", "Static triage: strings, imports, packers", "Detonate in isolated sandbox VM", "Capture IOCs (network, files, registry)", "Author detections (YARA / Sigma) & report"] },
  { id: "Cloud Attacks", icon: Cloud, tool: "cloud",
    desc: "Find cloud misconfigurations — public buckets, weak IAM, exposed metadata and container escape surface.",
    attack: ["T1530 Data from Cloud Storage", "T1078.004 Cloud Accounts", "T1552.005 Cloud Instance Metadata"],
    method: ["Enumerate public buckets & object ACLs (checker below)", "Review IAM roles/policies for over-permission", "Probe SSRF → instance metadata (IMDS) exposure", "Assess container/K8s escape & secrets", "Report least-privilege & public-access blocks"] },
];

/* ---------------- AI ADVISOR (all domains) ---------------- */
function Advisor({ domain }) {
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [answer, setAnswer] = useState("");
  const ask = async (e) => {
    e.preventDefault();
    if (!q.trim()) return;
    setBusy(true); setAnswer("");
    try {
      const { data } = await api.post("/redteam/advisor", { domain, question: q.trim() });
      setAnswer(data.answer);
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Advisor failed"); }
    finally { setBusy(false); }
  };
  return (
    <div className="bg-[#121212] border border-border p-5" data-testid="redteam-advisor">
      <p className="data-label mb-3 flex items-center gap-2"><Sparkles className="w-3.5 h-3.5 text-primary" /> AI Red-Team Advisor</p>
      <form onSubmit={ask} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={q} onChange={(e) => setQ(e.target.value)} data-testid="advisor-input" placeholder={`Ask about ${domain}…`} />
        <button type="submit" disabled={busy} data-testid="advisor-submit" className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 glow-primary">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />} Ask
        </button>
      </form>
      {busy && <p className="data-label mt-3 animate-pulse">Advisor analysing operation paths… (can take ~20s)</p>}
      {answer && <div className="mt-4 text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap border-t border-border pt-4" data-testid="advisor-answer">{answer}</div>}
    </div>
  );
}

/* ---------------- PHISHING SIM ---------------- */
function PhishingTool() {
  const [f, setF] = useState({ scenario: "IT Support password reset", company: "Acme Corp", role: "Finance employee", difficulty: "medium" });
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const gen = async (e) => {
    e.preventDefault(); setBusy(true); setRes(null);
    try { const { data } = await api.post("/redteam/phishing", f); setRes(data); toast.success("Simulation drafted"); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Failed"); }
    finally { setBusy(false); }
  };
  const upd = (k) => (e) => setF((s) => ({ ...s, [k]: e.target.value }));
  return (
    <div className="bg-[#121212] border border-border p-5" data-testid="phishing-tool">
      <p className="data-label mb-3 flex items-center gap-2"><Crosshair className="w-3.5 h-3.5 text-primary" /> Phishing Simulation Generator <span className="ml-2 text-[9px] uppercase tracking-widest text-severity-medium border border-severity-medium/40 px-1.5 py-0.5">authorized awareness only</span></p>
      <form onSubmit={gen} className="grid sm:grid-cols-2 gap-2">
        <input className={inputCls} value={f.scenario} onChange={upd("scenario")} data-testid="phish-scenario" placeholder="Scenario" />
        <input className={inputCls} value={f.company} onChange={upd("company")} data-testid="phish-company" placeholder="Company" />
        <input className={inputCls} value={f.role} onChange={upd("role")} data-testid="phish-role" placeholder="Target role" />
        <select className={inputCls} value={f.difficulty} onChange={upd("difficulty")} data-testid="phish-difficulty">
          {["easy", "medium", "hard"].map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
        <button type="submit" disabled={busy} data-testid="phish-submit" className="sm:col-span-2 bg-primary text-black font-semibold py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Generate Simulation
        </button>
      </form>
      {res && (
        <div className="mt-4 border border-border bg-[#0a0a0a] p-4 space-y-2" data-testid="phish-result">
          <div className="flex items-center justify-between gap-2">
            <p className="text-white text-sm font-medium">{res.subject}</p>
            <button onClick={() => { navigator.clipboard.writeText(res.body_text || ""); toast.success("Copied"); }} className="text-zinc-500 hover:text-primary" data-testid="phish-copy"><Copy className="w-3.5 h-3.5" /></button>
          </div>
          <p className="data-label">From: {res.sender_display}</p>
          <p className="text-sm text-zinc-300 whitespace-pre-wrap border-l-2 border-primary/40 pl-3">{res.body_text}</p>
          {(res.red_flags || []).length > 0 && (
            <div className="pt-2">
              <p className="data-label mb-1 flex items-center gap-1.5"><ShieldAlert className="w-3 h-3 text-severity-high" /> Red flags to teach</p>
              <ul className="list-disc list-inside text-xs text-zinc-400 space-y-0.5">{res.red_flags.map((r, i) => <li key={i}>{r}</li>)}</ul>
            </div>
          )}
          {res.teachable_moment && <p className="text-xs text-emerald-400/80 border-t border-border pt-2">{res.teachable_moment}</p>}
        </div>
      )}
    </div>
  );
}

/* ---------------- CLOUD CHECKER ---------------- */
function CloudTool() {
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault(); if (!target.trim()) return toast.error("Enter a bucket name or URL");
    setBusy(true); setRes(null);
    try { const { data } = await api.post("/redteam/cloud", { target: target.trim() }); setRes(data); toast.success(`${data.finding_count} misconfig(s)`); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Scan failed"); }
    finally { setBusy(false); }
  };
  return (
    <div className="bg-[#121212] border border-border p-5" data-testid="cloud-tool">
      <p className="data-label mb-3 flex items-center gap-2"><Cloud className="w-3.5 h-3.5 text-primary" /> Public Bucket Exposure Checker</p>
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={target} onChange={(e) => setTarget(e.target.value)} data-testid="cloud-input" placeholder="bucket-name or s3 URL (e.g. flaws.cloud)" />
        <button type="submit" disabled={busy} data-testid="cloud-submit" className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Check
        </button>
      </form>
      {res && (
        <div className="mt-4 space-y-3" data-testid="cloud-result">
          {res.checks.map((c, i) => (
            <div key={i} className="flex items-center justify-between gap-2 border border-border bg-[#0a0a0a] px-3 py-2 text-xs" data-testid={`cloud-check-${i}`}>
              <span className="text-white font-mono">{c.provider}</span>
              <span className={`font-mono ${c.state.includes("PUBLIC") ? "text-severity-critical" : c.state.includes("private") ? "text-severity-medium" : "text-zinc-500"}`}>{c.state}</span>
            </div>
          ))}
          {res.findings.map((f, i) => (
            <div key={i} className="border border-border bg-[#0a0a0a] p-3" data-testid={`cloud-finding-${i}`}>
              <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-white text-sm">{f.title}</span><span className="ml-auto font-mono text-xs text-zinc-400">CVSS {f.cvss}</span></div>
              <p className="text-xs text-zinc-400 mt-2 font-mono break-all">{f.evidence}</p>
              <p className="text-sm text-zinc-300 mt-2 border-l-2 border-emerald-500/40 pl-3">{f.recommendation}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------------- APK ANALYZER ---------------- */
function ApkTool() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const analyzeUrl = async (e) => {
    e.preventDefault(); if (!url.trim()) return toast.error("Enter an APK URL");
    setBusy(true); setRes(null);
    try { const { data } = await api.post("/redteam/apk/url", { apk_url: url.trim() }); setRes(data); toast.success(`${data.finding_count} findings`); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Analysis failed"); }
    finally { setBusy(false); }
  };
  const analyzeFile = async (e) => {
    const file = e.target.files?.[0]; if (!file) return;
    setBusy(true); setRes(null);
    try {
      const fd = new FormData(); fd.append("file", file);
      const { data } = await api.post("/redteam/apk/upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
      setRes(data); toast.success(`${data.finding_count} findings`);
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Analysis failed"); }
    finally { setBusy(false); }
  };
  const a = res?.app;
  return (
    <div className="bg-[#121212] border border-border p-5" data-testid="apk-tool">
      <p className="data-label mb-3 flex items-center gap-2"><Binary className="w-3.5 h-3.5 text-primary" /> APK Static Analyzer</p>
      <form onSubmit={analyzeUrl} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} data-testid="apk-url" placeholder="https://…/app.apk" />
        <button type="submit" disabled={busy} data-testid="apk-url-submit" className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Link2 className="w-4 h-4" />} Analyze URL
        </button>
      </form>
      <label className="mt-2 flex items-center justify-center gap-2 border border-dashed border-zinc-700 py-2.5 text-sm text-zinc-400 cursor-pointer hover:border-primary/50 transition-colors" data-testid="apk-upload-label">
        <Upload className="w-4 h-4" /> or upload an APK
        <input type="file" accept=".apk" className="hidden" onChange={analyzeFile} data-testid="apk-upload" disabled={busy} />
      </label>
      {res && (
        <div className="mt-4 space-y-4" data-testid="apk-result">
          <div className="flex items-center gap-3 flex-wrap">
            <p className="font-mono text-3xl font-bold" style={{ color: POSTURE_COLOR[res.posture] }}>{res.finding_count}</p>
            <div><p className="data-label">findings</p><SeverityBadge severity={res.posture} /></div>
            <div className="ml-auto text-right"><p className="font-mono text-sm text-white">{a?.package || "—"}</p><p className="data-label">v{a?.version_name || "?"} · {res.size_kb} KB</p></div>
          </div>
          {(a?.min_sdk || a?.target_sdk) && <p className="font-mono text-[11px] text-zinc-500">SDK min {a.min_sdk} → target {a.target_sdk}</p>}
          <div className="flex flex-wrap gap-2">
            {Object.entries(res.flags || {}).map(([k, v]) => (
              <span key={k} className={`font-mono text-[11px] border px-2 py-1 ${v && k !== "exported_components" ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : "border-border bg-[#0a0a0a] text-zinc-400"}`}>{k}: {String(v)}</span>
            ))}
          </div>
          {res.dangerous_permissions?.length > 0 && (
            <div><p className="data-label mb-1.5 flex items-center gap-1.5"><FileWarning className="w-3 h-3 text-severity-high" /> Dangerous permissions</p>
              <div className="flex flex-wrap gap-2">{res.dangerous_permissions.map((p, i) => <span key={i} className="font-mono text-[11px] border border-severity-high/40 bg-severity-high/10 text-severity-high px-2 py-1">{p}</span>)}</div></div>
          )}
          {res.secrets?.length > 0 && (
            <div><p className="data-label mb-1.5 flex items-center gap-1.5"><KeyRound className="w-3 h-3 text-severity-critical" /> Hardcoded secrets ({res.secrets.length})</p>
              <div className="space-y-1.5">{res.secrets.map((s, i) => (
                <div key={i} className="flex items-center justify-between gap-2 border-b border-border/50 pb-1 text-xs" data-testid={`apk-secret-${i}`}>
                  <span className="text-white">{s.type}</span><span className="font-mono text-[11px] text-zinc-500">{s.source}</span><span className="font-mono text-[11px] text-severity-critical">{s.match}</span>
                </div>))}</div></div>
          )}
          {res.urls?.length > 0 && (
            <div><p className="data-label mb-1.5">Backend URLs ({res.urls.length})</p>
              <div className="flex flex-wrap gap-2 max-h-40 overflow-y-auto">{res.urls.map((u, i) => <span key={i} className="font-mono text-[10px] border border-border bg-[#0a0a0a] px-2 py-1 text-zinc-400 break-all">{u}</span>)}</div></div>
          )}
          {res.findings?.map((f, i) => (
            <div key={i} className="border border-border bg-[#0a0a0a] p-3" data-testid={`apk-finding-${i}`}>
              <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-white text-sm">{f.title}</span><span className="ml-auto font-mono text-xs text-zinc-400">CVSS {f.cvss}</span></div>
              {f.recommendation && <p className="text-sm text-zinc-300 mt-2 border-l-2 border-emerald-500/40 pl-3">{f.recommendation}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const TOOLS = { phishing: PhishingTool, cloud: CloudTool, apk: ApkTool };

export default function RedTeam() {
  const [active, setActive] = useState(DOMAINS[0].id);
  const domain = DOMAINS.find((d) => d.id === active);
  const Tool = domain.tool ? TOOLS[domain.tool] : null;

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="redteam-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary">
          <Swords className="w-6 h-6 text-primary" />
        </div>
        <div>
          <p className="data-label mb-1">/ Red Team Operations</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">Red Team Ops</h1>
          <p className="text-sm text-zinc-500 mt-1">ATT&amp;CK-mapped methodology, an AI advisor and hands-on analyzers for authorized operations.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="bg-[#121212] border border-border p-2 h-max lg:sticky lg:top-4" data-testid="redteam-rail">
          {DOMAINS.map((d) => {
            const Icon = d.icon;
            return (
              <button key={d.id} onClick={() => setActive(d.id)} data-testid={`redteam-domain-${d.id.replace(/\s+/g, "-").toLowerCase()}`}
                className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm border-l-2 transition-colors ${active === d.id ? "border-primary bg-primary/10 text-white" : "border-transparent text-zinc-400 hover:text-white hover:bg-white/[0.03]"}`}>
                <Icon className="w-4 h-4 shrink-0" /> <span className="truncate">{d.id}</span>
                {d.tool && <span className="ml-auto w-1.5 h-1.5 rounded-full bg-primary" title="hands-on tool" />}
              </button>
            );
          })}
        </div>

        <div className="lg:col-span-3 space-y-6 nova-stagger" key={active}>
          <div className="bg-[#121212] border border-border p-6" data-testid="redteam-overview">
            <div className="flex items-center gap-3 mb-2"><domain.icon className="w-5 h-5 text-primary" /><h2 className="font-heading text-xl font-semibold">{domain.id}</h2></div>
            <p className="text-sm text-zinc-400 leading-relaxed">{domain.desc}</p>
            <div className="flex flex-wrap gap-2 mt-4">
              {domain.attack.map((t, i) => <span key={i} className="font-mono text-[11px] border border-primary/30 bg-primary/5 text-primary px-2 py-1">{t}</span>)}
            </div>
          </div>

          <div className="bg-[#121212] border border-border p-6" data-testid="redteam-methodology">
            <p className="data-label mb-3 flex items-center gap-2"><ListChecks className="w-3.5 h-3.5 text-primary" /> Operation Methodology</p>
            <ol className="space-y-2">
              {domain.method.map((m, i) => (
                <li key={i} className="flex items-start gap-3 text-sm text-zinc-300">
                  <span className="font-mono text-xs text-primary border border-primary/30 w-6 h-6 flex items-center justify-center shrink-0">{i + 1}</span>
                  <span className="pt-0.5">{m}</span>
                </li>
              ))}
            </ol>
          </div>

          {Tool && <Tool />}
          <Advisor domain={domain.id} />
        </div>
      </div>
    </div>
  );
}
