import { useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Markdown } from "@/components/Markdown";
import { Loader2, Play, FileDown, ShieldAlert, Sparkles, CheckCircle2, ChevronDown } from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm";

const META = {
  vapt: { title: "VAPT", full: "Vulnerability Assessment & Penetration Test", hint: "URL, host or domain — e.g. https://target.tld",
          blurb: "Full phased assessment: Recon → Infrastructure → Web application → Vulnerability scan." },
  wapt: { title: "WAPT", full: "Web Application Penetration Test", hint: "URL — e.g. https://target.tld/page?id=1",
          blurb: "OWASP Top 10 (2021) mapped web-application test." },
};

export default function Assessment({ kind = "vapt" }) {
  const meta = META[kind] || META.vapt;
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [aiBusy, setAiBusy] = useState(false);
  const [aiText, setAiText] = useState("");

  const run = async () => {
    if (!target.trim()) return toast.error("Enter a target");
    setBusy(true); setRes(null); setAiText("");
    try { setRes((await api.post(`/${kind}/run`, { target: target.trim() })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Assessment failed"); }
    finally { setBusy(false); }
  };

  const aiSummary = async () => {
    if (!res) return;
    setAiBusy(true);
    try { const { data } = await api.post("/vapt/ai-summary", { target: res.target, findings: res.findings, summary: res.summary }); setAiText(data.summary); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "AI summary failed"); }
    finally { setAiBusy(false); }
  };

  const download = () => {
    if (!res) return;
    const blob = new Blob([res.report_md || ""], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `insafelabs-${kind}-report.md`;
    a.click(); URL.revokeObjectURL(a);
  };

  const s = res?.summary;
  const GCOL = { A: "#22C55E", B: "#3B82F6", C: "#F59E0B", D: "#F97316", F: "#EF4444" };

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid={`${kind}-page`}>
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><ShieldAlert className="w-7 h-7 text-primary" /> {meta.title} <span className="text-base font-normal text-zinc-500">— {meta.full}</span></h1>
        <p className="text-sm text-zinc-500 mt-1.5">{meta.blurb} Non-destructive; authorized targets only.</p>
      </header>

      <div className="flex flex-col sm:flex-row gap-2">
        <input value={target} onChange={(e) => setTarget(e.target.value)} data-testid={`${kind}-target`} placeholder={meta.hint} className={inputCls} />
        <button onClick={run} disabled={busy || !target.trim()} data-testid={`${kind}-run`} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Run {meta.title}
        </button>
      </div>

      {busy && <div className="flex items-center gap-2 text-zinc-500"><Loader2 className="w-4 h-4 animate-spin" /><span className="data-label">running assessment…</span></div>}

      {res && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2" data-testid={`${kind}-summary`}>
            <div className="border border-border bg-[#0a0a0a] px-3 py-2">
              <p className="data-label">Grade</p>
              <p className="font-mono text-2xl font-bold mt-0.5" style={{ color: GCOL[s.grade] || "#fff" }}>{s.grade}</p>
            </div>
            <Stat k="Posture" v={s.posture} accent={GCOL[s.grade]} />
            <Stat k="Risk score" v={`${s.risk_score}/100`} accent="#FACC15" />
            <Stat k="Critical" v={s.critical} accent="#EF4444" />
            <Stat k="High" v={s.high} accent="#F97316" />
            <Stat k="Medium" v={s.medium} accent="#F59E0B" />
            <Stat k="Low" v={s.low} accent="#3B82F6" />
          </div>

          <div className="flex flex-wrap gap-2">
            <button onClick={download} data-testid={`${kind}-download`} className="inline-flex items-center gap-2 border border-border px-3 py-2 text-xs font-mono uppercase tracking-wider text-zinc-300 hover:text-primary hover:border-primary/50 transition-colors">
              <FileDown className="w-3.5 h-3.5" /> download report (.md)
            </button>
            <button onClick={aiSummary} disabled={aiBusy} data-testid={`${kind}-ai`} className="inline-flex items-center gap-2 border border-primary/40 px-3 py-2 text-xs font-mono uppercase tracking-wider text-primary hover:bg-primary/10 transition-colors disabled:opacity-60">
              {aiBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />} AI executive summary
            </button>
          </div>

          {aiText && (
            <div className="bg-[#121212] border border-border p-5" data-testid={`${kind}-ai-summary`}>
              <div className="flex items-center gap-2 mb-2"><Sparkles className="w-4 h-4 text-primary" /><h3 className="font-heading text-sm font-semibold">AI Executive Summary</h3></div>
              <Markdown>{aiText}</Markdown>
            </div>
          )}

          <div className="space-y-3">
            {(res.sections || []).map((sec) => (
              <details key={sec.id} open className="bg-[#121212] border border-border" data-testid={`${kind}-section-${sec.id}`}>
                <summary className="flex items-center gap-2 px-5 py-3 cursor-pointer">
                  <span className="font-heading text-sm font-semibold">{sec.name}</span>
                  <span className="data-label">{sec.tools?.join(", ")}</span>
                  <span className={`ml-auto font-mono text-xs ${sec.findings.length ? "text-severity-high" : "text-emerald-400"}`}>{sec.findings.length} finding(s)</span>
                  <ChevronDown className="w-4 h-4 text-zinc-500" />
                </summary>
                <div className="px-5 pb-4 space-y-2">
                  {sec.findings.length === 0 ? <p className="text-sm text-emerald-400 flex items-center gap-2"><CheckCircle2 className="w-4 h-4" /> No findings in this phase.</p> : sec.findings.map((f, i) => (
                    <div key={i} className="border border-border bg-[#0a0a0a] p-3">
                      <div className="flex items-center gap-2 mb-1"><SeverityBadge severity={f.severity} /><span className="text-sm text-white font-medium">{f.title}</span><span className="ml-auto data-label">{f.source}</span></div>
                      <p className="text-xs text-zinc-400">{f.detail}</p>
                      {f.evidence ? <pre className="mt-1.5 text-[11px] font-mono text-zinc-500 whitespace-pre-wrap break-all">{String(f.evidence).slice(0, 400)}</pre> : null}
                      {f.recommendation ? <p className="text-[11px] text-primary mt-1">→ {f.recommendation}</p> : null}
                    </div>
                  ))}
                </div>
              </details>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

const Stat = ({ k, v, accent }) => (
  <div className="border border-border bg-[#0a0a0a] px-3 py-2">
    <p className="data-label">{k}</p>
    <p className="font-mono text-lg font-bold mt-0.5 tabular-nums" style={{ color: accent || "#e4e4e7" }}>{v}</p>
  </div>
);
