import { useEffect, useState, useCallback } from "react";
import { api, formatApiError } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { toast } from "sonner";
import {
  Play, Loader2, Trash2, FileSearch, ShieldAlert, Radar, ChevronRight, ShieldCheck,
  Upload, FileCode2, X,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm focus:outline-none focus:border-primary transition-colors";
const POSTURE_COLOR = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6" };
const EXT_LANG = {
  py: "python", js: "node.js", jsx: "node.js", ts: "typescript", tsx: "typescript", java: "java",
  go: "go", rb: "ruby", php: "php", c: "c", h: "c", cpp: "c++", cc: "c++", cs: "c#", rs: "rust",
  kt: "kotlin", swift: "swift", scala: "scala", sh: "bash", sql: "sql", html: "html", css: "css",
  vue: "vue", dart: "dart", pl: "perl", lua: "lua", r: "r", ex: "elixir", exs: "elixir",
  yml: "yaml", yaml: "yaml", tf: "terraform", dockerfile: "docker",
};
const MAX_UPLOAD_BYTES = 400_000;

function RiskGauge({ score, posture }) {
  const color = POSTURE_COLOR[posture] || "#3B82F6";
  return (
    <div className="flex items-center gap-4" data-testid="risk-gauge">
      <div className="shrink-0">
        <p className="font-mono text-4xl font-bold" style={{ color }}>{score}</p>
        <p className="data-label">Risk / 100</p>
      </div>
      <div className="flex-1">
        <div className="flex items-center justify-between mb-1.5">
          <span className="data-label">Posture</span>
          <SeverityBadge severity={posture} />
        </div>
        <div className="h-2 bg-[#0a0a0a] border border-border overflow-hidden">
          <div className="h-full transition-all duration-700" style={{ width: `${score}%`, background: color }} />
        </div>
      </div>
    </div>
  );
}

function ReconPanel({ recon }) {
  if (!recon) return null;
  if (!recon.reachable) {
    return (
      <div className="border border-border bg-[#0a0a0a] p-4" data-testid="recon-panel">
        <p className="data-label mb-2 flex items-center gap-1.5"><Radar className="w-3.5 h-3.5" /> Live Recon</p>
        <p className="text-xs text-zinc-500 font-mono">Target not reachable from scanner — analysis based on provided context. {recon.error}</p>
      </div>
    );
  }
  const headers = recon.headers || {};
  return (
    <div className="border border-border bg-[#0a0a0a] p-4" data-testid="recon-panel">
      <div className="flex items-center justify-between mb-3">
        <p className="data-label flex items-center gap-1.5"><Radar className="w-3.5 h-3.5" /> Live Recon</p>
        <span className="font-mono text-xs text-emerald-400">HTTP {recon.status}</span>
      </div>
      <div className="grid sm:grid-cols-2 gap-x-6 gap-y-1.5">
        {Object.entries(headers).map(([k, v]) => (
          <div key={k} className="flex items-center justify-between gap-2 text-xs border-b border-border/50 pb-1">
            <span className="font-mono text-zinc-500 truncate">{k}</span>
            {v ? <span className="font-mono text-zinc-300 truncate max-w-[55%]">{String(v).slice(0, 40)}</span>
               : <span className="font-mono text-severity-high">missing</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingCard({ f, i }) {
  return (
    <div className="border border-border bg-[#0a0a0a] p-5" data-testid={`finding-${i}`}>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3 flex-wrap">
          <SeverityBadge severity={f.severity} />
          {f.cwe && <span className="font-mono text-xs text-primary">{f.cwe}</span>}
        </div>
        {f.cvss != null && f.cvss !== "" && <span className="font-mono text-xs text-zinc-400">CVSS {f.cvss}</span>}
      </div>
      <h4 className="text-white font-medium mt-3">{f.title}</h4>
      {f.category && <p className="font-mono text-[11px] text-zinc-500 mt-1">{f.category}</p>}
      {f.location && (
        <p className="font-mono text-[11px] text-severity-low mt-2 bg-severity-low/5 border border-severity-low/20 px-2 py-1 inline-block">{f.location}</p>
      )}
      {f.description && <p className="text-sm text-zinc-400 mt-3 leading-relaxed">{f.description}</p>}
      {f.evidence && (
        <div className="mt-3">
          <p className="data-label mb-1">Evidence</p>
          <p className="text-xs text-zinc-400 font-mono leading-relaxed">{f.evidence}</p>
        </div>
      )}
      {f.recommendation && (
        <div className="mt-3 border-l-2 border-emerald-500/40 pl-3">
          <p className="data-label mb-1 !text-emerald-400/80">Remediation</p>
          <p className="text-sm text-zinc-300 leading-relaxed">{f.recommendation}</p>
        </div>
      )}
    </div>
  );
}

export function AssessmentModule({ module, label, sublabel, icon: Icon, standard, fields, sample, languageField, runLabel }) {
  const initial = Object.fromEntries(fields.map((f) => [f.key, f.default || ""]));
  const [form, setForm] = useState(initial);
  const [history, setHistory] = useState([]);
  const [active, setActive] = useState(null);
  const [running, setRunning] = useState(false);
  const [uploaded, setUploaded] = useState([]);
  const [drag, setDrag] = useState(false);

  const set = (k, v) => setForm((s) => ({ ...s, [k]: v }));

  const onFiles = async (fileList, f) => {
    const files = Array.from(fileList || []).slice(0, 10);
    if (!files.length) return;
    let combined = form[f.key] ? form[f.key] + "\n\n" : "";
    const chips = [...uploaded];
    let firstExt = "", loaded = 0;
    for (const file of files) {
      if (file.size > MAX_UPLOAD_BYTES) { toast.error(`${file.name} too large (max 400KB)`); continue; }
      let text = "";
      try { text = await file.text(); } catch { toast.error(`Could not read ${file.name}`); continue; }
      if (/\u0000/.test(text.slice(0, 4000))) { toast.error(`${file.name} looks binary — skipped`); continue; }
      const ext = (file.name.split(".").pop() || "").toLowerCase();
      if (!firstExt) firstExt = ext;
      combined += (files.length > 1 || uploaded.length ? `// ===== ${file.name} =====\n` : "") + text + "\n";
      chips.push({ name: file.name, lines: text.split("\n").length });
      loaded++;
    }
    if (!loaded) return;
    set(f.key, combined.trim());
    setUploaded(chips);
    if (languageField && EXT_LANG[firstExt]) set(languageField, EXT_LANG[firstExt]);
    toast.success(`Loaded ${loaded} file${loaded > 1 ? "s" : ""} for review`);
  };

  const clearUploaded = (f) => { setUploaded([]); set(f.key, ""); };

  const load = useCallback(async () => {
    const { data } = await api.get("/assessments", { params: { module } });
    setHistory(data);
  }, [module]);

  useEffect(() => { load(); }, [load]);

  const run = async (e) => {
    e.preventDefault();
    setRunning(true);
    try {
      const { data } = await api.post("/assessments/run", { module, inputs: form });
      toast.success(`Assessment complete — ${data.finding_count} findings`, { description: data.summary?.slice(0, 90) });
      setActive(data);
      load();
    } catch (err) {
      toast.error(formatApiError(err.response?.data?.detail) || "Assessment failed");
    } finally {
      setRunning(false);
    }
  };

  const open = async (id) => {
    const { data } = await api.get(`/assessments/${id}`);
    setActive(data);
  };

  const remove = async (id, e) => {
    e.stopPropagation();
    await api.delete(`/assessments/${id}`);
    if (active?.id === id) setActive(null);
    load();
    toast.success("Assessment deleted");
  };

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid={`module-${module}`}>
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0">
          <Icon className="w-6 h-6 text-primary" />
        </div>
        <div>
          <p className="data-label mb-1">/ {standard}</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">{label}</h1>
          <p className="text-sm text-zinc-500 mt-1">{sublabel}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Inputs + history */}
        <div className="space-y-6">
          <form onSubmit={run} className="bg-[#121212] border border-border p-6 space-y-4" data-testid="assessment-form">
            {sample && (
              <div className="flex justify-end -mb-2">
                <button type="button" onClick={() => setForm({ ...initial, ...sample })} className="text-[10px] font-mono uppercase tracking-widest text-primary hover:underline" data-testid="load-sample">Load sample</button>
              </div>
            )}
            {fields.map((f, idx) => (
              <div key={f.key}>
                <label className="data-label block mb-1.5">{f.label}</label>
                {f.type === "textarea" ? (
                  <>
                    {f.upload && (
                      <>
                        <div
                          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
                          onDragLeave={() => setDrag(false)}
                          onDrop={(e) => { e.preventDefault(); setDrag(false); onFiles(e.dataTransfer.files, f); }}
                          className={`border border-dashed p-3 mb-2 text-center transition-colors ${drag ? "border-primary bg-primary/5" : "border-zinc-700"}`}
                          data-testid={`upload-zone-${f.key}`}>
                          <input id={`file-${f.key}`} type="file" multiple className="hidden" data-testid={`file-input-${f.key}`}
                            accept=".py,.js,.jsx,.ts,.tsx,.java,.go,.rb,.php,.c,.h,.cpp,.cc,.cs,.rs,.kt,.swift,.scala,.sh,.sql,.html,.css,.vue,.dart,.pl,.lua,.r,.ex,.exs,.yml,.yaml,.tf,.txt,.md,text/*"
                            onChange={(e) => { onFiles(e.target.files, f); e.target.value = ""; }} />
                          <label htmlFor={`file-${f.key}`} className="cursor-pointer inline-flex items-center gap-2 text-xs text-zinc-400 hover:text-primary">
                            <Upload className="w-4 h-4" /> Drop code files here or <span className="text-primary underline">browse</span>
                          </label>
                          <p className="text-[10px] text-zinc-600 mt-1 font-mono">.py .js .ts .java .go .php .rb .c/.cpp .cs … · up to 10 files · 400KB each · language auto-detected</p>
                        </div>
                        {uploaded.length > 0 && (
                          <div className="flex flex-wrap gap-1.5 mb-2 items-center" data-testid="uploaded-files">
                            {uploaded.map((u, i) => (
                              <span key={i} className="inline-flex items-center gap-1.5 border border-border bg-[#0a0a0a] px-2 py-1 text-[10px] font-mono text-zinc-300">
                                <FileCode2 className="w-3 h-3 text-primary" /> {u.name} <span className="text-zinc-600">{u.lines}L</span>
                              </span>
                            ))}
                            <button type="button" onClick={() => clearUploaded(f)} data-testid="clear-uploaded" className="text-[10px] text-zinc-500 hover:text-severity-critical underline inline-flex items-center gap-1"><X className="w-3 h-3" /> clear</button>
                          </div>
                        )}
                      </>
                    )}
                    <textarea className={`${inputCls} ${f.mono ? "font-mono text-xs" : ""}`} style={{ minHeight: f.rows ? `${f.rows * 20}px` : "120px" }}
                      value={form[f.key]} onChange={(e) => set(f.key, e.target.value)} data-testid={`field-${f.key}`} placeholder={f.placeholder} required={idx === 0} />
                  </>
                ) : f.type === "select" ? (
                  <select className={inputCls} value={form[f.key]} onChange={(e) => set(f.key, e.target.value)} data-testid={`field-${f.key}`}>
                    {f.options.map((o) => <option key={o} value={o}>{o}</option>)}
                  </select>
                ) : (
                  <input className={inputCls} value={form[f.key]} onChange={(e) => set(f.key, e.target.value)} data-testid={`field-${f.key}`} placeholder={f.placeholder} required={idx === 0} />
                )}
              </div>
            ))}
            <button type="submit" disabled={running} data-testid="run-assessment" className="w-full bg-primary text-black font-semibold py-3 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60">
              {running ? <><Loader2 className="w-4 h-4 animate-spin" /> Running…</> : <><Play className="w-4 h-4" /> {runLabel || "Run Assessment"}</>}
            </button>
          </form>

          <div className="bg-[#121212] border border-border">
            <p className="data-label px-4 py-3 border-b border-border">History</p>
            {history.length === 0 ? (
              <p className="p-6 text-sm text-zinc-500 text-center">No assessments yet</p>
            ) : (
              <div className="divide-y divide-border max-h-72 overflow-y-auto">
                {history.map((h) => (
                  <button key={h.id} onClick={() => open(h.id)} data-testid={`history-${h.id}`}
                    className={`w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-white/[0.02] transition-colors group ${active?.id === h.id ? "bg-primary/5 border-l-2 border-primary" : "border-l-2 border-transparent"}`}>
                    <SeverityBadge severity={h.posture} />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-white truncate">{h.title}</p>
                      <p className="font-mono text-[10px] text-zinc-600">{h.finding_count} findings · risk {h.risk_score}</p>
                    </div>
                    <Trash2 onClick={(e) => remove(h.id, e)} className="w-3.5 h-3.5 text-zinc-600 hover:text-severity-critical opacity-0 group-hover:opacity-100" />
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Result */}
        <div className="lg:col-span-2">
          {!active ? (
            <div className="bg-[#121212] border border-border p-16 text-center text-zinc-500 h-full flex flex-col items-center justify-center" data-testid="assessment-empty">
              <FileSearch className="w-12 h-12 mb-4 opacity-40" />
              <p className="max-w-xs">Run an assessment or open one from history to view the AI-generated report.</p>
            </div>
          ) : (
            <div className="space-y-5" data-testid="assessment-result">
              <div className="bg-[#121212] border border-border p-6 space-y-5">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <span className="font-mono text-sm text-primary">{active.ref}</span>
                  <span className="data-label">{active.finding_count} findings</span>
                </div>
                <RiskGauge score={active.risk_score} posture={active.posture} />
                {active.summary && <p className="text-sm text-zinc-300 leading-relaxed border-t border-border pt-4">{active.summary}</p>}
              </div>

              {module === "web" && <ReconPanel recon={active.recon} />}

              {active.findings?.length ? (
                <div className="space-y-4">
                  {active.findings.map((f, i) => <FindingCard key={i} f={f} i={i} />)}
                </div>
              ) : (
                <div className="border border-emerald-500/30 bg-emerald-500/5 p-12 text-center text-emerald-400/80">
                  <ShieldCheck className="w-8 h-8 mx-auto mb-3" />
                  <p className="text-sm">No significant issues identified.</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
