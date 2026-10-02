import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { Layers, Radar, Globe, ShieldAlert, Lock, Loader2, Play, ChevronDown, CheckCircle2, XCircle, X } from "lucide-react";

const ICONS = { radar: Radar, globe: Globe, shield: ShieldAlert, lock: Lock, layers: Layers };
const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm";

export default function Playbooks() {
  const [pbs, setPbs] = useState([]);
  const [sel, setSel] = useState(null);
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);

  useEffect(() => { api.get("/playbooks").then(({ data }) => setPbs(data.playbooks || [])).catch(() => {}); }, []);

  const open = (pb) => { setSel(pb); setRes(null); setTarget(""); };
  const run = async () => {
    if (!target.trim()) return toast.error("Enter a target");
    setBusy(true); setRes(null);
    try { setRes((await api.post("/playbooks/run", { playbook: sel.id, target: target.trim() })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Playbook failed"); }
    finally { setBusy(false); }
  };

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="playbooks-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><Layers className="w-7 h-7 text-primary" /> Playbooks</h1>
        <p className="text-sm text-zinc-500 mt-1.5">One-click guided workflows — each runs a curated sequence of the platform's native tools and collects the findings.</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4">
        {pbs.map((pb) => {
          const Icon = ICONS[pb.icon] || Layers;
          return (
            <button key={pb.id} onClick={() => open(pb)} data-testid={`playbook-${pb.id}`}
              className="text-left bg-[#121212] border border-border p-4 hover:border-primary/50 hover:bg-[#151515] transition-colors">
              <div className="flex items-center gap-2.5 mb-2">
                <span className="w-9 h-9 border border-primary/30 bg-primary/5 grid place-items-center"><Icon className="w-4 h-4 text-primary" /></span>
                <span className="font-heading text-base font-semibold text-white">{pb.name}</span>
              </div>
              <p className="text-xs text-zinc-500 mb-2">{pb.desc}</p>
              <p className="data-label">{pb.steps.length} steps · {pb.targetHint}</p>
            </button>
          );
        })}
      </div>

      {sel && (
        <div className="fixed inset-0 z-[9998] bg-black/60 backdrop-blur-sm flex items-start justify-center p-4 overflow-y-auto" onClick={() => setSel(null)} data-testid="playbook-detail">
          <div className="w-full max-w-3xl my-8 border border-border bg-[#0c0c0c]" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-3 px-5 py-4 border-b border-border">
              <div>
                <p className="data-label">Playbook</p>
                <h3 className="font-heading text-xl font-bold">{sel.name}</h3>
                <p className="text-xs text-zinc-500 mt-1">{sel.desc}</p>
              </div>
              <button onClick={() => setSel(null)} className="text-zinc-500 hover:text-white"><X className="w-5 h-5" /></button>
            </div>

            <div className="p-5 space-y-4">
              <div className="space-y-1.5">
                {sel.steps.map((s, i) => (
                  <p key={i} className="text-xs font-mono text-zinc-400"><span className="text-zinc-600">{i + 1}.</span> <span className="text-primary">{s.tool}</span> <span className="text-zinc-600">({s.param})</span> — {s.desc}</p>
                ))}
              </div>
              <div className="flex flex-col sm:flex-row gap-2">
                <input value={target} onChange={(e) => setTarget(e.target.value)} data-testid="playbook-target" placeholder={sel.targetHint} className={inputCls} />
                <button onClick={run} disabled={busy} data-testid="playbook-run" className={btnCls}>
                  {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Run playbook
                </button>
              </div>

              {res && (
                <>
                  <div className="grid grid-cols-3 gap-2">
                    <div className="border border-border bg-[#0a0a0a] px-3 py-2"><p className="data-label">Steps</p><p className="font-mono text-xs text-zinc-200 mt-0.5">{res.steps?.length || 0}</p></div>
                    <div className="border border-border bg-[#0a0a0a] px-3 py-2"><p className="data-label">Findings</p><p className="font-mono text-xs text-primary mt-0.5">{res.findings_total}</p></div>
                    <div className="border border-border bg-[#0a0a0a] px-3 py-2"><p className="data-label">Target</p><p className="font-mono text-[11px] text-zinc-300 mt-0.5 truncate">{res.target}</p></div>
                  </div>
                  <div className="space-y-2">
                    {(res.steps || []).map((s, i) => (
                      <details key={i} className="border border-border bg-[#0a0a0a]" data-testid={`playbook-step-${i}`}>
                        <summary className="flex items-center gap-2 px-3 py-2 cursor-pointer text-sm">
                          {s.result?.error ? <XCircle className="w-4 h-4 text-severity-critical" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                          <span className="font-mono text-primary">{s.tool}</span>
                          <span className="text-zinc-500 text-xs">{s.summary}</span>
                          <ChevronDown className="w-3.5 h-3.5 ml-auto text-zinc-600" />
                        </summary>
                        <pre className="px-3 pb-3 text-[11px] font-mono text-zinc-400 whitespace-pre-wrap break-all max-h-72 overflow-y-auto">{JSON.stringify(s.result, null, 2).slice(0, 20000)}</pre>
                      </details>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
