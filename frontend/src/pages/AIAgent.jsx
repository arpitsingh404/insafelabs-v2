import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { Markdown } from "@/components/Markdown";
import { Bot, Loader2, Play, Wrench, ChevronDown, CheckCircle2, XCircle, Sparkles } from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm";

function ToolCatalog({ tools }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-border bg-[#0a0a0a]">
      <button onClick={() => setOpen((o) => !o)} data-testid="agent-tools-toggle"
        className="w-full flex items-center gap-2 px-4 py-3 text-left">
        <Wrench className="w-4 h-4 text-primary" />
        <span className="font-heading text-sm font-semibold">Tools the AI can control</span>
        <span className="data-label ml-2">{tools.length}</span>
        <ChevronDown className={`w-4 h-4 ml-auto text-zinc-500 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div className="px-4 pb-4 grid sm:grid-cols-2 gap-1.5" data-testid="agent-tools-list">
          {tools.map((t) => (
            <div key={t.name} className="text-[11px] font-mono border border-border/50 px-2 py-1.5">
              <span className="text-primary">{t.name}</span><span className="text-zinc-600">({t.params.join(", ")})</span>
              <p className="text-zinc-500 mt-0.5">{t.desc}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AIAgent() {
  const [tools, setTools] = useState([]);
  const [instruction, setInstruction] = useState("");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);

  useEffect(() => { api.get("/ai/agent/tools").then(({ data }) => setTools(data.tools || [])).catch(() => {}); }, []);

  const run = async () => {
    if (!instruction.trim()) return toast.error("Enter an instruction");
    setBusy(true); setRes(null);
    try { setRes((await api.post("/ai/agent/run", { instruction: instruction.trim(), target: target.trim(), max_steps: 6 })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Agent run failed"); }
    finally { setBusy(false); }
  };

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="ai-agent-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><Bot className="w-7 h-7 text-primary" /> AI Agent</h1>
        <p className="text-sm text-zinc-500 mt-1.5">
          InsafeLabs-AI plans and runs the app's own tools for you. Give it an instruction and a target —
          it picks the tools, executes them, and writes the report. Authorized targets only.
        </p>
      </header>

      <ToolCatalog tools={tools} />

      <div className="bg-[#121212] border border-border p-5 space-y-3">
        <div>
          <p className="data-label mb-1.5">Instruction</p>
          <textarea value={instruction} onChange={(e) => setInstruction(e.target.value)} data-testid="agent-instruction"
            placeholder="e.g. Do a full security assessment and tell me the biggest risks"
            className={inputCls + " min-h-[90px] resize-y"} />
        </div>
        <div className="grid sm:grid-cols-3 gap-3">
          <div className="sm:col-span-2">
            <p className="data-label mb-1.5">Target (URL / host / domain)</p>
            <input value={target} onChange={(e) => setTarget(e.target.value)} data-testid="agent-target" placeholder="https://target.tld" className={inputCls} />
          </div>
          <div className="flex items-end">
            <button onClick={run} disabled={busy || !instruction.trim()} data-testid="agent-run" className={btnCls + " w-full"}>
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Run agent
            </button>
          </div>
        </div>
        <p className="text-[11px] text-zinc-600 font-mono">The AI only uses the {tools.length} tools listed above — it cannot run anything else.</p>
      </div>

      {busy && (
        <div className="flex items-center gap-2 text-zinc-500">
          <Loader2 className="w-4 h-4 animate-spin" /> <span className="data-label">planning + executing…</span>
        </div>
      )}

      {res && (
        <>
          <div className="bg-[#121212] border border-border p-5" data-testid="agent-plan">
            <div className="flex items-center gap-2 mb-3"><Sparkles className="w-4 h-4 text-primary" /><h3 className="font-heading text-base font-semibold">Plan</h3>
              <span className="data-label ml-2">{res.plan?.length || 0} steps</span></div>
            {(res.plan || []).length === 0 ? <p className="text-sm text-zinc-600">No tools needed for this instruction.</p> : (
              <ol className="space-y-1.5">
                {res.plan.map((p, i) => (
                  <li key={i} className="text-sm text-zinc-300 font-mono">
                    <span className="text-zinc-600">{i + 1}.</span> <span className="text-primary">{p.tool}</span>
                    {p.args && Object.keys(p.args).length ? <span className="text-zinc-500"> {JSON.stringify(p.args)}</span> : null}
                    {p.why ? <span className="text-zinc-600"> — {p.why}</span> : null}
                  </li>
                ))}
              </ol>
            )}
          </div>

          <div className="bg-[#121212] border border-border p-5" data-testid="agent-steps">
            <h3 className="font-heading text-base font-semibold mb-3">Execution ({res.steps?.length || 0})</h3>
            <div className="space-y-2">
              {(res.steps || []).map((s, i) => (
                <details key={i} className="border border-border bg-[#0a0a0a]" data-testid={`agent-step-${i}`}>
                  <summary className="flex items-center gap-2 px-3 py-2 cursor-pointer text-sm">
                    {s.result?.error ? <XCircle className="w-4 h-4 text-severity-critical" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                    <span className="font-mono text-primary">{s.tool}</span>
                    <span className="text-zinc-500 text-xs">{s.summary}</span>
                  </summary>
                  <pre className="px-3 pb-3 text-[11px] font-mono text-zinc-400 whitespace-pre-wrap break-all max-h-72 overflow-y-auto">{JSON.stringify(s.result, null, 2).slice(0, 20000)}</pre>
                </details>
              ))}
            </div>
          </div>

          <div className="bg-[#121212] border border-border p-5" data-testid="agent-report">
            <div className="flex items-center gap-2 mb-3"><Bot className="w-4 h-4 text-primary" /><h3 className="font-heading text-base font-semibold">AI Report</h3></div>
            <div className="prose-invert max-w-none">
              <Markdown>{res.final_report || "_no report_"}</Markdown>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
