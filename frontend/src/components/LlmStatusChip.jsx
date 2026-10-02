import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Cpu, Check, ChevronDown, Loader2, RotateCcw } from "lucide-react";
import { Popover, PopoverTrigger, PopoverContent } from "@/components/ui/popover";
import { toast } from "sonner";

export function LlmStatusChip() {
  const [st, setSt] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = () => api.get("/ai/status").then(({ data }) => setSt({
    backend: data?.backend ?? "—",
    model: data?.model ?? "—",
    models: Array.isArray(data?.models) ? data.models : [],
    key_present: !!data?.key_present,
    usage: {
      total_cost: Number(data?.usage?.total_cost ?? 0),
      input_tokens: Number(data?.usage?.input_tokens ?? 0),
      output_tokens: Number(data?.usage?.output_tokens ?? 0),
      calls: Number(data?.usage?.calls ?? 0),
    },
  })).catch(() => setSt(false));
  useEffect(() => {
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);

  const pick = async (m) => {
    if (!st || m === st.model || busy) return;
    setBusy(true);
    try { await api.post("/ai/model", { model: m }); await load(); toast.success(`Model switched → ${m}`); }
    catch { toast.error("Model switch failed"); }
    finally { setBusy(false); }
  };
  const resetSpend = async () => {
    setBusy(true);
    try { await api.post("/ai/usage/reset"); await load(); toast.success("Spend counter reset"); }
    catch { toast.error("Reset failed"); }
    finally { setBusy(false); }
  };

  if (!st) return null;
  const ok = st.key_present;

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button data-testid="llm-status-chip" className="flex items-center gap-2 border border-primary/30 bg-black/40 px-2.5 py-1 text-[11px] font-mono hover:bg-primary/5 transition-colors">
          <Cpu className="w-3.5 h-3.5 text-primary" />
          <span className="text-zinc-300 hidden md:inline">LLM: <span className="text-zinc-400">{st.backend}</span> · <span className="text-primary">{st.model}</span></span>
          <span className="md:hidden text-primary">{st.model}</span>
          {ok ? <Check className="w-3 h-3 text-emerald-400" /> : <span className="text-severity-high font-bold">✗</span>}
          <span className="text-zinc-500 border-l border-border pl-2" data-testid="llm-spend">${st.usage.total_cost.toFixed(4)}</span>
          <ChevronDown className="w-3 h-3 text-zinc-500" />
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-72 bg-[#0c0c0c] border-border text-white p-0" data-testid="llm-popover">
        <div className="p-3 border-b border-border">
          <p className="data-label mb-0.5">AI Engine</p>
          <p className="text-xs text-zinc-400 font-mono">{st.backend} · key {ok ? "loaded ✓" : "missing ✗"}</p>
        </div>
        <div className="p-3 border-b border-border">
          <p className="data-label mb-2">Model</p>
          <div className="space-y-1 max-h-56 overflow-y-auto">
            {st.models.map((m) => (
              <button key={m} onClick={() => pick(m)} disabled={busy} data-testid={`llm-model-${m}`}
                className={`w-full flex items-center justify-between px-2 py-1.5 text-xs font-mono border transition-colors ${m === st.model ? "border-primary text-primary bg-primary/10" : "border-transparent text-zinc-300 hover:border-border hover:bg-white/5"}`}>
                {m}
                {m === st.model && <Check className="w-3.5 h-3.5" />}
              </button>
            ))}
          </div>
        </div>
        <div className="p-3 flex items-center justify-between">
          <div>
            <p className="data-label">Spend (est.)</p>
            <p className="text-sm font-mono text-primary">${st.usage.total_cost.toFixed(4)}</p>
            <p className="text-[10px] text-zinc-500 font-mono">{st.usage.calls} calls · {(st.usage.input_tokens + st.usage.output_tokens).toLocaleString()} tokens</p>
          </div>
          <button onClick={resetSpend} disabled={busy} data-testid="llm-reset-spend" className="flex items-center gap-1 text-[11px] font-mono text-zinc-400 border border-border px-2 py-1 hover:text-white transition-colors">
            {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <RotateCcw className="w-3 h-3" />} reset
          </button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
