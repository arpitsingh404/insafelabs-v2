import { useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { toast } from "sonner";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { GitCompare, Loader2, TrendingUp, TrendingDown, ArrowRight, ShieldPlus, ShieldCheck } from "lucide-react";

const label = (h) => `${h.host} · ${h.finding_count ?? 0}f · ${(h.created_at || "").slice(5, 16).replace("T", " ")}`;

export function ScanCompare({ history }) {
  const scans = (history || []).filter((h) => h.status !== "running" && h.status !== "failed");
  const [open, setOpen] = useState(false);
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [loading, setLoading] = useState(false);
  const [diff, setDiff] = useState(null);

  const run = async () => {
    if (!a || !b) { toast.error("Select two scans to compare"); return; }
    if (a === b) { toast.error("Pick two different scans"); return; }
    setLoading(true); setDiff(null);
    try {
      const { data } = await api.get("/scanner/diff", { params: { a, b } });
      setDiff(data);
    } catch (err) {
      toast.error(formatApiError(err.response?.data?.detail) || "Compare failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <button data-testid="compare-open" disabled={scans.length < 2}
          className="text-[10px] font-mono uppercase tracking-wider border border-zinc-800 px-2 py-1 text-zinc-400 hover:border-primary/50 hover:text-primary transition-colors inline-flex items-center gap-1.5 disabled:opacity-40">
          <GitCompare className="w-3 h-3" /> Compare
        </button>
      </DialogTrigger>
      <DialogContent className="bg-[#0c0c0c] border-border text-white max-w-3xl max-h-[85vh] overflow-y-auto" data-testid="compare-dialog">
        <DialogHeader>
          <DialogTitle className="font-heading flex items-center gap-2"><GitCompare className="w-5 h-5 text-primary" /> Scan Diff — Exposure Comparison</DialogTitle>
        </DialogHeader>

        <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto_1fr] items-end gap-3">
          <div>
            <label className="data-label block mb-1.5">Baseline (older)</label>
            <Select value={a} onValueChange={setA}>
              <SelectTrigger data-testid="compare-select-a" className="bg-[#0a0a0a] border-zinc-800 text-sm"><SelectValue placeholder="Select scan A" /></SelectTrigger>
              <SelectContent className="bg-[#121212] border-border text-white max-h-64">
                {scans.map((h) => <SelectItem key={h.id} value={h.id} className="font-mono text-xs">{label(h)}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <ArrowRight className="w-4 h-4 text-zinc-600 mb-3 hidden sm:block" />
          <div>
            <label className="data-label block mb-1.5">Current (newer)</label>
            <Select value={b} onValueChange={setB}>
              <SelectTrigger data-testid="compare-select-b" className="bg-[#0a0a0a] border-zinc-800 text-sm"><SelectValue placeholder="Select scan B" /></SelectTrigger>
              <SelectContent className="bg-[#121212] border-border text-white max-h-64">
                {scans.map((h) => <SelectItem key={h.id} value={h.id} className="font-mono text-xs">{label(h)}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </div>

        <button onClick={run} disabled={loading} data-testid="compare-run"
          className="w-full bg-primary text-black font-semibold py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 mt-2">
          {loading ? <><Loader2 className="w-4 h-4 animate-spin" /> Comparing…</> : <><GitCompare className="w-4 h-4" /> Compare Scans</>}
        </button>

        {diff && (
          <div className="space-y-4 mt-2" data-testid="compare-result">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <Stat label="Risk Δ" value={`${diff.risk_delta > 0 ? "+" : ""}${diff.risk_delta}`} up={diff.risk_delta > 0} />
              <Stat label="Findings Δ" value={`${diff.finding_delta > 0 ? "+" : ""}${diff.finding_delta}`} up={diff.finding_delta > 0} />
              <div className="border border-severity-critical/40 bg-severity-critical/5 p-3"><p className="data-label">New Exposures</p><p className="font-mono text-2xl font-bold text-severity-critical">{diff.added.length}</p></div>
              <div className="border border-emerald-500/40 bg-emerald-500/5 p-3"><p className="data-label">Resolved</p><p className="font-mono text-2xl font-bold text-emerald-400">{diff.removed.length}</p></div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="data-label mb-2 flex items-center gap-1.5 text-severity-critical"><ShieldPlus className="w-3.5 h-3.5" /> New exposures in {diff.b.host}</p>
                <div className="space-y-1.5 max-h-72 overflow-y-auto">
                  {diff.added.length === 0 ? <p className="text-xs text-zinc-600">None — no new findings.</p> :
                    diff.added.map((f, i) => (
                      <div key={i} className="flex items-center gap-2 border-l-2 border-severity-critical/60 bg-severity-critical/5 pl-2 py-1.5" data-testid={`diff-added-${i}`}>
                        <SeverityBadge severity={f.severity} />
                        <span className="text-xs text-white truncate">{f.title}</span>
                      </div>
                    ))}
                </div>
              </div>
              <div>
                <p className="data-label mb-2 flex items-center gap-1.5 text-emerald-400"><ShieldCheck className="w-3.5 h-3.5" /> Resolved since {diff.a.host}</p>
                <div className="space-y-1.5 max-h-72 overflow-y-auto">
                  {diff.removed.length === 0 ? <p className="text-xs text-zinc-600">None resolved.</p> :
                    diff.removed.map((f, i) => (
                      <div key={i} className="flex items-center gap-2 border-l-2 border-emerald-500/60 bg-emerald-500/5 pl-2 py-1.5" data-testid={`diff-removed-${i}`}>
                        <SeverityBadge severity={f.severity} />
                        <span className="text-xs text-zinc-400 line-through truncate">{f.title}</span>
                      </div>
                    ))}
                </div>
              </div>
            </div>
            <p className="text-[11px] text-zinc-600 font-mono">{diff.common_count} finding(s) unchanged between scans.</p>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

const Stat = ({ label, value, up }) => (
  <div className="border border-border bg-[#0a0a0a] p-3">
    <p className="data-label flex items-center gap-1">{label} {up ? <TrendingUp className="w-3 h-3 text-severity-high" /> : <TrendingDown className="w-3 h-3 text-emerald-400" />}</p>
    <p className={`font-mono text-2xl font-bold ${up ? "text-severity-high" : "text-emerald-400"}`}>{value}</p>
  </div>
);
