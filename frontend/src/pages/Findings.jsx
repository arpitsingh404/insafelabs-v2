import { useEffect, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { api } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Bug, Loader2, ChevronDown, Radar, ShieldAlert } from "lucide-react";

const SEVS = ["critical", "high", "medium", "low", "info"];
const SEV_COLORS = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#A1A1AA" };
const fmt = (s) => { try { return new Date(s).toLocaleString(); } catch { return s || ""; } };

export default function Findings() {
  const [sp, setSp] = useSearchParams();
  const severity = sp.get("severity") || "";
  const [data, setData] = useState(null);
  const [open, setOpen] = useState(null);

  useEffect(() => {
    let active = true;
    setData(null);
    api.get("/dashboard/findings", { params: severity ? { severity } : {} })
      .then(({ data }) => active && setData(data))
      .catch(() => active && setData({ findings: [], counts: {}, count: 0, total: 0 }));
    return () => { active = false; };
  }, [severity]);

  const setSev = (s) => { setOpen(null); setSp(s ? { severity: s } : {}); };
  const counts = data?.counts || {};

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="findings-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary"><Bug className="w-6 h-6 text-primary" /></div>
        <div className="flex-1">
          <p className="data-label mb-1">/ Aggregated · Findings</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">Findings Explorer</h1>
          <p className="text-sm text-zinc-500 mt-1">All findings from every recon scan in one place — filter by severity (dashboard drilldowns land here).</p>
        </div>
      </div>

      {/* severity filter chips */}
      <div className="flex flex-wrap gap-2" data-testid="findings-filters">
        <button onClick={() => setSev("")} data-testid="findings-chip-all"
          className={`px-3 py-1.5 text-xs font-mono uppercase tracking-widest border transition-colors ${severity === "" ? "border-primary bg-primary/10 text-primary" : "border-border text-zinc-400 hover:text-white hover:border-primary/40"}`}>
          All {data ? `· ${data.total ?? 0}` : ""}
        </button>
        {SEVS.map((s) => (
          <button key={s} onClick={() => setSev(s)} data-testid={`findings-chip-${s}`}
            className={`px-3 py-1.5 text-xs font-mono uppercase tracking-widest border transition-colors ${severity === s ? "text-black" : "border-border text-zinc-400 hover:text-white hover:border-primary/40"}`}
            style={severity === s ? { background: SEV_COLORS[s], borderColor: SEV_COLORS[s] } : {}}>
            {s} · {counts[s] ?? 0}
          </button>
        ))}
      </div>

      {!data ? (
        <div className="flex items-center gap-2 text-zinc-500 py-16 justify-center"><Loader2 className="w-5 h-5 animate-spin" /> Loading findings…</div>
      ) : data.findings.length === 0 ? (
        <div className="bg-[#121212] border border-border p-16 text-center text-zinc-500" data-testid="findings-empty">
          <ShieldAlert className="w-8 h-8 mx-auto mb-3 text-zinc-700" />
          {severity ? `No ${severity.toUpperCase()} findings found.` : "No findings yet — run a scan on Attack Surface."}
        </div>
      ) : (
        <div className="space-y-2" data-testid="findings-list">
          {data.findings.map((f, i) => {
            const isOpen = open === i;
            return (
              <div key={i} className="bg-[#121212] border border-border" data-testid={`finding-row-${i}`}>
                <button onClick={() => setOpen(isOpen ? null : i)} className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/[0.02] transition-colors">
                  <SeverityBadge severity={f.severity} />
                  <span className="font-mono text-xs shrink-0 w-10" style={{ color: SEV_COLORS[f.severity] || "#A1A1AA" }}>{f.cvss ?? "—"}</span>
                  <span className="text-sm text-white flex-1 truncate">{f.title}</span>
                  <span className="font-mono text-[11px] text-zinc-500 hidden md:inline truncate max-w-[180px]">{f.host}</span>
                  <ChevronDown className={`w-4 h-4 text-zinc-600 shrink-0 transition-transform ${isOpen ? "rotate-180" : ""}`} />
                </button>
                {isOpen && (
                  <div className="px-4 pb-4 pt-1 border-t border-border space-y-2 text-sm">
                    {f.component && <p className="font-mono text-xs text-zinc-400">component: <span className="text-zinc-300">{f.component}</span></p>}
                    {f.description && <p className="text-zinc-400 leading-relaxed">{f.description}</p>}
                    {f.proof && <pre className="bg-[#0a0a0a] border border-border p-2 text-[11px] text-zinc-400 overflow-x-auto whitespace-pre-wrap">{String(f.proof).slice(0, 600)}</pre>}
                    <div className="flex items-center gap-3 pt-1">
                      <span className="data-label">{f.ref || f.host}</span>
                      <span className="data-label">{fmt(f.created_at)}</span>
                      <Link to="/app/scanner" className="ml-auto data-label text-primary inline-flex items-center gap-1 hover:underline"><Radar className="w-3 h-3" /> open scanner</Link>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
