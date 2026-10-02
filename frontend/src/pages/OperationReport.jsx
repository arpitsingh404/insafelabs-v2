import { useEffect, useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { toast } from "sonner";
import {
  FileText, Radar, Share2, Binary, Download, Loader2, RefreshCw,
  CheckSquare, Square, ShieldAlert, Image as ImageIcon, X,
} from "lucide-react";

const POSTURE_COLOR = {
  critical: "text-severity-critical", high: "text-severity-high",
  medium: "text-severity-medium", low: "text-severity-low", info: "text-zinc-400",
};
const VERDICT_COLOR = {
  high: "text-severity-critical", suspicious: "text-severity-medium",
  low: "text-severity-low", clean: "text-emerald-400",
};

const fmtDate = (s) => { try { return new Date(s).toLocaleString(); } catch { return s || "—"; } };

export default function OperationReport() {
  const [sources, setSources] = useState({ recon: [], network: [], binaries: [] });
  const [sel, setSel] = useState({ recon: new Set(), network: new Set(), binaries: new Set() });
  const [title, setTitle] = useState("");
  const [operator, setOperator] = useState("");
  const [coverNotes, setCoverNotes] = useState("");
  const [logo, setLogo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [gen, setGen] = useState(false);

  const load = async () => {
    setLoading(true);
    try { const { data } = await api.get("/offensive/operation/sources"); setSources(data); }
    catch { toast.error("Failed to load sources"); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const toggle = (kind, id) => setSel((s) => {
    const n = new Set(s[kind]); n.has(id) ? n.delete(id) : n.add(id); return { ...s, [kind]: n };
  });
  const selectAll = (kind, ids) => setSel((s) => {
    const all = ids.every((i) => s[kind].has(i));
    return { ...s, [kind]: all ? new Set() : new Set(ids) };
  });
  const total = sel.recon.size + sel.network.size + sel.binaries.size;

  const onLogo = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (!f.type.startsWith("image/")) { toast.error("Please upload an image file"); return; }
    if (f.size > 2 * 1024 * 1024) { toast.error("Logo must be smaller than 2MB"); return; }
    const reader = new FileReader();
    reader.onload = () => setLogo(reader.result);
    reader.readAsDataURL(f);
  };

  const generate = async () => {
    if (!total) { toast.error("Select at least one result"); return; }
    setGen(true);
    try {
      const { data } = await api.post("/offensive/operation/report", {
        title, operator, cover_notes: coverNotes, logo,
        recon_ids: [...sel.recon], network_ids: [...sel.network], binary_ids: [...sel.binaries],
      }, { responseType: "blob", timeout: 90000 });
      const u = URL.createObjectURL(data);
      const a = document.createElement("a");
      a.href = u; a.download = "insafelabs-operation-report.pdf"; a.click();
      setTimeout(() => URL.revokeObjectURL(u), 5000);
      toast.success("Operation dossier PDF ready");
    } catch (e) {
      toast.error(formatApiError(e?.response?.data?.detail) || "Report generate fail");
    } finally { setGen(false); }
  };

  const Row = ({ kind, id, active, children }) => (
    <button type="button" onClick={() => toggle(kind, id)} data-testid={`op-item-${kind}-${id}`}
      className={`w-full flex items-start gap-3 px-3 py-2.5 text-left border transition-colors ${
        active ? "border-primary/60 bg-primary/[0.06]" : "border-border hover:border-primary/30 hover:bg-white/[0.02]"}`}>
      {active ? <CheckSquare className="w-4 h-4 text-primary mt-0.5 shrink-0" /> : <Square className="w-4 h-4 text-zinc-600 mt-0.5 shrink-0" />}
      <div className="min-w-0 flex-1">{children}</div>
    </button>
  );

  const Column = ({ kind, icon: Icon, label, items, empty }) => {
    const ids = items.map((i) => i.id);
    const allOn = ids.length > 0 && ids.every((i) => sel[kind].has(i));
    return (
      <div className="border border-border bg-[#121212] flex flex-col" data-testid={`op-col-${kind}`}>
        <div className="flex items-center gap-2 px-4 h-12 border-b border-border">
          <Icon className="w-4 h-4 text-primary" />
          <span className="font-heading font-bold text-sm text-white">{label}</span>
          <span className="data-label ml-1">{items.length}</span>
          {ids.length > 0 && (
            <button onClick={() => selectAll(kind, ids)} data-testid={`op-selectall-${kind}`}
              className="ml-auto text-[10px] font-mono uppercase tracking-widest text-zinc-500 hover:text-primary">
              {allOn ? "clear" : "all"}
            </button>
          )}
        </div>
        <div className="p-2 space-y-2 overflow-y-auto" style={{ maxHeight: "56vh" }}>
          {items.length === 0 ? (
            <p className="text-xs text-zinc-600 px-2 py-6 text-center">{empty}</p>
          ) : items.map((it) => (
            <Row key={it.id} kind={kind} id={it.id} active={sel[kind].has(it.id)}>{kindRow(kind, it)}</Row>
          ))}
        </div>
      </div>
    );
  };

  const kindRow = (kind, it) => {
    if (kind === "recon") return (
      <>
        <p className="text-sm text-white font-medium truncate">{it.host || it.target}</p>
        <p className="text-[11px] font-mono text-zinc-500 flex items-center gap-2 flex-wrap">
          <span className={POSTURE_COLOR[it.posture] || "text-zinc-400"}>{(it.posture || "info").toUpperCase()}</span>
          <span>risk {it.risk_score ?? 0}</span>
          <span>{it.finding_count ?? 0} findings</span>
        </p>
        <p className="text-[10px] text-zinc-600 mt-0.5">{fmtDate(it.created_at)}</p>
      </>
    );
    if (kind === "network") return (
      <>
        <p className="text-sm text-white font-medium truncate">{it.target}</p>
        <p className="text-[11px] font-mono text-zinc-500">{it.hosts_up ?? 0}/{it.scanned ?? 0} hosts up</p>
        <p className="text-[10px] text-zinc-600 mt-0.5">{fmtDate(it.created_at)}</p>
      </>
    );
    const lvl = it.verdict?.level;
    return (
      <>
        <p className="text-sm text-white font-medium truncate">{it.filename || "binary"}</p>
        <p className="text-[11px] font-mono text-zinc-500 flex items-center gap-2 flex-wrap">
          <span className="uppercase">{it.format}</span>
          {lvl && <span className={`inline-flex items-center gap-1 ${VERDICT_COLOR[lvl] || "text-zinc-400"}`}><ShieldAlert className="w-3 h-3" />{lvl}</span>}
        </p>
        <p className="text-[10px] text-zinc-600 mt-0.5">{fmtDate(it.created_at)}</p>
      </>
    );
  };

  return (
    <div className="p-5 md:p-8 space-y-6 pb-32" data-testid="operation-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary"><FileText className="w-6 h-6 text-primary" /></div>
        <div className="flex-1">
          <p className="data-label mb-1">/ Reporting · Unified Dossier</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">Operation Report</h1>
          <p className="text-sm text-zinc-500 mt-1">Consolidate Attack Surface scans, Network Maps and Reverse-Eng findings into one professional PDF dossier. Select results below and hit <b className="text-primary">Generate Dossier</b>.</p>
        </div>
        <button onClick={load} data-testid="op-refresh" className="border border-border px-3 py-2 text-xs font-mono uppercase text-zinc-400 hover:text-primary hover:border-primary/50 inline-flex items-center gap-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Report branding */}
      <div className="border border-border bg-[#121212] p-4 grid md:grid-cols-[220px_1fr] gap-4" data-testid="op-branding">
        <div>
          <p className="data-label mb-2 flex items-center gap-1.5"><ImageIcon className="w-3.5 h-3.5 text-primary" /> Cover Logo</p>
          {logo ? (
            <div className="relative inline-block">
              <img src={logo} alt="logo" className="max-h-24 max-w-[200px] border border-border bg-white/5 p-2" data-testid="op-logo-preview" />
              <button onClick={() => setLogo(null)} data-testid="op-logo-remove" className="absolute -top-2 -right-2 w-6 h-6 bg-black border border-border flex items-center justify-center text-zinc-400 hover:text-severity-critical"><X className="w-3.5 h-3.5" /></button>
            </div>
          ) : (
            <label className="flex flex-col items-center justify-center gap-2 border border-dashed border-border h-24 cursor-pointer hover:border-primary/50 transition-colors text-zinc-500" data-testid="op-logo-drop">
              <ImageIcon className="w-5 h-5" />
              <span className="text-[11px] font-mono">upload logo (PNG/JPG)</span>
              <input type="file" accept="image/*" onChange={onLogo} data-testid="op-logo-input" className="hidden" />
            </label>
          )}
        </div>
        <div>
          <p className="data-label mb-2">Cover Notes / Scope</p>
          <textarea value={coverNotes} onChange={(e) => setCoverNotes(e.target.value)} data-testid="op-cover-notes"
            placeholder="Engagement scope, rules of engagement, client name, disclaimer… (appears on the report cover)"
            className="w-full bg-[#0a0a0a] border border-border px-3 py-2 text-sm text-white placeholder:text-zinc-600 focus:border-primary/50 outline-none min-h-[92px] resize-y" />
        </div>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 text-zinc-500 py-16 justify-center"><Loader2 className="w-5 h-5 animate-spin" /> Loading sources…</div>
      ) : (
        <div className="grid lg:grid-cols-3 gap-4">
          <Column kind="recon" icon={Radar} label="Attack Surface" items={sources.recon} empty="No completed scans — run a scan on Attack Surface." />
          <Column kind="network" icon={Share2} label="Network Maps" items={sources.network} empty="No network maps — run a scan on Network Map." />
          <Column kind="binaries" icon={Binary} label="Reverse Eng" items={sources.binaries} empty="No binary analyses — analyze a file on Reverse Eng." />
        </div>
      )}

      {/* sticky action bar */}
      <div className="fixed bottom-16 md:bottom-0 left-0 right-0 md:left-64 z-30 glass-header border-t border-border px-5 md:px-8 py-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <input value={title} onChange={(e) => setTitle(e.target.value)} data-testid="op-title-input"
            placeholder="Report title (e.g. Q2 External Assessment)"
            className="flex-1 bg-[#0a0a0a] border border-border px-3 py-2 text-sm text-white placeholder:text-zinc-600 focus:border-primary/50 outline-none" />
          <input value={operator} onChange={(e) => setOperator(e.target.value)} data-testid="op-operator-input"
            placeholder="Operator / analyst"
            className="sm:w-48 bg-[#0a0a0a] border border-border px-3 py-2 text-sm text-white placeholder:text-zinc-600 focus:border-primary/50 outline-none" />
          <span className="text-xs font-mono text-zinc-500 whitespace-nowrap" data-testid="op-selected-count">{total} selected</span>
          <button onClick={generate} disabled={gen || !total} data-testid="op-generate"
            className="bg-primary text-black font-semibold px-5 py-2 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-50 glow-primary whitespace-nowrap">
            {gen ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            {gen ? "Building…" : "Generate Dossier"}
          </button>
        </div>
      </div>
    </div>
  );
}
