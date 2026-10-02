import { useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { toast } from "sonner";
import {
  Binary, Upload, Loader2, Cpu, FileCode2, Boxes, KeyRound, Globe,
  ShieldAlert, ShieldCheck, BadgeCheck, Bug, ScrollText, Bot, Fingerprint, FileDown,
} from "lucide-react";

const VERDICT_STYLE = {
  clean: "border-emerald-500/50 bg-emerald-500/10 text-emerald-400",
  low: "border-blue-500/50 bg-blue-500/10 text-blue-400",
  suspicious: "border-severity-high/50 bg-severity-high/10 text-severity-high",
  high: "border-severity-critical/50 bg-severity-critical/10 text-severity-critical",
};
const VERDICT_ICON = { clean: BadgeCheck, low: ShieldCheck, suspicious: ShieldAlert, high: Bug };

const Card = ({ icon: Icon, title, extra, children, testId }) => (
  <div className="border border-border bg-[#0c0c0c]" data-testid={testId}>
    <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border">
      <Icon className="w-4 h-4 text-primary" /><span className="data-label">{title}</span>
      {extra != null && <span className="ml-auto data-label text-zinc-500">{extra}</span>}
    </div>
    <div className="p-4">{children}</div>
  </div>
);
const KV = ({ k, v }) => (
  <div className="flex justify-between gap-3 border-b border-border/40 py-1.5">
    <span className="data-label shrink-0">{k}</span>
    <span className="font-mono text-xs text-white text-right break-all">{v ?? "—"}</span>
  </div>
);

export default function BinRE() {
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [saving, setSaving] = useState(false);

  const analyze = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setRes(null);
    try {
      const fd = new FormData(); fd.append("file", file);
      const { data } = await api.post("/offensive/binary/analyze", fd, { headers: { "Content-Type": "multipart/form-data" }, timeout: 180000 });
      setRes(data); toast.success(`Analyzed ${data.format} · ${data.verdict?.level}`);
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Analysis failed"); }
    finally { setBusy(false); e.target.value = ""; }
  };

  const savePdf = async () => {
    if (!res) return;
    setSaving(true);
    try {
      const { data } = await api.post("/offensive/binary/report", res, { responseType: "blob", timeout: 60000 });
      const u = URL.createObjectURL(data);
      const a = document.createElement("a"); a.href = u; a.download = `insafelabs-RE-${(res.filename || "binary")}.pdf`; a.click();
      URL.revokeObjectURL(u);
      toast.success("IOC + verdict PDF saved");
    } catch { toast.error("Report generation failed"); }
    finally { setSaving(false); }
  };

  const bin = res?.pe || res?.elf || {};
  const Vicon = res ? (VERDICT_ICON[res.verdict?.level] || ShieldAlert) : ShieldAlert;
  const packHint = res && res.entropy >= 7.2 ? "high — likely packed/encrypted" : res ? "normal" : "";

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="binre-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary"><Binary className="w-6 h-6 text-primary" /></div>
        <div>
          <p className="data-label mb-1">/ Reverse Engineering</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">Reverse Engineering Assistant</h1>
          <p className="text-sm text-zinc-500 mt-1">Triage an ELF / PE / Mach-O binary — format, arch, entropy/packing, imports, suspicious APIs, embedded URLs/secrets, and an AI capability summary.</p>
        </div>
      </div>

      <label className="flex items-center justify-center gap-2 border border-dashed border-zinc-700 py-6 text-sm text-zinc-400 cursor-pointer hover:border-primary/50 hover:text-primary transition-colors bg-[#121212]" data-testid="binre-upload-label">
        <Upload className="w-4 h-4" /> {busy ? "Analyzing binary…" : "Drop / choose a binary (.exe .dll .so ELF Mach-O — up to 40 MB)"}
        <input type="file" className="hidden" onChange={analyze} data-testid="binre-upload" disabled={busy} />
      </label>

      {res && (
        <div className="space-y-4" data-testid="binre-result">
          <div className="flex justify-end">
            <button onClick={savePdf} disabled={saving} data-testid="binre-save-pdf" className="border border-border px-3 py-1.5 text-xs font-mono uppercase tracking-wider text-zinc-300 hover:border-primary/50 hover:text-primary transition-colors inline-flex items-center gap-1.5 disabled:opacity-60">
              {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileDown className="w-3.5 h-3.5" />} Save IOC + Verdict PDF
            </button>
          </div>
          <div className={`border p-4 flex items-start gap-3 ${VERDICT_STYLE[res.verdict?.level] || VERDICT_STYLE.low}`} data-testid="binre-verdict">
            <Vicon className="w-6 h-6 shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 flex-wrap">
                <p className="font-heading text-base font-bold">{res.verdict?.label}</p>
                <span className="font-mono text-xs px-2 py-0.5 border border-current">risk {res.verdict?.score}/100</span>
                <span className="font-mono text-xs px-2 py-0.5 border border-current">{res.format}</span>
              </div>
              <ul className="mt-2 space-y-1 text-xs">
                {(res.verdict?.reasons || []).map((r, i) => <li key={i} className="flex items-start gap-1.5"><span className="mt-0.5">›</span> {r}</li>)}
                {(res.verdict?.reasons || []).length === 0 && <li className="text-zinc-400">No strong malicious indicators.</li>}
              </ul>
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card icon={Fingerprint} title="File Identity" testId="binre-identity">
              <KV k="Filename" v={res.filename} />
              <KV k="Format" v={res.format} />
              <KV k="Size" v={`${res.size_kb} KB`} />
              <KV k="Entropy" v={`${res.entropy} (${packHint})`} />
              <KV k="Arch / Machine" v={bin.arch || bin.machine} />
              <KV k="Bits / Subsystem" v={bin.bits || bin.subsystem} />
              <KV k="SHA-256" v={res.sha256 ? res.sha256.slice(0, 40) + "…" : "—"} />
            </Card>

            <Card icon={Boxes} title="Libraries / Sections" testId="binre-struct">
              {(bin.libraries || []).length > 0 && (
                <div className="mb-3">
                  <p className="data-label mb-1">Libraries</p>
                  <div className="flex flex-wrap gap-1.5">{bin.libraries.map((l, i) => <span key={i} className="font-mono text-[10px] border border-border px-2 py-0.5 text-zinc-400">{l}</span>)}</div>
                </div>
              )}
              <p className="data-label mb-1">Sections</p>
              <div className="max-h-40 overflow-y-auto space-y-0.5 font-mono text-[10px]">
                {(bin.sections || []).map((s, i) => (
                  <div key={i} className="flex justify-between gap-2 text-zinc-400">
                    <span className="truncate">{s.name}</span>
                    <span className="shrink-0">{s.size}b{s.entropy != null ? ` · H${s.entropy}` : ""}</span>
                  </div>
                ))}
                {(bin.sections || []).length === 0 && <p className="text-zinc-600">No section data.</p>}
              </div>
            </Card>
          </div>

          {(res.suspicious_apis || []).length > 0 && (
            <Card icon={Cpu} title="Suspicious API References" extra={res.suspicious_apis.length} testId="binre-apis">
              <div className="flex flex-wrap gap-1.5">
                {res.suspicious_apis.map((a, i) => <span key={i} className="font-mono text-[11px] border border-severity-high/40 bg-severity-high/10 text-severity-high px-2 py-1">{a}</span>)}
              </div>
            </Card>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            {(bin.imports || []).length > 0 && (
              <Card icon={FileCode2} title="Imports" extra={bin.imports.length} testId="binre-imports">
                <div className="max-h-52 overflow-y-auto flex flex-wrap gap-1.5">
                  {bin.imports.map((im, i) => <span key={i} className="font-mono text-[10px] border border-border px-1.5 py-0.5 text-zinc-500">{im}</span>)}
                </div>
              </Card>
            )}
            <Card icon={Globe} title="URLs / IPs" extra={(res.urls || []).length + (res.ips || []).length} testId="binre-net">
              <div className="max-h-52 overflow-y-auto space-y-1 font-mono text-[11px]">
                {(res.urls || []).map((u, i) => <div key={"u" + i} className="text-primary truncate" title={u}>{u}</div>)}
                {(res.ips || []).map((ip, i) => <div key={"i" + i} className="text-blue-400">{ip}</div>)}
                {(res.urls || []).length === 0 && (res.ips || []).length === 0 && <p className="text-zinc-600">None found.</p>}
              </div>
            </Card>
          </div>

          {(res.secrets || []).length > 0 && (
            <Card icon={KeyRound} title="Embedded Secrets / Keys" extra={res.secrets.length} testId="binre-secrets">
              <div className="space-y-1.5">
                {res.secrets.map((s, i) => (
                  <div key={i} className="flex items-center justify-between gap-2 border-b border-border/40 pb-1.5">
                    <span className="text-xs text-white">{s.type}</span>
                    <span className="font-mono text-[10px] text-severity-critical truncate max-w-[50%]">{s.match}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {res.ai_summary && (
            <Card icon={Bot} title="AI Capability Assessment" testId="binre-ai">
              <div className="font-mono text-[13px] text-zinc-200 whitespace-pre-wrap leading-relaxed">{res.ai_summary}</div>
            </Card>
          )}

          {(res.strings_sample || []).length > 0 && (
            <Card icon={ScrollText} title="Interesting Strings" extra={res.string_count} testId="binre-strings">
              <div className="max-h-52 overflow-y-auto space-y-0.5 font-mono text-[10px] text-zinc-500">
                {res.strings_sample.map((s, i) => <div key={i} className="truncate">{s}</div>)}
              </div>
            </Card>
          )}

          {(res.notes || []).length > 0 && (
            <div className="bg-[#0a0a0a] border border-border p-4">
              <p className="data-label mb-2">Notes</p>
              {res.notes.map((n, i) => <p key={i} className="font-mono text-[11px] text-zinc-500">• {n}</p>)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
