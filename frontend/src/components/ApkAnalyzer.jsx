import { useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { toast } from "sonner";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  Upload, Link2, Loader2, ShieldCheck, ShieldAlert, KeyRound,
  FileArchive, Boxes, Fingerprint, Globe, FileCode2, Package,
  ScrollText, Radar, BadgeCheck, Bug,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm focus:outline-none focus:border-primary transition-colors";
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
      <Icon className="w-4 h-4 text-primary" />
      <span className="data-label">{title}</span>
      {extra && <span className="ml-auto data-label text-zinc-500">{extra}</span>}
    </div>
    <div className="p-4">{children}</div>
  </div>
);

const KV = ({ k, v }) => (
  <div className="flex justify-between gap-3 border-b border-border/40 py-1.5">
    <span className="data-label shrink-0">{k}</span>
    <span className="font-mono text-xs text-white text-right truncate" title={String(v ?? "")}>{v ?? "—"}</span>
  </div>
);

// Shared helper — upload an APK File/Blob to the backend static analyzer.
export async function analyzeApkFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  const { data } = await api.post("/redteam/apk/upload", fd, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 180000,
  });
  return data;
}

// Shared result renderer — reused by the Mobile page and the USB Device Bridge.
export function ApkResult({ res }) {
  if (!res) return null;
  const app = res.app || {};
  const cert = res.certificates?.[0];
  const ep = res.endpoints || {};
  const files = res.files || {};
  const cc = res.components_count || {};
  const Vicon = VERDICT_ICON[res.verdict?.level] || ShieldAlert;

  return (
    <div className="space-y-4" data-testid="apk-result">
      {/* Verdict */}
      <div className={`border p-4 flex items-start gap-3 ${VERDICT_STYLE[res.verdict?.level] || VERDICT_STYLE.low}`} data-testid="apk-verdict">
        <Vicon className="w-6 h-6 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <p className="font-heading text-base font-bold">{res.verdict?.label}</p>
            <span className="font-mono text-xs px-2 py-0.5 border border-current">risk {res.verdict?.score}/100</span>
            <SeverityBadge severity={res.posture} />
          </div>
          <ul className="mt-2 space-y-1 text-xs text-zinc-300">
            {(res.verdict?.reasons || []).map((r, i) => (
              <li key={i} className="flex items-start gap-1.5"><span className="text-current mt-0.5">›</span> {r}</li>
            ))}
          </ul>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card icon={Package} title="App Identity" testId="apk-identity">
          <KV k="Name" v={app.app_name} />
          <KV k="Package" v={app.package} />
          <KV k="Version" v={`${app.version_name || "?"} (${app.version_code || "?"})`} />
          <KV k="Min / Target SDK" v={`${app.min_sdk || "?"} / ${app.target_sdk || "?"}`} />
          <KV k="Main activity" v={app.main_activity} />
          <KV k="Size" v={`${res.size_kb} KB`} />
        </Card>

        <Card icon={Fingerprint} title="Signing Certificate — who built it" testId="apk-cert">
          {cert ? (
            <>
              <KV k="Signed by" v={cert.subject} />
              <KV k="Issuer" v={cert.issuer} />
              <KV k="Valid" v={`${(cert.valid_from || "").slice(0, 10)} → ${(cert.valid_to || "").slice(0, 10)}`} />
              <KV k="SHA-256" v={cert.sha256 ? cert.sha256.slice(0, 32) + "…" : "—"} />
              <div className="flex gap-2 mt-2">
                {cert.is_debug && <span className="font-mono text-[10px] border border-severity-critical/50 text-severity-critical px-2 py-0.5">DEBUG-SIGNED (not official)</span>}
                {cert.self_signed && <span className="font-mono text-[10px] border border-severity-medium/50 text-severity-medium px-2 py-0.5">self-signed</span>}
                {!cert.is_debug && !cert.self_signed && <span className="font-mono text-[10px] border border-emerald-500/50 text-emerald-400 px-2 py-0.5">CA-signed</span>}
              </div>
            </>
          ) : <p className="text-sm text-zinc-500">Certificate could not be parsed (v2/v3-only signing or unsigned).</p>}
        </Card>
      </div>

      <Card icon={ShieldAlert} title="Permissions" extra={`${(app.permissions || []).length} total · ${(res.dangerous_permissions || []).length} dangerous`} testId="apk-perms">
        {(app.permissions || []).length === 0 ? <p className="text-sm text-zinc-500">No permissions declared.</p> : (
          <div className="flex flex-wrap gap-1.5 max-h-40 overflow-y-auto">
            {(app.permissions || []).map((p) => {
              const short = p.split(".").pop();
              const danger = (res.dangerous_permissions || []).includes(short);
              return <span key={p} className={`font-mono text-[10px] px-2 py-1 border ${danger ? "border-severity-high/50 bg-severity-high/10 text-severity-high" : "border-border text-zinc-400"}`}>{short}</span>;
            })}
          </div>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card icon={Boxes} title="Components (attack surface)" extra={`${res.flags?.exported_components || 0} exported`} testId="apk-components">
          <div className="grid grid-cols-2 gap-2 font-mono text-xs">
            <div className="border border-border bg-[#0a0a0a] p-2"><p className="data-label">Activities</p><p className="text-white text-lg">{cc.activities || 0}</p></div>
            <div className="border border-border bg-[#0a0a0a] p-2"><p className="data-label">Services</p><p className="text-white text-lg">{cc.services || 0}</p></div>
            <div className="border border-border bg-[#0a0a0a] p-2"><p className="data-label">Receivers</p><p className="text-white text-lg">{cc.receivers || 0}</p></div>
            <div className="border border-border bg-[#0a0a0a] p-2"><p className="data-label">Providers</p><p className="text-white text-lg">{cc.providers || 0}</p></div>
          </div>
        </Card>

        <Card icon={FileArchive} title="Files inside the APK" extra={`${files.total || 0} files`} testId="apk-files">
          <div className="grid grid-cols-2 gap-2 text-xs mb-3">
            <KV k="DEX files" v={files.dex} />
            <KV k="Native libs" v={files.native_libs} />
            <KV k="ABIs" v={(files.abis || []).join(", ") || "none"} />
            <KV k="Assets" v={files.assets} />
          </div>
          <div className="max-h-32 overflow-y-auto space-y-0.5">
            {(files.top_files || []).map((f, i) => (
              <div key={i} className="flex justify-between gap-2 font-mono text-[10px] text-zinc-400"><span className="truncate">{f.name}</span><span className="shrink-0">{f.size_kb}KB</span></div>
            ))}
          </div>
        </Card>
      </div>

      {(res.secrets || []).length > 0 && (
        <Card icon={KeyRound} title="Hardcoded Secrets / API Keys" extra={`${res.secrets.length}`} testId="apk-secrets">
          <div className="space-y-1.5">
            {res.secrets.map((s, i) => (
              <div key={i} className="flex items-center justify-between gap-2 border-b border-border/40 pb-1.5">
                <span className="text-xs text-white">{s.type}</span>
                <span className="font-mono text-[10px] text-zinc-500">{s.source}</span>
                <span className="font-mono text-[10px] text-severity-critical truncate max-w-[40%]">{s.match}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card icon={Globe} title="API Endpoints & Docs" extra={`${(ep.api || []).length} api`} testId="apk-endpoints">
          {(ep.api || []).length === 0 && (ep.docs || []).length === 0 ? <p className="text-sm text-zinc-500">No API/doc URLs found.</p> : (
            <div className="space-y-1 max-h-44 overflow-y-auto font-mono text-[11px]">
              {(ep.api || []).map((u, i) => <div key={"a" + i} className="text-primary truncate" title={u}>API · {u}</div>)}
              {(ep.docs || []).map((u, i) => <div key={"d" + i} className="text-blue-400 truncate" title={u}>DOC · {u}</div>)}
            </div>
          )}
        </Card>
        <Card icon={FileCode2} title="Domains contacted" extra={`${(ep.domains || []).length}`} testId="apk-domains">
          <div className="flex flex-wrap gap-1.5 max-h-44 overflow-y-auto">
            {(ep.domains || []).map((d, i) => <span key={i} className="font-mono text-[10px] border border-border px-2 py-1 text-zinc-400">{d}</span>)}
            {(ep.domains || []).length === 0 && <p className="text-sm text-zinc-500">None.</p>}
          </div>
        </Card>
      </div>

      {(res.trackers || []).length > 0 && (
        <Card icon={Radar} title="Trackers / SDKs detected" extra={`${res.trackers.length}`} testId="apk-trackers">
          <div className="flex flex-wrap gap-2">
            {res.trackers.map((t, i) => <span key={i} className="font-mono text-[11px] border border-severity-medium/40 bg-severity-medium/10 text-severity-medium px-2 py-1">{t}</span>)}
          </div>
        </Card>
      )}

      <Card icon={ScrollText} title="Security Findings" extra={`${res.finding_count}`} testId="apk-findings">
        {(res.findings || []).length === 0 ? <p className="text-sm text-emerald-400/80">No security findings.</p> : (
          <div className="space-y-2">
            {res.findings.map((f, i) => (
              <div key={i} className="border-l-2 border-border pl-3 py-1" data-testid={`apk-finding-${i}`}>
                <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-sm text-white">{f.title}</span></div>
                <p className="text-xs text-zinc-500 mt-0.5">{f.evidence}</p>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

export function ApkAnalyzer() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);

  const analyzeUrl = async (e) => {
    e.preventDefault();
    if (!url.trim()) { toast.error("Enter an APK URL or upload a file"); return; }
    setBusy(true); setRes(null);
    try {
      const { data } = await api.post("/redteam/apk/url", { apk_url: url.trim() }, { timeout: 180000 });
      setRes(data); toast.success(`Analyzed — ${data.finding_count} findings`);
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Analysis failed"); }
    finally { setBusy(false); }
  };

  const analyzeFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setRes(null);
    try {
      const data = await analyzeApkFile(file);
      setRes(data); toast.success(`Analyzed ${data.app?.package || "APK"} — ${data.finding_count} findings`);
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Analysis failed"); }
    finally { setBusy(false); e.target.value = ""; }
  };

  return (
    <div className="bg-[#121212] border border-border" data-testid="apk-analyzer">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-border">
        <div className="w-10 h-10 border border-primary/40 bg-primary/10 flex items-center justify-center"><FileArchive className="w-5 h-5 text-primary" /></div>
        <div>
          <p className="data-label">Static APK Analyzer · mini-MobSF</p>
          <h3 className="font-heading text-lg font-semibold">Upload an APK — get everything inside it</h3>
        </div>
      </div>

      <div className="p-6 space-y-3">
        <form onSubmit={analyzeUrl} className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Link2 className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input className={inputCls + " pl-9"} value={url} onChange={(e) => setUrl(e.target.value)} data-testid="apk-url" placeholder="https://…/app.apk (or upload below)" />
          </div>
          <button type="submit" disabled={busy} data-testid="apk-url-submit" className="bg-primary text-black font-semibold px-5 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />} Analyze
          </button>
        </form>
        <label className="flex items-center justify-center gap-2 border border-dashed border-zinc-700 py-4 text-sm text-zinc-400 cursor-pointer hover:border-primary/50 hover:text-primary transition-colors" data-testid="apk-upload-label">
          <Upload className="w-4 h-4" /> {busy ? "Analyzing… (large APKs take a moment)" : "Drop / choose an .apk file to analyze"}
          <input type="file" accept=".apk,application/vnd.android.package-archive" className="hidden" onChange={analyzeFile} data-testid="apk-upload" disabled={busy} />
        </label>
      </div>

      {res && <div className="px-6 pb-6"><ApkResult res={res} /></div>}
    </div>
  );
}
