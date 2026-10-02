import { useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { Link2, Loader2, ServerCog, ShieldCheck, Send, Radar, Globe } from "lucide-react";

const inputCls = "flex-1 bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const areaCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors min-h-[70px] resize-y";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm whitespace-nowrap";

function Panel({ icon: Icon, title, kicker, children, right, ...rest }) {
  return (
    <div className="bg-[#121212] border border-border p-5" {...rest}>
      <div className="flex items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2.5">
          <Icon className="w-4 h-4 text-primary" />
          <div>{kicker ? <p className="data-label">{kicker}</p> : null}<h3 className="font-heading text-base font-semibold">{title}</h3></div>
        </div>
        {right}
      </div>
      {children}
    </div>
  );
}

const gradeColor = (g) => ({ "A+": "#22C55E", A: "#22C55E", B: "#3B82F6", C: "#F59E0B", D: "#F97316", F: "#EF4444" }[g] || "#71717A");

export default function WebInspector() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState("");
  const [insp, setInsp] = useState(null);
  const [fp, setFp] = useState(null);
  const [cors, setCors] = useState(null);

  const [method, setMethod] = useState("GET");
  const [reqUrl, setReqUrl] = useState("");
  const [headers, setHeaders] = useState("");
  const [body, setBody] = useState("");
  const [resp, setResp] = useState(null);

  const call = async (kind) => {
    if (!url.trim()) return toast.error("Enter a URL");
    setBusy(kind);
    try {
      if (kind === "inspect") setInsp((await api.post("/toolkit/http-inspect", { url: url.trim() })).data);
      else if (kind === "fingerprint") setFp((await api.post("/toolkit/fingerprint", { url: url.trim() })).data);
      else if (kind === "cors") setCors((await api.post("/toolkit/cors-test", { url: url.trim() })).data);
    } catch (e) { toast.error(formatApiError(e.response?.data?.detail) || `${kind} failed`); }
    finally { setBusy(""); }
  };

  const send = async () => {
    if (!reqUrl.trim()) return toast.error("Enter a request URL");
    setBusy("send");
    try {
      setResp((await api.post("/toolkit/http-request", { method, url: reqUrl.trim(), headers, body })).data);
    } catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Request failed"); }
    finally { setBusy(""); }
  };

  const L = (k) => busy === k;

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="webinspector-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><Globe className="w-7 h-7 text-primary" /> Web Inspector</h1>
        <p className="text-sm text-zinc-500 mt-1.5">Headers + TLS grade, tech/WAF fingerprint, CORS misconfig and raw request replay.</p>
      </header>

      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="webinspect-url" placeholder="https://target.tld" className={inputCls} />
        <div className="flex flex-wrap gap-2">
          <button onClick={() => call("inspect")} disabled={!!busy} data-testid="webinspect-run" className={btnCls}>
            {L("inspect") ? <Loader2 className="w-4 h-4 animate-spin" /> : <Link2 className="w-4 h-4" />} Inspect
          </button>
          <button onClick={() => call("fingerprint")} disabled={!!busy} data-testid="webinspect-fingerprint" className={btnCls}>
            {L("fingerprint") ? <Loader2 className="w-4 h-4 animate-spin" /> : <ServerCog className="w-4 h-4" />} Fingerprint
          </button>
          <button onClick={() => call("cors")} disabled={!!busy} data-testid="webinspect-cors" className={btnCls}>
            {L("cors") ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />} CORS
          </button>
        </div>
      </div>

      {insp && (
        <Panel icon={Link2} kicker="HTTP + TLS" title="Header inspection" data-testid="webinspect-result"
          right={insp.security ? <span className="font-mono text-lg font-bold" style={{ color: gradeColor(insp.security.grade) }}>{insp.security.grade}</span> : null}>
          <div className="grid sm:grid-cols-3 gap-3 mb-3 font-mono text-xs">
            <Stat k="Status" v={insp.status} />
            <Stat k="Server" v={insp.server || "—"} />
            <Stat k="Latency" v={`${insp.elapsed_ms} ms`} />
          </div>
          {insp.security && (
            <div className="mb-3">
              <p className="data-label mb-1">Missing security headers ({(insp.security.missing || []).length})</p>
              <div className="flex flex-wrap gap-1.5">
                {(insp.security.missing || []).length === 0
                  ? <span className="text-xs text-emerald-400">all present</span>
                  : insp.security.missing.map((m, i) => <span key={i} className="text-[11px] font-mono border border-severity-high/40 text-severity-high px-2 py-0.5">{m}</span>)}
              </div>
            </div>
          )}
          {insp.tls && !insp.tls.error && (
            <div className="font-mono text-xs space-y-1 border-t border-border pt-3">
              <Row k="TLS" v={`${insp.tls.tls_version || "?"} · ${insp.tls.cipher || "?"}`} />
              <Row k="Issuer" v={insp.tls.issuer || "—"} />
              <Row k="Valid to" v={`${insp.tls.valid_to || "?"} (${insp.tls.days_left} days)`} />
            </div>
          )}
          <details className="mt-3">
            <summary className="data-label cursor-pointer">response headers ({Object.keys(insp.headers || {}).length})</summary>
            <pre className="mt-2 text-[11px] font-mono text-zinc-400 whitespace-pre-wrap break-all max-h-64 overflow-y-auto">{Object.entries(insp.headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}</pre>
          </details>
        </Panel>
      )}

      {fp && (
        <Panel icon={ServerCog} kicker="Fingerprint" title="Tech & WAF" data-testid="webinspect-fp">
          <div className="flex flex-wrap gap-1.5 mb-3">
            {(fp.waf || []).length === 0 ? <span className="text-xs text-zinc-600">No WAF/CDN detected</span>
              : fp.waf.map((w, i) => <span key={i} className="text-[11px] font-mono border border-severity-critical/40 text-severity-critical px-2 py-0.5">{w}</span>)}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {(fp.tech || []).map((t, i) => (
              <span key={i} className="text-[11px] font-mono border border-border px-2 py-0.5 text-zinc-300" title={t.evidence}>{t.name} <span className="text-zinc-600">{t.category}</span></span>
            ))}
            {(fp.tech || []).length === 0 && <span className="text-xs text-zinc-600">No technologies matched.</span>}
          </div>
        </Panel>
      )}

      {cors && (
        <Panel icon={ShieldCheck} kicker="CORS" title="Misconfiguration tester" data-testid="webinspect-cors-result"
          right={<span className="data-label" style={{ color: cors.vulnerable ? "#EF4444" : "#22C55E" }}>{cors.vulnerable ? "VULNERABLE" : "no high-risk finding"}</span>}>
          {(cors.findings || []).map((f, i) => (
            <p key={i} className="text-xs mb-1.5" style={{ color: f.severity === "LOW" ? "#71717A" : "#EF4444" }}>[{f.severity}] {f.detail}</p>
          ))}
          <div className="mt-2 overflow-x-auto">
            <table className="w-full text-[11px] font-mono">
              <thead><tr className="text-zinc-500 text-left"><th className="py-1 pr-3">test</th><th className="pr-3">origin</th><th className="pr-3">ACAO</th><th>credentials</th></tr></thead>
              <tbody>
                {(cors.tests || []).map((t, i) => (
                  <tr key={i} className="border-t border-border/40 text-zinc-400">
                    <td className="py-1 pr-3">{t.test}</td><td className="pr-3 truncate max-w-[220px]">{t.origin}</td>
                    <td className="pr-3">{t.error ? "—" : (t.acao || "none")}</td><td>{t.acac || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Panel icon={Send} kicker="Replay" title="Raw request builder">
        <div className="flex flex-col sm:flex-row gap-2 mb-2">
          <select value={method} onChange={(e) => setMethod(e.target.value)} data-testid="webinspect-method"
            className="bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary">
            {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <input value={reqUrl} onChange={(e) => setReqUrl(e.target.value)} data-testid="webinspect-req-url" placeholder="https://target.tld/api" className={inputCls} />
          <button onClick={send} disabled={busy === "send"} data-testid="webinspect-send" className={btnCls}>
            {busy === "send" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />} Send
          </button>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <textarea value={headers} onChange={(e) => setHeaders(e.target.value)} data-testid="webinspect-headers" placeholder={"Header-Name: value\n(one per line)"} className={areaCls} />
          <textarea value={body} onChange={(e) => setBody(e.target.value)} data-testid="webinspect-body" placeholder="request body (optional)" className={areaCls} />
        </div>

        {resp && (
          <div className="mt-3 border border-border bg-[#0a0a0a] p-3" data-testid="webinspect-response">
            <div className="grid sm:grid-cols-4 gap-2 font-mono text-xs mb-2">
              <Stat k="Status" v={`${resp.status} ${resp.reason || ""}`} />
              <Stat k="Time" v={`${resp.elapsed_ms} ms`} />
              <Stat k="Size" v={`${resp.size_bytes} B`} />
              <Stat k="Type" v={resp.content_type || "—"} />
            </div>
            <pre className="text-[11px] font-mono text-zinc-300 whitespace-pre-wrap break-all max-h-72 overflow-y-auto">{resp.body || "(empty body)"}{resp.truncated ? "\n… [truncated]" : ""}</pre>
          </div>
        )}
      </Panel>
    </div>
  );
}

const Stat = ({ k, v }) => (
  <div className="border border-border bg-[#0a0a0a] px-3 py-2">
    <p className="data-label">{k}</p>
    <p className="text-zinc-200 mt-0.5 truncate">{v}</p>
  </div>
);

const Row = ({ k, v }) => (
  <div className="flex items-center justify-between gap-3 border-b border-border/40 pb-1">
    <span className="text-zinc-500">{k}</span>
    <span className="truncate max-w-[64%] text-zinc-300">{v}</span>
  </div>
);
