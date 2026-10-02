import { useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { Radar, Search, Loader2, Globe, Mail, Network, ShieldAlert, CheckCircle2 } from "lucide-react";

const inputCls = "flex-1 bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm";

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

const sevColor = (s) => ({ HIGH: "#EF4444", MEDIUM: "#F59E0B", LOW: "#3B82F6" }[String(s || "").toUpperCase()] || "#71717A");

export default function ReconLab() {
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState("");
  const [dns, setDns] = useState(null);
  const [email, setEmail] = useState(null);
  const [subs, setSubs] = useState(null);
  const [takeover, setTakeover] = useState(null);

  const clean = () => target.trim().replace(/^https?:\/\//, "").split("/")[0];

  const run = async (kind) => {
    const t = clean();
    if (!t) return toast.error("Enter a domain or host");
    setBusy(kind);
    try {
      if (kind === "dns") setDns((await api.post("/toolkit/dns", { domain: t })).data);
      else if (kind === "email") setEmail((await api.post("/toolkit/email-dns", { domain: t })).data);
      else if (kind === "subs") setSubs((await api.post("/toolkit/subdomain-enum", { domain: t })).data);
      else if (kind === "takeover") setTakeover((await api.post("/toolkit/takeover", { host: t })).data);
      toast.success(`${kind} complete`);
    } catch (e) {
      toast.error(formatApiError(e.response?.data?.detail) || `${kind} failed`);
    } finally { setBusy(""); }
  };

  const isLoading = (k) => busy === k;

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="recon-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><Radar className="w-7 h-7 text-primary" /> Recon Lab</h1>
        <p className="text-sm text-zinc-500 mt-1.5">DNS, email security, subdomain enumeration and takeover checks — one workspace.</p>
      </header>

      <div className="flex flex-col sm:flex-row gap-2">
        <input value={target} onChange={(e) => setTarget(e.target.value)} data-testid="recon-target"
          placeholder="example.com" className={inputCls} />
        <div className="flex flex-wrap gap-2">
          <button onClick={() => run("dns")} disabled={!!busy} data-testid="recon-dns" className={btnCls}>
            {isLoading("dns") ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />} DNS
          </button>
          <button onClick={() => run("email")} disabled={!!busy} data-testid="recon-email" className={btnCls}>
            {isLoading("email") ? <Loader2 className="w-4 h-4 animate-spin" /> : <Mail className="w-4 h-4" />} Email
          </button>
          <button onClick={() => run("subs")} disabled={!!busy} data-testid="recon-subs" className={btnCls}>
            {isLoading("subs") ? <Loader2 className="w-4 h-4 animate-spin" /> : <Network className="w-4 h-4" />} Subdomains
          </button>
          <button onClick={() => run("takeover")} disabled={!!busy} data-testid="recon-takeover" className={btnCls}>
            {isLoading("takeover") ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldAlert className="w-4 h-4" />} Takeover
          </button>
        </div>
      </div>

      {dns && (
        <Panel icon={Globe} kicker="Recon" title={`DNS — ${dns.domain || clean()}`} data-testid="recon-dns-result">
          <div className="grid sm:grid-cols-2 gap-x-6 gap-y-1 font-mono text-xs">
            {Object.entries(dns).filter(([k, v]) => !["findings", "domain"].includes(k) && v != null).slice(0, 24).map(([k, v]) => (
              <div key={k} className="flex items-start justify-between gap-3 border-b border-border/40 py-1">
                <span className="text-zinc-500">{k}</span>
                <span className="text-zinc-300 text-right break-all max-w-[62%]">{Array.isArray(v) ? v.join(", ") || "—" : String(v)}</span>
              </div>
            ))}
          </div>
          {(dns.findings || []).length > 0 && (
            <div className="mt-3 space-y-1">
              {dns.findings.map((f, i) => (
                <p key={i} className="text-xs text-zinc-400">• {typeof f === "string" ? f : JSON.stringify(f)}</p>
              ))}
            </div>
          )}
        </Panel>
      )}

      {email && (
        <Panel icon={Mail} kicker="Email security" title={`SPF / DMARC / DKIM — ${email.domain}`}
          right={<span className="data-label" style={{ color: email.spoofable ? "#EF4444" : "#22C55E" }}>{email.spoofable ? "spoofable" : "protected"}</span>}>
          <div className="grid sm:grid-cols-2 gap-3">
            <div className="font-mono text-xs space-y-1">
              <Row k="SPF" v={email.spf?.length ? email.spf.join(" ") : "MISSING"} />
              <Row k="DMARC" v={email.dmarc?.length ? `${email.dmarc_policy || "?"}` : "MISSING"} />
              <Row k="DKIM" v={Object.keys(email.dkim || {}).length ? Object.keys(email.dkim).join(", ") : "none found"} />
              <Row k="DNSSEC" v={email.dnssec ? "enabled" : "off"} />
              <Row k="CAA" v={email.caa?.length ? "present" : "none"} />
            </div>
            <div className="space-y-1.5">
              {(email.issues || []).length === 0 ? (
                <p className="text-sm text-emerald-400 flex items-center gap-2"><CheckCircle2 className="w-4 h-4" /> No email-security issues found.</p>
              ) : email.issues.map((it, i) => (
                <div key={i} className="border border-border bg-[#0a0a0a] p-2.5" data-testid={`email-issue-${i}`}>
                  <p className="font-mono text-[11px]" style={{ color: sevColor(it.severity) }}>{it.severity} · {it.check}</p>
                  <p className="text-xs text-zinc-400 mt-0.5">{it.detail}</p>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      )}

      {subs && (
        <Panel icon={Network} kicker="Enumeration" title={`Subdomains — ${subs.domain}`} right={<span className="data-label">{subs.found_count} found / {subs.checked} checked</span>}>
          {(subs.found || []).length === 0 ? <p className="text-sm text-zinc-600">No subdomains resolved from the common wordlist.</p> : (
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {subs.found.map((s, i) => (
                <div key={i} className="border border-border bg-[#0a0a0a] px-3 py-2" data-testid={`sub-${i}`}>
                  <p className="font-mono text-xs text-white truncate">{s.subdomain}</p>
                  <p className="font-mono text-[10px] text-zinc-500 truncate">{(s.ips || []).join(", ")}</p>
                </div>
              ))}
            </div>
          )}
        </Panel>
      )}

      {takeover && (
        <Panel icon={ShieldAlert} kicker="Takeover" title={`Subdomain takeover — ${takeover.host}`}
          right={<span className="data-label" style={{ color: takeover.vulnerable ? "#EF4444" : "#22C55E" }}>{takeover.vulnerable ? "VULNERABLE" : "no confirmed"}</span>}>
          <Row k="CNAMEs" v={(takeover.cnames || []).join(", ") || "none"} />
          <Row k="HTTP status" v={String(takeover.http_status ?? "—")} />
          {(takeover.matches || []).length > 0 && (
            <div className="mt-3 space-y-1.5">
              {takeover.matches.map((m, i) => (
                <div key={i} className="border border-border bg-[#0a0a0a] p-2.5" data-testid={`takeover-${i}`}>
                  <p className="font-mono text-xs text-white">{m.service}</p>
                  <p className="text-[11px] text-zinc-500">{m.fingerprint ? `fingerprint matched: ${m.fingerprint}` : m.note}</p>
                </div>
              ))}
            </div>
          )}
        </Panel>
      )}

      {!dns && !email && !subs && !takeover && (
        <div className="border border-dashed border-border p-10 text-center text-zinc-600 text-sm flex flex-col items-center gap-2">
          <Search className="w-6 h-6 opacity-50" />
          Run DNS / Email / Subdomains / Takeover against a domain you are authorized to test.
        </div>
      )}
    </div>
  );
}

const Row = ({ k, v }) => (
  <div className="flex items-center justify-between gap-3 border-b border-border/40 pb-1">
    <span className="text-zinc-500">{k}</span>
    <span className="truncate max-w-[62%] text-zinc-300">{v}</span>
  </div>
);
