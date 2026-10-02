import { useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  ShieldAlert, Globe, Syringe, ListTree, Lock, Network, FileKey, Loader2, Play, Copy, CheckCircle2,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const areaCls = inputCls + " min-h-[90px] resize-y";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm";

function Findings({ items }) {
  if (!items || items.length === 0) return <p className="text-sm text-emerald-400 flex items-center gap-2"><CheckCircle2 className="w-4 h-4" /> No findings.</p>;
  return (
    <div className="space-y-2">
      {items.map((f, i) => (
        <div key={i} className="border border-border bg-[#0a0a0a] p-3" data-testid={`finding-${i}`}>
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={f.severity} />
            <span className="text-sm text-white font-medium">{f.title}</span>
          </div>
          <p className="text-xs text-zinc-400">{f.detail}</p>
          {f.evidence ? <pre className="mt-1.5 text-[11px] font-mono text-zinc-500 whitespace-pre-wrap break-all">{f.evidence}</pre> : null}
          {f.recommendation ? <p className="text-[11px] text-primary mt-1">→ {f.recommendation}</p> : null}
        </div>
      ))}
    </div>
  );
}

function Stat({ k, v }) {
  return (
    <div className="border border-border bg-[#0a0a0a] px-3 py-2">
      <p className="data-label">{k}</p>
      <p className="font-mono text-xs text-zinc-200 mt-0.5 break-all">{v ?? "—"}</p>
    </div>
  );
}

const useRunner = () => {
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (path, body) => {
    setBusy(true); setRes(null);
    try { setRes((await api.post(path, body)).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Scan failed"); }
    finally { setBusy(false); }
  };
  return { busy, res, run, setRes };
};

function WebScan() {
  const [url, setUrl] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-web">
      <p className="text-xs text-zinc-500">Comprehensive non-destructive web check: security headers, cookies, CSP, clickjacking, HTTP methods, CORS, TLS, sensitive files, directory listing.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-web-url" placeholder="https://target.tld" className={inputCls} />
        <button onClick={() => run("/vulnsuite/web-scan", { url: url.trim() })} disabled={busy || !url.trim()} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />} Scan
        </button>
      </div>
      {res && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <Stat k="Status" v={res.status} />
            <Stat k="Header grade" v={res.grade} />
            <Stat k="Findings" v={res.findings_count} />
            <Stat k="Final URL" v={res.final_url} />
          </div>
          <Findings items={res.findings} />
          {res.checks?.exposed_paths?.length > 0 && (
            <div className="border border-border p-3">
              <p className="data-label mb-2">Reachable paths probed</p>
              <div className="flex flex-wrap gap-1.5">
                {res.checks.exposed_paths.map((p, i) => (
                  <span key={i} className="text-[11px] font-mono border border-severity-high/40 text-severity-high px-2 py-0.5">{p.path}</span>
                ))}
              </div>
            </div>
          )}
          {res.checks?.methods && (
            <div className="grid grid-cols-2 gap-2">
              <Stat k="Allowed methods" v={res.checks.methods.allow || "—"} />
              <Stat k="TRACE" v={res.checks.methods.trace ? "enabled" : "off"} />
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Injection() {
  const [url, setUrl] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-inj">
      <p className="text-xs text-zinc-500">Tests each query-parameter for: error/boolean SQL injection, reflected XSS, CRLF injection, open redirect (URL-like params) and Host-header reflection. Non-destructive.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-inj-url" placeholder="https://target.tld/item?id=1&page=home" className={inputCls} />
        <button onClick={() => run("/vulnsuite/injection", { url: url.trim() })} disabled={busy || !url.trim()} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Syringe className="w-4 h-4" />} Test
        </button>
      </div>
      {res && (
        <>
          <div className="grid grid-cols-2 gap-2"><Stat k="Tested params" v={(res.params || []).join(", ")} /><Stat k="Findings" v={res.findings_count} /></div>
          <Findings items={res.findings} />
          {res.results?.length > 0 && (
            <div className="border border-border p-3 overflow-x-auto">
              <p className="data-label mb-2">Per-parameter detail</p>
              <table className="w-full text-[11px] font-mono">
                <thead><tr className="text-zinc-500 text-left"><th className="py-1 pr-3">param</th><th>signals</th></tr></thead>
                <tbody>
                  {res.results.map((e, i) => (
                    <tr key={i} className="border-t border-border/40 text-zinc-400">
                      <td className="py-1 pr-3 text-zinc-300">{e.param}</td>
                      <td>{Object.entries(e.tests || {}).map(([k, v]) => `${k}: ${v}`).join(" · ") || "clean"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Params() {
  const [url, setUrl] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-params">
      <p className="text-xs text-zinc-500">Discover hidden parameters: existing query params, form inputs, and common names that change the response or reflect.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-params-url" placeholder="https://target.tld/page" className={inputCls} />
        <button onClick={() => run("/vulnsuite/params", { url: url.trim() })} disabled={busy || !url.trim()} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ListTree className="w-4 h-4" />} Discover
        </button>
      </div>
      {res && (
        <>
          <div className="grid grid-cols-2 gap-2"><Stat k="Existing params" v={(res.existing || []).join(", ") || "none"} /><Stat k="Form inputs" v={(res.form_inputs || []).join(", ") || "none"} /></div>
          <div className="border border-border p-3">
            <p className="data-label mb-2">Discovered ({res.discovered?.length || 0} of {res.tested})</p>
            {(res.discovered || []).length === 0 ? <p className="text-sm text-zinc-600">No hidden parameters detected.</p> : (
              <div className="flex flex-wrap gap-1.5">
                {res.discovered.map((d, i) => (
                  <span key={i} className="text-[11px] font-mono border border-primary/40 text-primary px-2 py-0.5">{d.param} <span className="text-zinc-500">{d.note}</span></span>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function Tls() {
  const [host, setHost] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-tls">
      <p className="text-xs text-zinc-500">TLS certificate + protocol support (TLS 1.0–1.3) with weak-protocol findings.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={host} onChange={(e) => setHost(e.target.value)} data-testid="vs-tls-host" placeholder="target.tld" className={inputCls} />
        <button onClick={() => run("/vulnsuite/tls", { host: host.trim() })} disabled={busy || !host.trim()} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />} Inspect
        </button>
      </div>
      {res && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {Object.entries(res.protocols || {}).map(([p, ok]) => (
              <div key={p} className="border border-border bg-[#0a0a0a] px-3 py-2">
                <p className="data-label">{p}</p>
                <p className={`font-mono text-xs mt-0.5 ${ok ? "text-emerald-400" : "text-zinc-600"}`}>{ok ? "enabled" : "off"}</p>
              </div>
            ))}
          </div>
          <div className="grid sm:grid-cols-2 gap-2">
            <Stat k="Subject" v={res.cert?.subject} />
            <Stat k="Issuer" v={res.cert?.issuer} />
            <Stat k="Valid to" v={res.cert?.valid_to} />
            <Stat k="Days left" v={res.cert?.days_left} />
          </div>
          <Findings items={res.findings} />
        </>
      )}
    </div>
  );
}

function Dns() {
  const [domain, setDomain] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-dns">
      <p className="text-xs text-zinc-500">DNS records (A/AAAA/MX/TXT/NS/CNAME/SOA/CAA) + zone-transfer (AXFR) and SPF checks.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={domain} onChange={(e) => setDomain(e.target.value)} data-testid="vs-dns-domain" placeholder="example.com" className={inputCls} />
        <button onClick={() => run("/vulnsuite/dns", { domain: domain.trim() })} disabled={busy || !domain.trim()} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Network className="w-4 h-4" />} Lookup
        </button>
      </div>
      {res && (
        <>
          <div className="grid sm:grid-cols-2 gap-2">
            {Object.entries(res.records || {}).map(([t, vals]) => (
              <div key={t} className="border border-border bg-[#0a0a0a] p-3">
                <p className="data-label mb-1">{t}</p>
                <p className="font-mono text-[11px] text-zinc-300 break-all">{vals.length ? vals.join("\n") : "—"}</p>
              </div>
            ))}
          </div>
          <Findings items={res.findings} />
        </>
      )}
    </div>
  );
}

function Wordlist() {
  const [keywords, setKeywords] = useState("");
  const [years, setYears] = useState("2020-2026");
  const [extra, setExtra] = useState("");
  const { busy, res, run } = useRunner();
  const download = () => {
    const blob = new Blob([(res.words || []).join("\n")], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "insafelabs-wordlist.txt";
    a.click();
  };
  return (
    <div className="space-y-4" data-testid="vs-wordlist">
      <p className="text-xs text-zinc-500">Targeted wordlist generator (names, domain, city, year) with permutations — for authorised password/dir auditing.</p>
      <div className="grid sm:grid-cols-3 gap-2">
        <input value={keywords} onChange={(e) => setKeywords(e.target.value)} data-testid="vs-wl-keywords" placeholder="acme, john, mumbai" className={inputCls} />
        <input value={years} onChange={(e) => setYears(e.target.value)} data-testid="vs-wl-years" placeholder="2020-2026" className={inputCls} />
        <input value={extra} onChange={(e) => setExtra(e.target.value)} data-testid="vs-wl-extra" placeholder="extra words (admin, dev)" className={inputCls} />
      </div>
      <button onClick={() => run("/vulnsuite/wordlist", { keywords, years, extra })} disabled={busy || !keywords.trim()} className={btnCls}>
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileKey className="w-4 h-4" />} Generate
      </button>
      {res && (
        <>
          <div className="flex items-center gap-3">
            <span className="data-label">{res.count} words</span>
            <button onClick={download} className="inline-flex items-center gap-1.5 border border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400 hover:text-primary hover:border-primary/50">
              <Copy className="w-3.5 h-3.5" /> download .txt
            </button>
          </div>
          <pre className="border border-border bg-[#0a0a0a] p-3 text-[11px] font-mono text-zinc-300 max-h-72 overflow-y-auto whitespace-pre-wrap break-all" data-testid="vs-wl-out">{(res.words || []).slice(0, 500).join("\n")}</pre>
        </>
      )}
    </div>
  );
}

function AuthForm() {
  const [url, setUrl] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-auth">
      <p className="text-xs text-zinc-500">Analyses login/authentication forms: method, CSRF token, password handling, transport and rate-limit hints.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-auth-url" placeholder="https://target.tld/login" className={inputCls} />
        <button onClick={() => run("/vulnsuite/auth-form", { url: url.trim() })} disabled={busy || !url.trim()} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />} Analyse
        </button>
      </div>
      {res && (
        <>
          <div className="space-y-2">
            {(res.forms || []).length === 0 ? <p className="text-sm text-zinc-600">No login form found on this page.</p> : res.forms.map((f, i) => (
              <div key={i} className="border border-border bg-[#0a0a0a] p-3">
                <p className="font-mono text-xs text-zinc-300">{f.method.toUpperCase()} {f.action || "(self)"}</p>
                <p className="font-mono text-[11px] text-zinc-500 mt-1">inputs: {(f.inputs || []).map((x) => `${x.name || "?"}:${x.type}`).join(", ") || "—"}</p>
                <p className="font-mono text-[11px] mt-1"><span className="text-zinc-500">csrf:</span> <span className={f.csrf_token ? "text-emerald-400" : "text-severity-high"}>{f.csrf_token ? "present" : "missing"}</span></p>
              </div>
            ))}
          </div>
          <Findings items={res.findings} />
        </>
      )}
    </div>
  );
}

function Vhost() {
  const [url, setUrl] = useState("");
  const [extra, setExtra] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-vhost">
      <p className="text-xs text-zinc-500">Virtual-host discovery: resolves the IP, does reverse-DNS (PTR), then probes common vhost names via the Host header and reports different responses.</p>
      <div className="grid sm:grid-cols-3 gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-vhost-url" placeholder="https://target.tld" className={inputCls + " sm:col-span-2"} />
        <input value={extra} onChange={(e) => setExtra(e.target.value)} data-testid="vs-vhost-extra" placeholder="extra vhosts" className={inputCls} />
      </div>
      <button onClick={() => run("/vulnsuite/vhost", { url: url.trim(), extra })} disabled={busy || !url.trim()} className={btnCls}>
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Network className="w-4 h-4" />} Discover
      </button>
      {res && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <Stat k="Host" v={res.host} />
            <Stat k="IP" v={res.ip} />
            <Stat k="PTR" v={res.ptr} />
            <Stat k="Tested" v={res.tested} />
          </div>
          <div className="border border-border p-3">
            <p className="data-label mb-2">Candidate vhosts ({res.found?.length || 0})</p>
            {(res.found || []).length === 0 ? <p className="text-sm text-zinc-600">No distinct vhosts detected.</p> : (
              <table className="w-full text-[11px] font-mono">
                <thead><tr className="text-zinc-500 text-left"><th className="py-1 pr-3">vhost</th><th className="pr-3">status</th><th className="pr-3">size</th><th>location</th></tr></thead>
                <tbody>
                  {res.found.map((v, i) => (
                    <tr key={i} className="border-t border-border/40 text-zinc-300"><td className="py-1 pr-3">{v.vhost}</td><td className="pr-3">{v.status}</td><td className="pr-3">{v.size}</td><td className="text-zinc-500 truncate max-w-[260px]">{v.location || "—"}</td></tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function RateLimit() {
  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("GET");
  const [count, setCount] = useState(12);
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-rate">
      <p className="text-xs text-zinc-500">Sends a burst of requests and checks whether the endpoint enforces rate limiting (429 / Retry-After / RateLimit headers). Non-destructive.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-rate-url" placeholder="https://target.tld/login" className={inputCls} />
        <select value={method} onChange={(e) => setMethod(e.target.value)} data-testid="vs-rate-method" className="bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary">
          {["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <input type="number" min={5} max={30} value={count} onChange={(e) => setCount(Number(e.target.value))} data-testid="vs-rate-count" className="w-24 bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary" />
        <button onClick={() => run("/vulnsuite/rate-limit", { url: url.trim(), method, count })} disabled={busy || !url.trim()} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Test
        </button>
      </div>
      {res && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <Stat k="Requests" v={res.requests} />
            <Stat k="Elapsed" v={`${res.elapsed_s}s`} />
            <Stat k="Enforced" v={res.enforced ? "yes" : "NO"} />
            <Stat k="429 at #" v={res.limited_at_request ?? "—"} />
          </div>
          <div className="border border-border bg-[#0a0a0a] p-3">
            <p className="data-label mb-1">Status distribution</p>
            <p className="font-mono text-xs text-zinc-300">{Object.entries(res.status_distribution || {}).map(([k, v]) => `${k}: ${v}`).join("  ·  ")}</p>
            {res.rate_limit_headers && Object.keys(res.rate_limit_headers).length > 0 && (
              <p className="font-mono text-[11px] text-zinc-500 mt-1">{Object.entries(res.rate_limit_headers).map(([k, v]) => `${k}: ${v}`).join("  ·  ")}</p>
            )}
          </div>
          <Findings items={res.findings} />
        </>
      )}
    </div>
  );
}

function Idor() {
  const [url, setUrl] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-idor">
      <p className="text-xs text-zinc-500">Checks for <b>IDOR</b> by varying a numeric object id in the URL (e.g. <span className="font-mono">/users/1</span> or <span className="font-mono">?id=1</span>) and comparing responses. Read-only.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-idor-url" placeholder="https://target.tld/api/users/1  ·  ?id=1" className={inputCls} />
        <button onClick={() => run("/vulnsuite/idor", { url: url.trim() })} disabled={busy || !url.trim()} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Test
        </button>
      </div>
      {res && (
        <>
          <div className="grid grid-cols-2 gap-2"><Stat k="Object id" v={res.id} /><Stat k="Baseline" v={`${res.baseline?.status} · ${res.baseline?.size}B`} /></div>
          <div className="border border-border p-3">
            <p className="data-label mb-2">Varied-id responses ({res.hits?.length || 0})</p>
            {(res.hits || []).length === 0 ? <p className="text-sm text-zinc-600">No differing 200 responses — no obvious IDOR.</p> : (
              <table className="w-full text-[11px] font-mono">
                <thead><tr className="text-zinc-500 text-left"><th className="py-1 pr-3">id</th><th className="pr-3">status</th><th className="pr-3">size</th><th>diff</th></tr></thead>
                <tbody>
                  {res.hits.map((h, i) => <tr key={i} className="border-t border-border/40 text-zinc-300"><td className="py-1 pr-3">{h.id}</td><td className="pr-3">{h.status}</td><td className="pr-3">{h.size}</td><td>{h.diff}</td></tr>)}
                </tbody>
              </table>
            )}
          </div>
          <Findings items={res.findings} />
        </>
      )}
    </div>
  );
}

function ParamScanner({ path, blurb, testid, flag }) {
  const [url, setUrl] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid={testid}>
      <p className="text-xs text-zinc-500">{blurb}</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid={`${testid}-url`} placeholder="https://target.tld/page?param=test" className={inputCls} />
        <button onClick={() => run(path, { url: url.trim() })} disabled={busy || !url.trim()} data-testid={`${testid}-run`} className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Test
        </button>
      </div>
      {res && (
        <>
          <div className="border border-border p-3">
            <p className="data-label mb-2">Per-parameter ({res.results?.length || 0})</p>
            <table className="w-full text-[11px] font-mono">
              <thead><tr className="text-zinc-500 text-left"><th className="py-1 pr-3">param</th><th className="pr-3">detected</th><th>evidence</th></tr></thead>
              <tbody>
                {(res.results || []).map((e, i) => (
                  <tr key={i} className="border-t border-border/40 text-zinc-300">
                    <td className="py-1 pr-3">{e.param}</td>
                    <td className="pr-3">{e[flag] ? <span className="text-severity-critical">YES</span> : <span className="text-zinc-600">no</span>}</td>
                    <td className="truncate max-w-[260px]">{e.evidence ? JSON.stringify(e.evidence) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Findings items={res.findings} />
        </>
      )}
    </div>
  );
}

function IocExtractor() {
  const [text, setText] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-ioc">
      <p className="text-xs text-zinc-500">Paste any text / log / report → extract IOCs: IPs, URLs, emails, domains, MD5/SHA1/SHA256 hashes, CVEs, JWTs and BTC addresses.</p>
      <textarea value={text} onChange={(e) => setText(e.target.value)} data-testid="vs-ioc-text" placeholder="paste log / report text here…" className={inputCls + " min-h-[140px] resize-y"} />
      <button onClick={() => run("/vulnsuite/ioc", { text })} disabled={busy || !text.trim()} data-testid="vs-ioc-run" className={btnCls}>
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Extract
      </button>
      {res && (
        <>
          <div className="flex flex-wrap gap-1.5" data-testid="vs-ioc-counts">
            {Object.entries(res.counts || {}).map(([k, v]) => (
              <span key={k} className={`text-[11px] font-mono border px-2 py-0.5 ${v ? "border-primary/40 text-primary" : "border-border text-zinc-600"}`}>{k}: {v}</span>
            ))}
          </div>
          <div className="grid sm:grid-cols-2 gap-2">
            {Object.entries(res.iocs || {}).filter(([, v]) => v.length).map(([k, v]) => (
              <div key={k} className="border border-border bg-[#0a0a0a] p-3">
                <p className="data-label mb-1">{k} ({v.length})</p>
                <p className="font-mono text-[11px] text-zinc-300 break-all max-h-40 overflow-y-auto">{v.slice(0, 60).join("\n")}</p>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function FaviconFP() {
  const [url, setUrl] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-favicon">
      <p className="text-xs text-zinc-500">Compute the favicon fingerprints — useful to identify tech / find related assets (search the Shodan hash on Shodan &amp; friends).</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-favicon-url" placeholder="https://target.tld" className={inputCls} />
        <button onClick={() => run("/vulnsuite/favicon", { url: url.trim() })} disabled={busy || !url.trim()} data-testid="vs-favicon-run" className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Fingerprint
        </button>
      </div>
      {res && (
        <div className="grid sm:grid-cols-2 gap-2" data-testid="vs-favicon-result">
          <Stat k="Favicon URL" v={res.favicon_url} />
          <Stat k="Size" v={`${res.size} B`} />
          <Stat k="MD5" v={res.md5} />
          <Stat k="SHA-256" v={res.sha256} />
          <Stat k="mmh3" v={res.mmh3} />
          <Stat k="Shodan hash" v={res.shodan_hash} />
        </div>
      )}
    </div>
  );
}

function CidrSweep() {
  const [target, setTarget] = useState("");
  const [limit, setLimit] = useState(256);
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-cidr">
      <p className="text-xs text-zinc-500">Reverse-DNS (PTR) sweep of a subnet — list which hosts have DNS names. Works for LANs too.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={target} onChange={(e) => setTarget(e.target.value)} data-testid="vs-cidr-target" placeholder="192.168.1.0/24" className={inputCls} />
        <input type="number" min={1} max={1024} value={limit} onChange={(e) => setLimit(Number(e.target.value))} className="w-28 bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary" />
        <button onClick={() => run("/vulnsuite/cidr", { target: target.trim(), limit })} disabled={busy || !target.trim()} data-testid="vs-cidr-run" className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Sweep
        </button>
      </div>
      {res && (
        <>
          <div className="grid grid-cols-3 gap-2"><Stat k="Network" v={res.network} /><Stat k="Scanned" v={res.scanned} /><Stat k="With PTR" v={res.with_ptr} /></div>
          <div className="border border-border bg-[#0a0a0a] p-3 max-h-80 overflow-y-auto">
            {(res.results || []).length === 0 ? <p className="text-sm text-zinc-600">No hosts with a PTR record.</p> : (
              <table className="w-full text-[11px] font-mono">
                <thead><tr className="text-zinc-500 text-left"><th className="py-1 pr-3">ip</th><th>ptr</th></tr></thead>
                <tbody>{res.results.map((r, i) => <tr key={i} className="border-t border-border/40 text-zinc-300"><td className="py-1 pr-3">{r.ip}</td><td className="truncate">{r.ptr}</td></tr>)}</tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function OpenApi() {
  const [url, setUrl] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-openapi">
      <p className="text-xs text-zinc-500">Find &amp; analyse an OpenAPI/Swagger spec — lists every endpoint and flags those with no declared authentication.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-openapi-url" placeholder="https://target.tld" className={inputCls} />
        <button onClick={() => run("/vulnsuite/openapi", { url: url.trim() })} disabled={busy || !url.trim()} data-testid="vs-openapi-run" className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Analyse
        </button>
      </div>
      {res && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <Stat k="Spec" v={res.spec_url} /><Stat k="Title" v={res.title} /><Stat k="Version" v={res.version} /><Stat k="Endpoints" v={res.endpoint_count} />
          </div>
          <Findings items={res.findings} />
          <div className="border border-border bg-[#0a0a0a] p-3 max-h-80 overflow-y-auto">
            <p className="data-label mb-2">Endpoints ({(res.endpoints || []).length})</p>
            <table className="w-full text-[11px] font-mono">
              <thead><tr className="text-zinc-500 text-left"><th className="py-1 pr-3">method</th><th className="pr-3">path</th><th>auth</th></tr></thead>
              <tbody>{(res.endpoints || []).map((e, i) => (
                <tr key={i} className="border-t border-border/40 text-zinc-300"><td className="py-1 pr-3">{e.method}</td><td className="pr-3 truncate">{e.path}</td><td>{e.protected ? "yes" : <span className="text-severity-high">no</span>}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function Xxe() {
  const [url, setUrl] = useState("");
  const { busy, res, run } = useRunner();
  return (
    <div className="space-y-4" data-testid="vs-xxe">
      <p className="text-xs text-zinc-500">Test an XML endpoint for XXE — posts an external-entity payload and looks for local file content.</p>
      <div className="flex flex-col sm:flex-row gap-2">
        <input value={url} onChange={(e) => setUrl(e.target.value)} data-testid="vs-xxe-url" placeholder="https://target.tld/api/xml" className={inputCls} />
        <button onClick={() => run("/vulnsuite/xxe", { url: url.trim() })} disabled={busy || !url.trim()} data-testid="vs-xxe-run" className={btnCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Test
        </button>
      </div>
      {res && (
        <>
          <Stat k="Endpoint accepts XML" v={res.accepted_xml ? "yes" : "no / error"} />
          <Findings items={res.findings} />
        </>
      )}
    </div>
  );
}

export default function VulnSuite() {
  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="vulnsuite-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><ShieldAlert className="w-7 h-7 text-primary" /> Vuln Suite</h1>
        <p className="text-sm text-zinc-500 mt-1.5">Native, in-app security testing — runs entirely here (no external binaries). Non-destructive; authorised targets only.</p>
      </header>

      <Tabs defaultValue="web">
        <TabsList className="bg-[#0c0c0c] border border-border flex flex-wrap h-auto">
          <TabsTrigger value="web" data-testid="vs-tab-web">Web Scan</TabsTrigger>
          <TabsTrigger value="inj" data-testid="vs-tab-inj">Injection</TabsTrigger>
          <TabsTrigger value="params" data-testid="vs-tab-params">Params</TabsTrigger>
          <TabsTrigger value="vhost" data-testid="vs-tab-vhost">VHost</TabsTrigger>
          <TabsTrigger value="tls" data-testid="vs-tab-tls">TLS</TabsTrigger>
          <TabsTrigger value="auth" data-testid="vs-tab-auth">Auth Form</TabsTrigger>
          <TabsTrigger value="rate" data-testid="vs-tab-rate">Rate Limit</TabsTrigger>
          <TabsTrigger value="idor" data-testid="vs-tab-idor">IDOR</TabsTrigger>
          <TabsTrigger value="ssti" data-testid="vs-tab-ssti">SSTI</TabsTrigger>
          <TabsTrigger value="lfi" data-testid="vs-tab-lfi">LFI</TabsTrigger>
          <TabsTrigger value="cmdi" data-testid="vs-tab-cmdi">Cmd Inj</TabsTrigger>
          <TabsTrigger value="ioc" data-testid="vs-tab-ioc">IOC Extract</TabsTrigger>
          <TabsTrigger value="favicon" data-testid="vs-tab-favicon">Favicon</TabsTrigger>
          <TabsTrigger value="cidr" data-testid="vs-tab-cidr">CIDR/PTR</TabsTrigger>
          <TabsTrigger value="openapi" data-testid="vs-tab-openapi">OpenAPI</TabsTrigger>
          <TabsTrigger value="xxe" data-testid="vs-tab-xxe">XXE</TabsTrigger>
          <TabsTrigger value="dns" data-testid="vs-tab-dns">DNS / AXFR</TabsTrigger>
          <TabsTrigger value="wordlist" data-testid="vs-tab-wordlist">Wordlist</TabsTrigger>
        </TabsList>
        <TabsContent value="web" className="bg-[#121212] border border-border p-5 mt-4"><WebScan /></TabsContent>
        <TabsContent value="inj" className="bg-[#121212] border border-border p-5 mt-4"><Injection /></TabsContent>
        <TabsContent value="params" className="bg-[#121212] border border-border p-5 mt-4"><Params /></TabsContent>
        <TabsContent value="vhost" className="bg-[#121212] border border-border p-5 mt-4"><Vhost /></TabsContent>
        <TabsContent value="tls" className="bg-[#121212] border border-border p-5 mt-4"><Tls /></TabsContent>
        <TabsContent value="auth" className="bg-[#121212] border border-border p-5 mt-4"><AuthForm /></TabsContent>
        <TabsContent value="rate" className="bg-[#121212] border border-border p-5 mt-4"><RateLimit /></TabsContent>
        <TabsContent value="idor" className="bg-[#121212] border border-border p-5 mt-4"><Idor /></TabsContent>
        <TabsContent value="ssti" className="bg-[#121212] border border-border p-5 mt-4"><ParamScanner path="/vulnsuite/ssti" flag="ssti" testid="vs-ssti" blurb="Server-Side Template Injection: injects template expressions ({{7*7}}, ${7*7}, <%= 7*7 %>…) and looks for evaluation." /></TabsContent>
        <TabsContent value="lfi" className="bg-[#121212] border border-border p-5 mt-4"><ParamScanner path="/vulnsuite/lfi" flag="lfi" testid="vs-lfi" blurb="Local File Inclusion / path traversal: injects ../../ payloads (incl. encodings) and looks for /etc/passwd or win.ini content." /></TabsContent>
        <TabsContent value="cmdi" className="bg-[#121212] border border-border p-5 mt-4"><ParamScanner path="/vulnsuite/cmdi" flag="cmdi" testid="vs-cmdi" blurb="OS command injection (time + echo based): measures response delay for ;sleep 5 and reflects an echo marker." /></TabsContent>
        <TabsContent value="ioc" className="bg-[#121212] border border-border p-5 mt-4"><IocExtractor /></TabsContent>
        <TabsContent value="favicon" className="bg-[#121212] border border-border p-5 mt-4"><FaviconFP /></TabsContent>
        <TabsContent value="cidr" className="bg-[#121212] border border-border p-5 mt-4"><CidrSweep /></TabsContent>
        <TabsContent value="openapi" className="bg-[#121212] border border-border p-5 mt-4"><OpenApi /></TabsContent>
        <TabsContent value="xxe" className="bg-[#121212] border border-border p-5 mt-4"><Xxe /></TabsContent>
        <TabsContent value="dns" className="bg-[#121212] border border-border p-5 mt-4"><Dns /></TabsContent>
        <TabsContent value="wordlist" className="bg-[#121212] border border-border p-5 mt-4"><Wordlist /></TabsContent>
      </Tabs>
    </div>
  );
}
