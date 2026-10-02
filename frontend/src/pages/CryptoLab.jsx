import { useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { KeyRound, Hash, Loader2, ShieldCheck, ShieldAlert, Copy } from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const areaCls = inputCls + " min-h-[80px] resize-y";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm";

function Panel({ icon: Icon, title, kicker, children }) {
  return (
    <div className="bg-[#121212] border border-border p-5">
      <div className="flex items-center gap-2.5 mb-4">
        <Icon className="w-4 h-4 text-primary" />
        <div>{kicker ? <p className="data-label">{kicker}</p> : null}<h3 className="font-heading text-base font-semibold">{title}</h3></div>
      </div>
      {children}
    </div>
  );
}

function b64urlJson(seg) {
  try {
    const s = seg.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((seg.length + 3) % 4);
    return JSON.parse(decodeURIComponent(escape(atob(s))));
  } catch { return null; }
}

const copy = (t) => { navigator.clipboard.writeText(t).then(() => toast.success("Copied")).catch(() => {}); };

export default function CryptoLab() {
  const [hash, setHash] = useState("");
  const [hWordlist, setHWordlist] = useState("");
  const [hRes, setHRes] = useState(null);
  const [hBusy, setHBusy] = useState(false);

  const [token, setToken] = useState("");
  const [jWordlist, setJWordlist] = useState("");
  const [jRes, setJRes] = useState(null);
  const [jBusy, setJBusy] = useState(false);

  const parts = token.split(".");
  const jwtHeader = parts.length === 3 ? b64urlJson(parts[0]) : null;
  const jwtPayload = parts.length === 3 ? b64urlJson(parts[1]) : null;

  const crackHash = async () => {
    if (!hash.trim()) return toast.error("Enter a hash");
    setHBusy(true);
    try { setHRes((await api.post("/toolkit/hash-crack", { hash: hash.trim(), wordlist: hWordlist })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Hash crack failed"); }
    finally { setHBusy(false); }
  };
  const crackJwt = async () => {
    if (!token.trim()) return toast.error("Paste a JWT");
    setJBusy(true);
    try { setJRes((await api.post("/toolkit/jwt-crack", { token: token.trim(), wordlist: jWordlist })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "JWT analysis failed"); }
    finally { setJBusy(false); }
  };

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="crypto-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><KeyRound className="w-7 h-7 text-primary" /> Crypto Lab</h1>
        <p className="text-sm text-zinc-500 mt-1.5">Identify &amp; crack hashes, and inspect / brute-force JWT secrets.</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6">
        <Panel icon={Hash} kicker="Hash" title="Hash identifier & cracker">
          <input value={hash} onChange={(e) => setHash(e.target.value)} data-testid="crypto-hash" placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99" className={inputCls} />
          <textarea value={hWordlist} onChange={(e) => setHWordlist(e.target.value)} data-testid="crypto-hash-wordlist"
            placeholder="optional custom wordlist (comma or newline separated)" className={areaCls + " mt-2"} />
          <button onClick={crackHash} disabled={hBusy} data-testid="crypto-hash-run" className={btnCls + " mt-3"}>
            {hBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Hash className="w-4 h-4" />} identify &amp; crack
          </button>
          {hRes && (
            <div className="mt-4 border border-border bg-[#0a0a0a] p-3 font-mono text-xs space-y-1" data-testid="crypto-hash-result">
              <Row k="Candidates" v={(hRes.candidates || []).join(", ") || "—"} />
              <Row k="Crackable" v={hRes.crackable ? "yes" : "no"} />
              <Row k="Wordlist size" v={String(hRes.wordlist_size ?? 0)} />
              <Row k="Tried" v={String(hRes.tried ?? 0)} />
              <div className="flex items-center justify-between gap-3 pt-1">
                <span className="text-zinc-500">Result</span>
                {hRes.cracked
                  ? <span className="text-emerald-400 flex items-center gap-1.5"><ShieldAlert className="w-3.5 h-3.5" /> {hRes.cracked} ({hRes.cracked_algo})</span>
                  : <span className="text-zinc-500 flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> not cracked</span>}
              </div>
            </div>
          )}
        </Panel>

        <Panel icon={KeyRound} kicker="JWT" title="JWT inspect & secret brute-force">
          <textarea value={token} onChange={(e) => setToken(e.target.value)} data-testid="crypto-jwt"
            placeholder="paste a JWT (header.payload.signature)" className={areaCls} />
          <textarea value={jWordlist} onChange={(e) => setJWordlist(e.target.value)} data-testid="crypto-jwt-wordlist"
            placeholder="optional extra secret candidates" className={areaCls + " mt-2"} />
          <button onClick={crackJwt} disabled={jBusy} data-testid="crypto-jwt-run" className={btnCls + " mt-3"}>
            {jBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />} inspect &amp; crack
          </button>

          {(jwtHeader || jwtPayload) && (
            <div className="mt-4 border border-border bg-[#0a0a0a] p-3 font-mono text-[11px]" data-testid="crypto-jwt-decoded">
              <div className="flex items-center justify-between"><span className="data-label">Header</span><button onClick={() => copy(JSON.stringify(jwtHeader, null, 2))} className="text-zinc-500 hover:text-primary"><Copy className="w-3 h-3" /></button></div>
              <pre className="text-zinc-300 whitespace-pre-wrap break-all">{JSON.stringify(jwtHeader, null, 2)}</pre>
              <div className="flex items-center justify-between mt-2"><span className="data-label">Payload</span><button onClick={() => copy(JSON.stringify(jwtPayload, null, 2))} className="text-zinc-500 hover:text-primary"><Copy className="w-3 h-3" /></button></div>
              <pre className="text-zinc-300 whitespace-pre-wrap break-all">{JSON.stringify(jwtPayload, null, 2)}</pre>
            </div>
          )}

          {jRes && (
            <div className="mt-3 border border-border bg-[#0a0a0a] p-3 font-mono text-xs space-y-1" data-testid="crypto-jwt-result">
              <Row k="Alg" v={jRes.alg || "—"} />
              {jRes.alg_none_vuln && <p className="text-severity-critical">⚠ alg=none accepted by this token — signing bypass risk</p>}
              <Row k="Tried" v={String(jRes.tried ?? 0)} />
              <div className="flex items-center justify-between gap-3 pt-1">
                <span className="text-zinc-500">Secret</span>
                {jRes.cracked
                  ? <span className="text-emerald-400">{jRes.cracked}</span>
                  : <span className="text-zinc-500">{jRes.note || "not cracked"}</span>}
              </div>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

const Row = ({ k, v }) => (
  <div className="flex items-center justify-between gap-3 border-b border-border/40 pb-1">
    <span className="text-zinc-500">{k}</span>
    <span className="truncate max-w-[64%] text-zinc-300">{v}</span>
  </div>
);
