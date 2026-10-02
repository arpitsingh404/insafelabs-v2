import { useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { Network, Loader2, Play, Link2, CheckCircle2, XCircle } from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const areaCls = inputCls + " min-h-[120px] resize-y";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm";

export default function ProxyChain() {
  const [proxies, setProxies] = useState("");
  const [target, setTarget] = useState("https://api.ipify.org");
  const [busy, setBusy] = useState("");
  const [test, setTest] = useState(null);
  const [chain, setChain] = useState(null);

  const list = () => proxies.split("\n").map((l) => l.trim()).filter(Boolean);

  const runTest = async () => {
    if (!list().length) return toast.error("Enter at least one proxy (host:port)");
    setBusy("test"); setTest(null);
    try { setTest((await api.post("/proxy/test", { proxies: list(), target: target.trim() })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Test failed"); }
    finally { setBusy(""); }
  };
  const runChain = async () => {
    if (!list().length) return toast.error("Enter the proxy chain (one per line, in order)");
    setBusy("chain"); setChain(null);
    try { setChain((await api.post("/proxy/chain", { proxies: list(), target: target.trim() })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Chain failed"); }
    finally { setBusy(""); }
  };

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="proxy-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><Network className="w-7 h-7 text-primary" /> Proxy Chain</h1>
        <p className="text-sm text-zinc-500 mt-1.5">Test proxies individually and open a real multi-hop tunnel (proxychains-style) to a target.</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6">
        <div className="bg-[#121212] border border-border p-5 space-y-3">
          <div>
            <p className="data-label mb-1.5">Proxies — one per line, in chain order</p>
            <textarea value={proxies} onChange={(e) => setProxies(e.target.value)} data-testid="proxy-list"
              placeholder={"127.0.0.1:8080\nhttp://user:pass@1.2.3.4:3128\nsocks5://5.6.7.8:1080"} className={areaCls} />
          </div>
          <div>
            <p className="data-label mb-1.5">Target</p>
            <input value={target} onChange={(e) => setTarget(e.target.value)} data-testid="proxy-target" className={inputCls} />
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={runTest} disabled={!!busy} data-testid="proxy-test" className={btnCls}>
              {busy === "test" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Test each
            </button>
            <button onClick={runChain} disabled={!!busy} data-testid="proxy-chain" className={btnCls}>
              {busy === "chain" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Link2 className="w-4 h-4" />} Chain
            </button>
          </div>
          <p className="text-[11px] text-zinc-600 font-mono">Chaining uses HTTP CONNECT (http/https proxies). SOCKS proxies are tested individually only.</p>
        </div>

        <div className="bg-[#121212] border border-border p-5 space-y-4">
          {test && (
            <div data-testid="proxy-test-result">
              <p className="data-label mb-2">Individual test — {test.target}</p>
              <table className="w-full text-[11px] font-mono">
                <thead><tr className="text-zinc-500 text-left"><th className="py-1 pr-3">proxy</th><th className="pr-3">ok</th><th className="pr-3">status</th><th>exit ip / error</th></tr></thead>
                <tbody>
                  {test.results.map((r, i) => (
                    <tr key={i} className="border-t border-border/40 text-zinc-300">
                      <td className="py-1 pr-3 truncate max-w-[150px]">{r.proxy}</td>
                      <td className="pr-3">{r.ok ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <XCircle className="w-3.5 h-3.5 text-severity-critical" />}</td>
                      <td className="pr-3">{r.status ?? "—"}</td>
                      <td className="truncate max-w-[160px]">{r.ok ? (r.exit_ip || "ok") : (r.error || "—")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {chain && (
            <div data-testid="proxy-chain-result">
              <p className="data-label mb-2">Chain result — {chain.target}</p>
              <div className="space-y-1.5">
                {(chain.hops || []).map((h, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs font-mono">
                    {h.status === "failed" ? <XCircle className="w-3.5 h-3.5 text-severity-critical" /> : <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                    <span className="text-zinc-500">hop {h.hop}</span>
                    <span className="text-zinc-300 truncate">{h.proxy}</span>
                    <span className={h.status === "failed" ? "text-severity-critical" : "text-emerald-400"}>{h.status}</span>
                    {h.error ? <span className="text-severity-critical truncate">{h.error}</span> : null}
                  </div>
                ))}
              </div>
              {chain.ok && (
                <div className="mt-3 border border-border bg-[#0a0a0a] p-3 font-mono text-[11px]">
                  <p className="text-zinc-500">{chain.status_line}</p>
                  {chain.exit_ip ? <p className="text-primary mt-1">exit IP: {chain.exit_ip}</p> : null}
                  <pre className="text-zinc-400 mt-1 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">{(chain.body || "").slice(0, 800)}</pre>
                </div>
              )}
            </div>
          )}
          {!test && !chain && <p className="text-sm text-zinc-600">Results will appear here.</p>}
        </div>
      </div>
    </div>
  );
}
