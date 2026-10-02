import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import {
  Wrench, Search, Loader2, RefreshCw, Play, Copy, ExternalLink, CheckCircle2, XCircle, Terminal, X,
} from "lucide-react";

const btnMini = "inline-flex items-center gap-1.5 border border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400 hover:text-primary hover:border-primary/50 transition-colors";
const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";

const copyText = (t) => navigator.clipboard.writeText(t).then(() => toast.success("Copied")).catch(() => {});

function ToolCard({ tool, onOpen }) {
  return (
    <button onClick={() => onOpen(tool)} data-testid={`arsenal-${tool.id}`}
      className="text-left bg-[#121212] border border-border p-4 hover:border-primary/50 hover:bg-[#151515] transition-colors flex flex-col gap-2">
      <div className="flex items-start justify-between gap-2">
        <span className="font-heading text-base font-semibold text-white">{tool.name}</span>
        <span className={`inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-wider ${tool.installed ? "text-emerald-400" : "text-zinc-600"}`}>
          {tool.installed ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />} {tool.installed ? "installed" : "not installed"}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <span className="data-label border border-border px-1.5 py-0.5">{tool.category}</span>
        {tool.mode === "gui" && <span className="data-label border border-border px-1.5 py-0.5">manual</span>}
        {tool.runnable && <span className="data-label border border-primary/40 text-primary px-1.5 py-0.5">runnable</span>}
      </div>
      <p className="text-xs text-zinc-500 line-clamp-2">{tool.description}</p>
    </button>
  );
}

function Detail({ tool, onClose }) {
  const [profile, setProfile] = useState(tool.profiles?.[0]?.id || "");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);

  const profiles = tool.profiles || [];
  const sel = profiles.find((p) => p.id === profile) || profiles[0];
  const needsTarget = sel ? sel.needsTarget !== false : true;

  const run = async () => {
    if (needsTarget && !target.trim()) return toast.error("Enter a target");
    setBusy(true); setRes(null);
    try { setRes((await api.post("/arsenal/run", { id: tool.id, profile, target: target.trim() })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Run failed"); }
    finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-[9998] bg-black/60 backdrop-blur-sm flex items-start justify-center p-4 overflow-y-auto" onClick={onClose} data-testid="arsenal-detail">
      <div className="w-full max-w-2xl my-8 border border-border bg-[#0c0c0c]" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-3 px-5 py-4 border-b border-border">
          <div>
            <p className="data-label">{tool.category}</p>
            <h3 className="font-heading text-xl font-bold flex items-center gap-2">
              {tool.name}
              {tool.installed ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-zinc-600" />}
            </h3>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-white"><X className="w-5 h-5" /></button>
        </div>

        <div className="p-5 space-y-4">
          <p className="text-sm text-zinc-400">{tool.description}</p>

          {tool.installed ? (
            <div className="font-mono text-xs border border-border bg-[#0a0a0a] p-3 space-y-1">
              <p><span className="text-zinc-500">binary:</span> <span className="text-zinc-300">{tool.path}</span></p>
              <p><span className="text-zinc-500">version:</span> <span className="text-zinc-300">{tool.version || "unknown"}</span></p>
            </div>
          ) : (
            <div className="border border-border bg-[#0a0a0a] p-3">
              <p className="data-label mb-1">Install</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-xs font-mono text-primary break-all">{tool.install}</code>
                <button onClick={() => copyText(tool.install)} className="text-zinc-500 hover:text-primary"><Copy className="w-3.5 h-3.5" /></button>
              </div>
            </div>
          )}

          <a href={tool.doc} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline">
            <ExternalLink className="w-3.5 h-3.5" /> documentation
          </a>

          {tool.runnable ? (
            <div className="border-t border-border pt-4 space-y-3">
              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <p className="data-label mb-1.5">Profile</p>
                  <select value={profile} onChange={(e) => setProfile(e.target.value)} data-testid="arsenal-profile" className={inputCls}>
                    {(tool.profiles || []).map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                  </select>
                </div>
                {needsTarget ? (
                  <div>
                    <p className="data-label mb-1.5">Target ({tool.targetType})</p>
                    <input value={target} onChange={(e) => setTarget(e.target.value)} data-testid="arsenal-target"
                      placeholder={tool.targetType === "url" ? "https://target.tld" : tool.targetType === "domain" ? "example.com" : tool.targetType === "query" ? "search terms" : "10.0.0.1"}
                      className={inputCls} />
                  </div>
                ) : (
                  <div>
                    <p className="data-label mb-1.5">Target</p>
                    <p className="text-xs text-zinc-500 py-2.5 font-mono">not required for this profile</p>
                  </div>
                )}
              </div>
              <button onClick={run} disabled={busy} data-testid="arsenal-run"
                className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm">
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Run
              </button>

              {res && (
                <div className="border border-border bg-[#050505] p-3" data-testid="arsenal-output">
                  <div className="flex items-center gap-2 mb-2">
                    <Terminal className="w-4 h-4 text-primary" />
                    <span className="font-mono text-[11px] text-zinc-400">{res.argv?.join(" ")}</span>
                    <span className={`ml-auto font-mono text-[11px] ${res.exit_code === 0 ? "text-emerald-400" : "text-severity-high"}`}>exit {res.exit_code}{res.timed_out ? " · timeout" : ""}</span>
                    <button onClick={() => copyText(res.output || "")} className="text-zinc-500 hover:text-primary"><Copy className="w-3.5 h-3.5" /></button>
                  </div>
                  <pre className="text-[11px] font-mono text-zinc-300 whitespace-pre-wrap break-all max-h-72 overflow-y-auto">{res.output || "(no output)"}{res.truncated ? "\n… [truncated]" : ""}</pre>
                </div>
              )}
            </div>
          ) : (
            <div className="border-t border-border pt-4">
              <p className="text-xs text-zinc-500">
                {tool.installed
                  ? "This tool is installed but not executed from the console (GUI / file-driven). Run it directly on the host."
                  : "Install it above, then reopen this panel — the console auto-detects installed tools."}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Arsenal() {
  const [tools, setTools] = useState(null);
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("All");
  const [installedOnly, setInstalledOnly] = useState(false);
  const [sel, setSel] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setBusy(true);
    try { setTools((await api.get("/arsenal/tools")).data.tools); }
    catch { setTools(false); toast.error("Could not load the tool catalog"); }
    finally { setBusy(false); }
  };
  useEffect(() => { load(); }, []);

  const list = useMemo(() => (tools && tools !== false ? tools : []), [tools]);
  const categories = useMemo(() => ["All", ...Array.from(new Set(list.map((t) => t.category)))], [list]);
  const filtered = list.filter((t) =>
    (cat === "All" || t.category === cat) &&
    (!installedOnly || t.installed) &&
    (t.name.toLowerCase().includes(q.trim().toLowerCase()) || t.description.toLowerCase().includes(q.trim().toLowerCase()))
  );
  const installedCount = list.filter((t) => t.installed).length;

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="arsenal-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><Wrench className="w-7 h-7 text-primary" /> Arsenal</h1>
        <p className="text-sm text-zinc-500 mt-1.5">
          External security-tool catalog with auto-detection and a safe (shell-free) runner.
          {tools && tools !== false ? ` ${installedCount}/${list.length} installed on this host.` : ""}
        </p>
        <p className="text-[11px] text-zinc-600 mt-2 font-mono">
          How it works: install a tool (copy the install hint) → press <span className="text-primary">re-detect</span> → open its card → pick a profile + target → <span className="text-primary">Run</span> → output appears in the console.
        </p>
      </header>

      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input value={q} onChange={(e) => setQ(e.target.value)} data-testid="arsenal-search" placeholder="Search tools…"
            className={inputCls + " pl-9"} />
        </div>
        <button onClick={() => setInstalledOnly((v) => !v)} data-testid="arsenal-installed-only"
          className={`${btnMini} ${installedOnly ? "!text-primary !border-primary/50" : ""}`}>
          {installedOnly ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />} installed only
        </button>
        <button onClick={load} disabled={busy} data-testid="arsenal-refresh" className={btnMini}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />} re-detect
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
        {categories.map((c) => (
          <button key={c} onClick={() => setCat(c)} data-testid={`arsenal-cat-${c.toLowerCase().replace(/\s+/g, "-")}`}
            className={`px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider border transition-colors ${cat === c ? "bg-primary text-black border-primary" : "border-border text-zinc-400 hover:text-primary hover:border-primary/50"}`}>
            {c}
          </button>
        ))}
      </div>

      {tools === null ? (
        <div className="flex items-center justify-center h-64 text-zinc-500 gap-2"><Loader2 className="w-5 h-5 animate-spin" /> <span className="data-label">detecting tools…</span></div>
      ) : filtered.length === 0 ? (
        <div className="border border-dashed border-border p-10 text-center text-zinc-600 text-sm">No tools match.</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4">
          {filtered.map((t) => <ToolCard key={t.id} tool={t} onOpen={setSel} />)}
        </div>
      )}

      {sel && <Detail tool={sel} onClose={() => setSel(null)} />}
    </div>
  );
}
