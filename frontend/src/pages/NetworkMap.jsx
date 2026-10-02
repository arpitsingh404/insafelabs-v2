import { useState, useRef, useEffect } from "react";
import { api, formatApiError } from "@/lib/api";
import { safeHttpUrl } from "@/lib/safeUrl";
import { toast } from "sonner";
import {
  Share2, Loader2, Radar, Server, Bot, Send, Router as RouterIcon, Download, FileJson,
  Cpu, Database, Printer, Camera, Monitor, Terminal, Globe, Mail, HardDrive, Sparkles,
  Wifi, Radio, Activity, KeyRound,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60";

const PROFILES = [
  { k: "quick", label: "Quick", desc: "8 ports · fast" },
  { k: "standard", label: "Standard", desc: "23 common" },
  { k: "deep", label: "Deep", desc: "66 · IoT/DB/print" },
  { k: "stealth", label: "Stealth", desc: "slow · low-noise" },
  { k: "custom", label: "Custom", desc: "your ports" },
];

function deviceIcon(type) {
  const m = {
    "Router / Firewall": RouterIcon, "Printer": Printer, "IP Camera / NVR": Camera,
    "IoT Device": Cpu, "Database Server": Database, "Mail Server": Mail, "DNS Server": Globe,
    "Windows Machine": Monitor, "Web Server": Server, "Linux / Unix Host": Terminal, "Host": HardDrive,
  };
  return m[type] || HardDrive;
}

function Toggle({ label, checked, onChange, testid }) {
  return (
    <button type="button" onClick={() => onChange(!checked)} data-testid={testid}
      className={`px-3 py-1.5 text-[11px] font-mono uppercase border transition-colors ${checked ? "border-primary text-primary bg-primary/5" : "border-zinc-800 text-zinc-500 hover:text-zinc-300"}`}>
      {checked ? "● " : "○ "}{label}
    </button>
  );
}

function Constellation({ hosts }) {
  const W = 640, H = 420, cx = W / 2, cy = H / 2;
  const n = Math.max(hosts.length, 1);
  const R = Math.min(160, 70 + n * 12);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ background: "#0a0a0a" }} data-testid="netmap-graph">
      <defs>
        <radialGradient id="op-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#FACC15" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#FACC15" stopOpacity="0" />
        </radialGradient>
      </defs>
      {hosts.map((h, i) => {
        const a = (i / n) * Math.PI * 2 - Math.PI / 2;
        const x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
        const size = Math.min(22, 8 + (h.service_count || 0) * 1.5);
        return (
          <g key={h.ip}>
            <line x1={cx} y1={cy} x2={x} y2={y} stroke="#FACC15" strokeOpacity="0.35" strokeWidth="1" strokeDasharray="4 4">
              <animate attributeName="stroke-dashoffset" from="16" to="0" dur="1.2s" repeatCount="indefinite" />
            </line>
            <circle cx={x} cy={y} r={size} fill="#F97316" fillOpacity="0.15" stroke="#F97316" strokeWidth="1.5" />
            <text x={x} y={y + size + 12} textAnchor="middle" fill="#a1a1aa" fontSize="10" fontFamily="monospace">{h.rdns || h.ip}</text>
            <text x={x} y={y + 3} textAnchor="middle" fill="#F97316" fontSize="10" fontFamily="monospace">{h.service_count}</text>
          </g>
        );
      })}
      <circle cx={cx} cy={cy} r="46" fill="url(#op-glow)" />
      <circle cx={cx} cy={cy} r="16" fill="#FACC15" />
      <text x={cx} y={cy + 34} textAnchor="middle" fill="#FACC15" fontSize="11" fontFamily="monospace" fontWeight="bold">OPERATOR</text>
    </svg>
  );
}

export default function NetworkMap() {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("standard");
  const [ports, setPorts] = useState("");
  const [neighborhood, setNeighborhood] = useState(false);
  const [rdns, setRdns] = useState(true);
  const [banners, setBanners] = useState(true);
  const [osGuess, setOsGuess] = useState(true);

  const [scanning, setScanning] = useState(false);
  const [phase, setPhase] = useState("");
  const [progress, setProgress] = useState(0);
  const [res, setRes] = useState(null);
  const pollRef = useRef(null);
  const graphRef = useRef(null);

  const [scenario, setScenario] = useState("");
  const [pivBusy, setPivBusy] = useState(false);
  const [pivot, setPivot] = useState("");
  const [aiBusy, setAiBusy] = useState(false);
  const [aiSummary, setAiSummary] = useState("");
  const [openHosts, setOpenHosts] = useState({});

  const copy = (t) => navigator.clipboard?.writeText(t).then(() => toast.success("Copied")).catch(() => toast.error("Copy failed"));

  useEffect(() => () => clearInterval(pollRef.current), []);

  const exportPng = () => {
    const svg = graphRef.current?.querySelector("svg");
    if (!svg) return toast.error("No graph to export");
    const xml = new XMLSerializer().serializeToString(svg);
    const url = URL.createObjectURL(new Blob([xml], { type: "image/svg+xml;charset=utf-8" }));
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = 1280; canvas.height = 840;
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#0a0a0a"; ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);
      canvas.toBlob((b) => { const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href = u; a.download = "insafelabs-network.png"; a.click(); URL.revokeObjectURL(u); });
      toast.success("Graph PNG exported");
    };
    img.onerror = () => { URL.revokeObjectURL(url); toast.error("PNG export failed"); };
    img.src = url;
  };

  const exportJson = () => {
    if (!res) return;
    const data = { target: res.target, options: res.options, scanned: res.scanned, hosts_up: res.hosts_up, device_summary: res.device_summary, hosts: res.hosts, nodes: res.nodes, edges: res.edges, notes: res.notes };
    const u = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
    const a = document.createElement("a"); a.href = u; a.download = "insafelabs-network.json"; a.click(); URL.revokeObjectURL(u);
    toast.success("Graph JSON exported");
  };

  const run = async (e, override = {}) => {
    if (e?.preventDefault) e.preventDefault();
    const tgt = (override.target ?? target).trim();
    if (!tgt) return toast.error("Enter a host, IP, or CIDR");
    clearInterval(pollRef.current);
    setScanning(true); setRes(null); setAiSummary(""); setPhase("queued"); setProgress(5);
    const payload = { target: tgt, profile: override.profile ?? profile, ports, neighborhood, rdns, banners, os_guess: osGuess };
    try {
      const { data } = await api.post("/offensive/network/scan", payload);
      const id = data.id;
      let ticks = 0;
      pollRef.current = setInterval(async () => {
        ticks++;
        try {
          const { data: d } = await api.get(`/offensive/network/scan/${id}`);
          setPhase(d.phase || d.status); setProgress(d.progress || 0);
          if (d.status === "completed" || d.status === "failed" || ticks > 80) {
            clearInterval(pollRef.current);
            setScanning(false);
            setRes(d);
            if (d.status === "completed") toast.success(`${d.hosts_up}/${d.scanned} host(s) up`);
            else toast.error(d.error || "Scan failed");
          }
        } catch { /* keep polling */ }
      }, 2000);
    } catch (err) {
      setScanning(false);
      toast.error(formatApiError(err.response?.data?.detail) || "Scan failed");
    }
  };

  const scanLocalSegment = async () => {
    try {
      const { data } = await api.get("/offensive/network/interfaces");
      const seg = data.segments?.[0];
      if (!seg) return toast.error("No local segment detected on the backend");
      setTarget(seg.cidr);
      toast.message(`Discovering the server's own segment ${seg.cidr}`, { description: "This is the backend's network vantage — not your personal LAN." });
      run(null, { target: seg.cidr, profile: "quick" });
    } catch { toast.error("Could not detect local segment"); }
  };

  const analyze = async () => {
    if (!res?.id) return;
    setAiBusy(true); setAiSummary("");
    try {
      const { data } = await api.post(`/offensive/network/analyze/${res.id}`, {}, { timeout: 60000 });
      setAiSummary(data.answer);
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Analyzer failed"); }
    finally { setAiBusy(false); }
  };

  const advise = async () => {
    if (!scenario.trim()) return toast.error("Describe the pivot scenario");
    setPivBusy(true); setPivot("");
    try {
      const { data } = await api.post("/offensive/network/pivot", { scenario: scenario.trim() }, { timeout: 60000 });
      setPivot(data.answer);
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Advisor failed"); }
    finally { setPivBusy(false); }
  };

  const devSummary = res?.device_summary || {};

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="netmap-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary"><Share2 className="w-6 h-6 text-primary" /></div>
        <div>
          <p className="data-label mb-1">/ Network</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">Network Mapper &amp; Pivoting</h1>
          <p className="text-sm text-zinc-500 mt-1">Active host discovery, deep port/service mapping, device fingerprinting, neighborhood sweeps, a live network graph, and an AI attack-path advisor. Authorized targets only.</p>
        </div>
      </div>

      {/* Scan console */}
      <div className="bg-[#121212] border border-border p-5 space-y-4" data-testid="netmap-console">
        <form onSubmit={run} className="flex flex-col sm:flex-row gap-2">
          <input className={inputCls} value={target} onChange={(e) => setTarget(e.target.value)} data-testid="netmap-target" placeholder="scanme.nmap.org  ·  45.33.32.156  ·  93.184.216.0/28" />
          <button className={btnCls} disabled={scanning} data-testid="netmap-run">{scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />} Start Scan</button>
          <button type="button" onClick={scanLocalSegment} disabled={scanning} data-testid="netmap-local"
            className="border border-zinc-800 text-zinc-300 px-4 py-2.5 text-sm inline-flex items-center justify-center gap-2 hover:text-primary hover:border-primary/50 transition-colors disabled:opacity-60">
            <Wifi className="w-4 h-4" /> Discover Local Segment
          </button>
        </form>

        {/* Profiles */}
        <div>
          <p className="data-label mb-2">Scan Profile</p>
          <div className="flex flex-wrap gap-2" data-testid="netmap-profiles">
            {PROFILES.map((p) => (
              <button key={p.k} type="button" onClick={() => setProfile(p.k)} data-testid={`netmap-profile-${p.k}`}
                className={`px-3 py-2 border text-left transition-colors ${profile === p.k ? "border-primary bg-primary/5" : "border-zinc-800 hover:border-zinc-700"}`}>
                <span className={`block font-mono text-xs font-bold ${profile === p.k ? "text-primary" : "text-zinc-300"}`}>{p.label}</span>
                <span className="block text-[10px] text-zinc-600">{p.desc}</span>
              </button>
            ))}
          </div>
          {profile === "custom" && (
            <input className={`${inputCls} mt-2`} value={ports} onChange={(e) => setPorts(e.target.value)} data-testid="netmap-ports"
              placeholder="custom ports — e.g. 22,80,443,8000-8100,9200" />
          )}
        </div>

        {/* Toggles */}
        <div className="flex flex-wrap gap-2" data-testid="netmap-toggles">
          <Toggle label="Neighborhood /24" checked={neighborhood} onChange={setNeighborhood} testid="netmap-toggle-neighborhood" />
          <Toggle label="Device Fingerprint" checked={osGuess} onChange={setOsGuess} testid="netmap-toggle-os" />
          <Toggle label="Banner Grab" checked={banners} onChange={setBanners} testid="netmap-toggle-banners" />
          <Toggle label="Reverse DNS" checked={rdns} onChange={setRdns} testid="netmap-toggle-rdns" />
        </div>
        {neighborhood && <p className="text-[11px] text-zinc-600 font-mono">Neighborhood mode: a single IP is expanded to its whole /24 to map nearby devices (capped at 64 hosts).</p>}
      </div>

      {/* Progress */}
      {scanning && (
        <div className="border border-border bg-[#0c0c0c] p-4" data-testid="netmap-progress">
          <div className="flex items-center justify-between mb-2">
            <span className="data-label text-primary flex items-center gap-2"><Loader2 className="w-3.5 h-3.5 animate-spin" /> {phase || "scanning"}…</span>
            <span className="font-mono text-xs text-zinc-500">{progress}%</span>
          </div>
          <div className="h-1.5 bg-zinc-900 overflow-hidden">
            <div className="h-full bg-primary transition-all duration-500" style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {res && res.status === "completed" && (
        <div className="space-y-4" data-testid="netmap-result">
          {/* Device summary */}
          {Object.keys(devSummary).length > 0 && (
            <div className="border border-border bg-[#0c0c0c] p-4" data-testid="netmap-devsummary">
              <div className="flex items-center gap-2 mb-3"><Radio className="w-4 h-4 text-primary" /><span className="data-label">Discovered Devices</span>
                {res.options && <span className="data-label text-zinc-600 ml-auto">{res.options.profile} · {res.options.port_count} ports · {res.hosts_up}/{res.scanned} up</span>}
              </div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(devSummary).map(([type, count]) => {
                  const Icon = deviceIcon(type);
                  return (
                    <span key={type} className="inline-flex items-center gap-1.5 border border-primary/30 bg-primary/5 px-2.5 py-1.5" data-testid={`netmap-devtype-${type}`}>
                      <Icon className="w-3.5 h-3.5 text-primary" />
                      <span className="font-mono text-[11px] text-zinc-300">{type}</span>
                      <span className="font-mono text-[11px] text-primary font-bold">×{count}</span>
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="border border-border bg-[#0c0c0c]">
              <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border"><Share2 className="w-4 h-4 text-primary" /><span className="data-label">Network Graph</span>
                <div className="ml-auto flex items-center gap-2">
                  <button onClick={exportPng} data-testid="netmap-export-png" className="border border-border px-2 py-1 text-[10px] font-mono uppercase text-zinc-400 hover:text-primary hover:border-primary/50 inline-flex items-center gap-1"><Download className="w-3 h-3" /> PNG</button>
                  <button onClick={exportJson} data-testid="netmap-export-json" className="border border-border px-2 py-1 text-[10px] font-mono uppercase text-zinc-400 hover:text-primary hover:border-primary/50 inline-flex items-center gap-1"><FileJson className="w-3 h-3" /> JSON</button>
                  <span className="data-label text-zinc-500">{res.hosts_up}/{res.scanned} up</span>
                </div>
              </div>
              <div ref={graphRef}><Constellation hosts={res.hosts || []} /></div>
            </div>
            <div className="border border-border bg-[#0c0c0c]">
              <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border"><Server className="w-4 h-4 text-primary" /><span className="data-label">Hosts &amp; Services</span></div>
              <div className="p-4 max-h-[460px] overflow-y-auto space-y-3">
                {(res.hosts || []).length === 0 ? <p className="text-sm text-zinc-500">No live hosts / open services found.</p> :
                  res.hosts.map((h, i) => {
                    const Icon = deviceIcon(h.device_type);
                    return (
                      <div key={i} className="border border-border bg-[#0a0a0a] p-3" data-testid={`netmap-host-${i}`}>
                        <div className="flex items-center gap-2 flex-wrap">
                          <Icon className="w-4 h-4 text-primary shrink-0" />
                          <p className="font-mono text-sm text-white">{h.ip}</p>
                          {h.rdns && <span className="font-mono text-[11px] text-zinc-500">· {h.rdns}</span>}
                          {typeof h.latency_ms === "number" && <span className="font-mono text-[10px] text-emerald-400 inline-flex items-center gap-0.5 ml-auto"><Activity className="w-3 h-3" />{h.latency_ms}ms</span>}
                        </div>
                        <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                          <span className="font-mono text-[10px] text-primary border border-primary/30 px-1.5 py-0.5">{h.device_type || "Host"}</span>
                          {h.os_guess && h.os_guess !== "Unknown" && <span className="font-mono text-[10px] text-sky-300 border border-sky-400/20 px-1.5 py-0.5">OS: {h.os_guess}</span>}
                          {(h.tags || []).map((t, j) => <span key={j} className="font-mono text-[10px] text-zinc-500 border border-zinc-800 px-1.5 py-0.5">{t}</span>)}
                        </div>
                        <div className="flex flex-wrap gap-1.5 mt-2">
                          {(h.services || []).map((s, j) => (
                            <span key={j} className="font-mono text-[10px] border border-orange-500/40 bg-orange-500/5 text-orange-300 px-2 py-1" title={s.banner || ""}>{s.service}:{s.port}</span>
                          ))}
                        </div>
                        {h.access && ((h.access.creds || []).length + (h.access.access || []).length + (h.access.notes || []).length) > 0 && (
                          <>
                            <button onClick={() => setOpenHosts((o) => ({ ...o, [i]: !o[i] }))} data-testid={`netmap-access-toggle-${i}`}
                              className="mt-2 text-[10px] font-mono uppercase text-primary border border-primary/30 px-2 py-1 inline-flex items-center gap-1 hover:bg-primary/10">
                              <KeyRound className="w-3 h-3" /> Default creds &amp; access{(h.access.creds || []).length > 0 && <span className="text-zinc-500">({h.access.creds.length})</span>}
                            </button>
                            {openHosts[i] && (
                              <div className="mt-2 border border-primary/20 bg-[#0c0c0c] p-3 space-y-3" data-testid={`netmap-access-${i}`}>
                                {h.access.vendor && <p className="text-[11px] text-zinc-400">Vendor guess: <span className="text-primary font-mono">{h.access.vendor}</span></p>}
                                {(h.access.access || []).length > 0 && (
                                  <div>
                                    <p className="data-label mb-1">Access URLs</p>
                                    <div className="space-y-1">
                                      {h.access.access.map((a, k) => (
                                        <div key={k} className="flex items-center gap-2 font-mono text-[11px]">
                                          <span className="text-[9px] text-zinc-600 border border-zinc-800 px-1 shrink-0">{a.type}</span>
                                          {a.type === "Web UI"
                                            ? <a href={safeHttpUrl(a.url)} target="_blank" rel="noreferrer" className="text-sky-300 hover:underline truncate">{a.url}</a>
                                            : <button onClick={() => copy(a.url)} className="text-zinc-300 hover:text-primary truncate text-left" title="copy">{a.url}</button>}
                                          <span className="text-zinc-600 text-[10px] ml-auto shrink-0 hidden sm:inline">{a.note}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {(h.access.creds || []).length > 0 && (
                                  <div>
                                    <p className="data-label mb-1">Default credentials to try</p>
                                    <div className="flex flex-wrap gap-1.5">
                                      {h.access.creds.map((c, k) => (
                                        <button key={k} onClick={() => copy(`${c.user}:${c.pass}`)} title="copy user:pass"
                                          className="font-mono text-[10px] border border-severity-high/40 bg-severity-high/5 text-severity-high px-1.5 py-0.5 hover:bg-severity-high/15">
                                          {c.user || "(empty)"} : {c.pass || "(empty)"}
                                        </button>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {(h.access.notes || []).length > 0 && (
                                  <div>
                                    <p className="data-label mb-1 text-severity-high">Exposure notes</p>
                                    {h.access.notes.map((n, k) => <p key={k} className="font-mono text-[11px] text-orange-300">• {n}</p>)}
                                  </div>
                                )}
                                {(h.access.commands || []).length > 0 && (
                                  <div>
                                    <p className="data-label mb-1">Try commands</p>
                                    <div className="space-y-1">
                                      {h.access.commands.map((c, k) => (
                                        <button key={k} onClick={() => copy(c)} title="copy"
                                          className="w-full text-left font-mono text-[10px] text-zinc-300 bg-[#0a0a0a] border border-zinc-800 px-2 py-1 hover:border-primary/40 truncate">{c}</button>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                <p className="text-[9px] text-zinc-600">Default-credential references for AUTHORIZED testing only.</p>
                              </div>
                            )}
                          </>
                        )}
                      </div>
                    );
                  })}
              </div>
            </div>
          </div>

          {/* AI attack path */}
          <div className="border border-border bg-[#0c0c0c]" data-testid="netmap-ai">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border">
              <Sparkles className="w-4 h-4 text-primary" /><span className="data-label">AI Attack-Path Briefing</span>
              <button onClick={analyze} disabled={aiBusy || (res.hosts || []).length === 0} data-testid="netmap-analyze"
                className="ml-auto border border-primary/40 text-primary px-3 py-1 text-[11px] font-mono uppercase hover:bg-primary/10 inline-flex items-center gap-1.5 disabled:opacity-50">
                {aiBusy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Bot className="w-3 h-3" />} {aiSummary ? "Regenerate" : "Analyze"}
              </button>
            </div>
            <div className="p-4">
              {aiSummary
                ? <div className="font-mono text-[13px] text-zinc-200 whitespace-pre-wrap leading-relaxed max-h-[420px] overflow-y-auto" data-testid="netmap-ai-out">{aiSummary}</div>
                : <p className="text-sm text-zinc-600">Generate a prioritized, AI-written attack path from the discovered hosts, services, and device types.</p>}
            </div>
          </div>

          {(res.notes || []).length > 0 && (
            <div className="bg-[#0a0a0a] border border-border p-4" data-testid="netmap-notes">
              <p className="data-label mb-2">Notes</p>
              {res.notes.map((n, i) => <p key={i} className="font-mono text-[11px] text-zinc-500">• {n}</p>)}
            </div>
          )}
        </div>
      )}

      {/* Pivot advisor */}
      <div className="bg-[#121212] border border-border" data-testid="netmap-pivot">
        <div className="flex items-center gap-2 px-5 py-3 border-b border-border"><RouterIcon className="w-4 h-4 text-primary" /><span className="font-heading text-sm font-semibold">Pivoting Advisor</span><Bot className="w-3.5 h-3.5 text-zinc-500 ml-1" /></div>
        <div className="p-5 space-y-3">
          <div className="flex flex-col sm:flex-row gap-2">
            <input className={inputCls} value={scenario} onChange={(e) => setScenario(e.target.value)} data-testid="netmap-pivot-input" placeholder="e.g. foothold on 10.0.0.5, need to reach 10.0.1.0/24 behind it" />
            <button className={btnCls} disabled={pivBusy} onClick={advise} data-testid="netmap-pivot-run">{pivBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />} Get Recipes</button>
          </div>
          {pivot && <div className="border border-border bg-[#0a0a0a] p-4 font-mono text-[13px] text-zinc-200 whitespace-pre-wrap leading-relaxed max-h-[420px] overflow-y-auto" data-testid="netmap-pivot-out">{pivot}</div>}
        </div>
      </div>
    </div>
  );
}
