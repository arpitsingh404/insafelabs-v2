import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/lib/api";
import { Crosshair, Hammer, Send, Zap, Download, Radio, Target, ChevronRight, Loader2 } from "lucide-react";

const PHASES = [
  { n: 1, id: "recon", icon: Crosshair, name: "Reconnaissance", metric: "recon_scans",
    desc: "Passive & active footprinting — who/what is exposed.",
    tools: [["Recon Lab", "/app/recon"], ["Attack Surface", "/app/scanner"], ["OSINT", "/app/osint"], ["Arsenal (amass/subfinder)", "/app/arsenal"]] },
  { n: 2, id: "weaponization", icon: Hammer, name: "Weaponization", metric: null,
    desc: "Turn findings into testable techniques / payloads.",
    tools: [["Red Team Ops", "/app/redteam"], ["Reverse Eng", "/app/binre"], ["Crypto Lab", "/app/crypto"], ["Arsenal (searchsploit)", "/app/arsenal"]] },
  { n: 3, id: "delivery", icon: Send, name: "Delivery", metric: null,
    desc: "How a payload/attack reaches the target (phishing, web delivery).",
    tools: [["Red Team Ops (phishing sim)", "/app/redteam"], ["Web Inspector", "/app/web-inspect"], ["Bug Bounty", "/app/bugbounty"]] },
  { n: 4, id: "exploitation", icon: Zap, name: "Exploitation", metric: "total_findings",
    desc: "Validate the vulnerabilities that are actually exploitable.",
    tools: [["Vuln Suite (injection)", "/app/vuln-suite"], ["WAPT", "/app/wapt"], ["VAPT", "/app/vapt"], ["Arsenal (sqlmap/nuclei)", "/app/arsenal"], ["AI Pentest", "/app/ai-pentest"]] },
  { n: 5, id: "installation", icon: Download, name: "Installation", metric: "apk_scans",
    desc: "Persistence / implant analysis on hosts and apps.",
    tools: [["Mobile Testing", "/app/mobile"], ["Red Team Ops (APK)", "/app/redteam"], ["USB Bridge", "/app/device"], ["Reverse Eng", "/app/binre"]] },
  { n: 6, id: "c2", icon: Radio, name: "Command & Control", metric: "network_scans",
    desc: "Comms / pivoting / egress paths.",
    tools: [["Network Map (pivot)", "/app/netmap"], ["Proxy Chain", "/app/proxy-chain"], ["Operators Console", "/app/soc"], ["Arsenal (netexec/impacket)", "/app/arsenal"]] },
  { n: 7, id: "objectives", icon: Target, name: "Actions on Objectives", metric: "secrets_total",
    desc: "Impact: data, credentials, business risk — and reporting.",
    tools: [["Findings", "/app/findings"], ["Operation Report", "/app/operation"], ["Bug Bounty", "/app/bugbounty"], ["AI Agent", "/app/ai-agent"], ["SOC", "/app/soc"]] },
];

export default function KillChain() {
  const [stats, setStats] = useState(null);
  useEffect(() => { api.get("/dashboard/stats").then(({ data }) => setStats(data)).catch(() => setStats(false)); }, []);
  if (!stats) return <div className="flex items-center justify-center h-96 text-zinc-500 gap-2"><Loader2 className="w-5 h-5 animate-spin" /> <span className="data-label">loading…</span></div>;

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="killchain-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Offensive Modules</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><Target className="w-7 h-7 text-primary" /> Cyber Kill Chain</h1>
        <p className="text-sm text-zinc-500 mt-1.5">Lockheed Martin kill chain mapped to the platform's modules — see what tooling you have at every phase.</p>
      </header>

      <div className="space-y-3">
        {PHASES.map((p, i) => {
          const Icon = p.icon;
          const count = p.metric ? (stats[p.metric] ?? 0) : null;
          return (
            <div key={p.id} className="relative" data-testid={`killchain-${p.id}`}>
              <div className="bg-[#121212] border border-border p-4 flex items-start gap-4 hover:border-primary/40 transition-colors">
                <div className="w-11 h-11 shrink-0 border border-primary/40 bg-primary/10 grid place-items-center">
                  <Icon className="w-5 h-5 text-primary" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-[10px] text-zinc-600">PHASE {p.n}</span>
                    <h3 className="font-heading text-base font-semibold text-white">{p.name}</h3>
                    {count != null && <span className="data-label border border-border px-1.5 py-0.5">{count} recorded</span>}
                  </div>
                  <p className="text-sm text-zinc-500 mt-1">{p.desc}</p>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {p.tools.map(([label, to]) => (
                      <Link key={label} to={to} className="inline-flex items-center gap-1 text-[11px] font-mono border border-border px-2 py-0.5 text-zinc-400 hover:text-primary hover:border-primary/50 transition-colors" data-testid={`killchain-${p.id}-${label.split(" ")[0].toLowerCase()}`}>
                        {label} <ChevronRight className="w-3 h-3" />
                      </Link>
                    ))}
                  </div>
                </div>
              </div>
              {i < PHASES.length - 1 && <div className="ml-[26px] h-3 w-px bg-border" />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
