import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { motion, useInView } from "framer-motion";
import { HeroBackground } from "@/components/HeroBackground";
import {
  Terminal, Globe, Smartphone, Code2, Boxes, Bot, Radar, Fingerprint, Swords,
  Wrench, LayoutDashboard, ArrowRight, ArrowUpRight, ShieldCheck, Activity,
  Cpu, GitBranch, ScanSearch, FileText, Crosshair, ShieldAlert,
} from "lucide-react";

const SEV = { CRITICAL: "#EF4444", HIGH: "#F97316", MEDIUM: "#F59E0B", LOW: "#3B82F6", INFO: "#A1A1AA" };

const MODULES = [
  { id: "scanner", icon: Radar, tag: "Live Active Recon", to: "/app/scanner", span: "lg:col-span-8", feature: true,
    title: "Attack Surface Scanner", desc: "Live port scan, SSL/TLS audit, secret & subdomain discovery, web-vuln probes and CVSS-scored PDF reports — the recon engine that feeds every module." },
  { id: "osint", icon: Fingerprint, tag: "Email · Phone · IMEI", to: "/app/osint", span: "lg:col-span-4",
    title: "OSINT Investigator", desc: "Map a target's public footprint — email, phone, image geolocation, username and device IMEI intelligence." },
  { id: "redteam", icon: Swords, tag: "MITRE ATT&CK", to: "/app/redteam", span: "lg:col-span-4",
    title: "Red Team Ops", desc: "ATT&CK-mapped methodology + AI advisor with APK, cloud-bucket and phishing-simulation analyzers." },
  { id: "toolkit", icon: Wrench, tag: "Utilities", to: "/app/toolkit", span: "lg:col-span-4",
    title: "Hacker Toolkit", desc: "Encoders, hashing, JWT, payload library, live CVE search, DNS/WHOIS and IMEI lookup." },
  { id: "web", icon: Globe, tag: "OWASP · SANS 25", to: "/app/web", span: "lg:col-span-4",
    title: "Web App Security", desc: "AI-driven web pentests built on OWASP + SANS 25 with human-led validation." },
  { id: "mobile", icon: Smartphone, tag: "MASVS · NIST", to: "/app/mobile", span: "lg:col-span-4",
    title: "Mobile Security", desc: "Static + dynamic analysis for iOS and Android. MASVS, NIST, OWASP-aligned." },
  { id: "code", icon: Code2, tag: "OWASP · SANS 25", to: "/app/code-review", span: "lg:col-span-4",
    title: "Secure Code Review", desc: "Human-led and automated source review aligned to OWASP and SANS Top 25." },
  { id: "sca", icon: Boxes, tag: "SBOM · CBOM · CVE", to: "/app/sca", span: "lg:col-span-4",
    title: "Software Composition", desc: "Full SBOM/CBOM generation + CVE detection across every dependency." },
  { id: "ai", icon: Bot, tag: "LLM · GenAI · Agents", to: "/app/ai-pentest", span: "lg:col-span-8", feature: true,
    title: "AI Pentesting", desc: "Adversarial emulations across LLMs, AI agents, GenAI apps, chatbots and AI APIs — streaming red-team operations with a persistent operator." },
  { id: "command", icon: LayoutDashboard, tag: "Live Telemetry", to: "/app", span: "lg:col-span-4",
    title: "Command Dashboard", desc: "Threat map, posture gauge and a live cross-module operations log." },
  { id: "ai-agent", icon: Bot, tag: "Autonomous · Tool-calling", to: "/app/ai-agent", span: "lg:col-span-8", feature: true,
    title: "AI Agent", desc: "InsafeLabs-AI plans and runs the platform's own tools — recon, web checks, DNS, TLS — then writes the report. Autonomous, human-supervised." },
  { id: "vuln-suite", icon: ShieldAlert, tag: "Native · Non-destructive", to: "/app/vuln-suite", span: "lg:col-span-4",
    title: "Vuln Suite", desc: "Built-in web / injection / params / auth / TLS / vhost / DNS testing — pure in-app, no external binaries." },
  { id: "all-tools", icon: Wrench, tag: "129 tools", to: "/app/all-tools", span: "lg:col-span-8",
    title: "All Tools", desc: "One toolbox: Domain, DNS, email-security, network, validation, developer and converter utilities — ~130 tools, most running locally in your browser." },
  { id: "arsenal", icon: Wrench, tag: "95 tools", to: "/app/arsenal", span: "lg:col-span-4",
    title: "Arsenal", desc: "Nmap, Nuclei, SQLmap, ZAP, Burp, Metasploit and 90 more — auto-detected with a safe, shell-free runner." },
  { id: "recon-lab", icon: Radar, tag: "DNS · Email · Subdomains", to: "/app/recon", span: "lg:col-span-4",
    title: "Recon Lab", desc: "DNS, SPF/DMARC/DKIM, subdomain enumeration and takeover checks in one workspace." },
];

const STATS = [
  { k: 27, suffix: "", l: "Offensive Modules" },
  { k: 25, suffix: "+", l: "SANS / OWASP Classes" },
  { k: null, txt: "AI", l: "Driven Emulation" },
  { k: null, txt: "LIVE", l: "Recon Engine" },
];

const STANDARDS = ["OWASP TOP 10", "SANS TOP 25", "MASVS", "NIST 800-115", "MITRE ATT&CK", "CVSS 3.1", "CWE", "PTES"];

const FEED = [
  { t: "[recon]", m: "resolving target.acme.io", c: "#A1A1AA" },
  { t: "[dns]", m: "A 104.21.9.12 · MX 3 · SPF present", c: "#A1A1AA" },
  { t: "[scan]", m: "port 443/tcp OPEN (TLS 1.3)", c: "#22C55E" },
  { t: "[scan]", m: "port 22/tcp OPEN (OpenSSH 9.6)", c: "#22C55E" },
  { t: "[tls]", m: "HSTS header missing", tag: "MEDIUM" },
  { t: "[web]", m: "/admin exposed · 200 OK", tag: "HIGH" },
  { t: "[sca]", m: "lodash@4.17.19 · CVE-2021-23337", tag: "HIGH" },
  { t: "[ai]", m: "prompt-injection vector confirmed", tag: "CRITICAL" },
  { t: "[osint]", m: "gravatar identity linked", c: "#3B82F6" },
  { t: "[report]", m: "CVSS aggregated · PDF ready", c: "#FACC15" },
];

function Reveal({ children, delay = 0, className }) {
  return (
    <motion.div className={className} initial={{ opacity: 0, y: 24 }} whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-70px" }} transition={{ duration: 0.55, delay, ease: [0.22, 1, 0.36, 1] }}>
      {children}
    </motion.div>
  );
}

function Counter({ target, suffix }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!inView) return;
    let raf; const start = performance.now(); const dur = 1200;
    const tick = (now) => { const p = Math.min(1, (now - start) / dur); setVal(Math.round(target * (1 - Math.pow(1 - p, 3)))); if (p < 1) raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, target]);
  return <span ref={ref}>{val}{suffix}</span>;
}

function TerminalFeed() {
  const [feed, setFeed] = useState(FEED);
  const [done, setDone] = useState([]);
  const [typed, setTyped] = useState("");
  const [cur, setCur] = useState(null);

  useEffect(() => {
    let alive = true;
    import("@/lib/api").then(({ api }) =>
      api.get("/dashboard/livefeed")
        .then(({ data }) => { if (alive && data?.lines?.length) setFeed(data.lines); })
        .catch(() => {})
    );
    return () => { alive = false; };
  }, []);

  // Live-coding typewriter: type each line char-by-char, commit, then next.
  useEffect(() => {
    if (!feed.length) return;
    let i = 0, ch = 0, tmo, stopped = false;
    const tick = () => {
      if (stopped) return;
      const line = feed[i % feed.length];
      const text = line.m || "";
      if (ch <= text.length) {
        setCur(line);
        setTyped(text.slice(0, ch));
        ch += 1;
        tmo = setTimeout(tick, 16 + Math.random() * 42);
      } else {
        setDone((prev) => [...prev.slice(-6), { ...line, id: Date.now() + i }]);
        setCur(null); setTyped("");
        i += 1; ch = 0;
        tmo = setTimeout(tick, 400);
      }
    };
    tmo = setTimeout(tick, 300);
    return () => { stopped = true; clearTimeout(tmo); };
  }, [feed]);

  return (
    <div className="relative bg-[#0c0c0c] border border-border shadow-2xl shadow-black/60 overflow-hidden" data-testid="hero-terminal">
      <div className="pointer-events-none absolute inset-0 z-10" style={{ backgroundImage: "linear-gradient(rgba(34,197,94,0.05) 1px, transparent 1px)", backgroundSize: "100% 3px" }} />
      <div className="relative z-20 flex items-center gap-2 px-4 py-2.5 border-b border-border bg-[#0a0a0a]">
        <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" /><span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]" /><span className="w-2.5 h-2.5 rounded-full bg-[#22C55E]" />
        <span className="ml-2 font-mono text-[11px] text-zinc-500">insafelabs@recon: ~/operation — zsh</span>
        <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-[10px] text-emerald-400"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> {feed !== FEED ? "LIVE · REAL SCANS" : "LIVE"}</span>
      </div>
      <div className="relative z-20 p-4 h-72 sm:h-80 overflow-hidden font-mono text-xs leading-relaxed terminal-scroll flex flex-col justify-end">
        {done.map((l) => (
          <div key={l.id} className="flex items-start gap-2 animate-fade-up">
            <span className="text-emerald-400 shrink-0">❯</span>
            <span className="text-primary shrink-0">{l.t}</span>
            <span className="text-zinc-300 flex-1 break-all">{l.m}</span>
            {l.tag && <span className="font-bold shrink-0" style={{ color: SEV[l.tag] }}>[{l.tag}]</span>}
            {l.c && !l.tag && <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: l.c }} />}
          </div>
        ))}
        {cur ? (
          <div className="flex items-start gap-2">
            <span className="text-emerald-400 shrink-0">❯</span>
            <span className="text-primary shrink-0">{cur.t}</span>
            <span className="text-emerald-300 flex-1 break-all">{typed}<span className="inline-block w-1.5 h-3.5 bg-emerald-400 ml-0.5 align-middle animate-pulse" /></span>
          </div>
        ) : (
          <div className="flex items-center gap-2 mt-1"><span className="text-emerald-400">❯</span><span className="w-2 h-4 bg-emerald-400 animate-pulse" /></div>
        )}
      </div>
    </div>
  );
}

const STEPS = [
  { icon: ScanSearch, t: "Reconnaissance", d: "Continuous asset & attack-surface discovery." },
  { icon: Crosshair, t: "Vulnerability Mapping", d: "AI emulation and payload probing." },
  { icon: Activity, t: "Severity Ledger", d: "CVSS scoring and cross-module aggregation." },
  { icon: FileText, t: "Remediation", d: "Developer-ready fixes + client PDF report." },
];

export default function Landing() {
  return (
    <div className="min-h-screen bg-background text-white overflow-x-hidden">
      <header className="fixed top-0 inset-x-0 z-50 glass-header border-b border-white/10">
        <div className="max-w-7xl mx-auto px-5 sm:px-8 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5" data-testid="landing-brand">
            <div className="w-8 h-8 bg-primary flex items-center justify-center glow-primary"><Terminal className="w-5 h-5 text-black" strokeWidth={2.5} /></div>
            <span className="font-heading font-black text-lg tracking-tight">InsafeLabs</span>
          </Link>
          <nav className="hidden md:flex items-center gap-8 text-sm text-zinc-400">
            <a href="#services" className="hover:text-white transition-colors" data-testid="nav-services">Modules</a>
            <a href="#process" className="hover:text-white transition-colors" data-testid="nav-process">Process</a>
            <a href="#capabilities" className="hover:text-white transition-colors" data-testid="nav-capabilities">Capabilities</a>
          </nav>
          <Link to="/app" data-testid="header-cta" className="text-sm bg-primary text-black font-semibold px-4 py-2 hover:bg-yellow-500 transition-colors inline-flex items-center gap-1.5 glow-primary">
            Launch Console <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </header>

      {/* Hero */}
      <section className="relative min-h-screen flex items-center pt-24 pb-16">
        <HeroBackground />
        <div className="absolute inset-0 bg-gradient-to-b from-black/40 via-transparent to-background pointer-events-none" />
        <div className="relative max-w-7xl mx-auto px-5 sm:px-8 w-full">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div className="animate-fade-up">
              <div className="inline-flex items-center gap-2 border border-primary/30 bg-primary/5 px-3 py-1.5 mb-8">
                <span className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse-glow" />
                <span className="data-label !text-primary">AI-Driven · Human-Validated Offensive Security</span>
              </div>
              <h1 className="font-heading font-black tracking-tighter text-5xl sm:text-6xl lg:text-7xl leading-[1.03]">
                Adversarial testing<br />for the <span className="text-primary text-glow">entire</span> stack.
              </h1>
              <p className="text-zinc-400 text-base sm:text-lg mt-6 max-w-xl leading-relaxed">
                InsafeLabs unifies recon, web, mobile, code, dependency, OSINT, red-team and AI-system pentesting into one command center — recon to remediation, CVSS-scored.
              </p>
              <div className="flex flex-wrap items-center gap-4 mt-10">
                <Link to="/app" data-testid="hero-cta" className="bg-primary text-black font-semibold px-6 py-3.5 inline-flex items-center gap-2 hover:bg-yellow-500 hover:-translate-y-px transition-all glow-primary">
                  Enter Console <ArrowRight className="w-4 h-4" />
                </Link>
                <Link to="/app/scanner" data-testid="hero-scan" className="border border-zinc-700 text-white font-medium px-6 py-3.5 inline-flex items-center gap-2 hover:bg-white/5 hover:border-zinc-600 transition-colors">
                  <Radar className="w-4 h-4" /> Run a Live Scan
                </Link>
              </div>
            </div>
            <motion.div initial={{ opacity: 0, scale: 0.96, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} transition={{ duration: 0.7, delay: 0.15, ease: [0.22, 1, 0.36, 1] }}>
              <TerminalFeed />
            </motion.div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-border border border-border mt-16">
            {STATS.map((s) => (
              <div key={s.l} className="bg-[#0c0c0c] p-5" data-testid={`stat-${s.l}`}>
                <p className="font-mono text-3xl sm:text-4xl font-bold text-primary tabular-nums">
                  {s.k != null ? <Counter target={s.k} suffix={s.suffix} /> : s.txt}
                </p>
                <p className="data-label mt-1.5">{s.l}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Standards marquee */}
      <div className="border-y border-border bg-[#0a0a0a] py-4 overflow-hidden" data-testid="standards-marquee">
        <div className="marquee-track">
          {[...STANDARDS, ...STANDARDS].map((s, i) => (
            <span key={i} className="inline-flex items-center gap-6 px-6 font-mono text-xs uppercase tracking-[0.2em] text-zinc-600 shrink-0">
              {s} <span className="w-1 h-1 rounded-full bg-primary/60" />
            </span>
          ))}
        </div>
      </div>

      {/* Modules bento */}
      <section id="services" className="relative max-w-7xl mx-auto px-5 sm:px-8 py-24">
        <Reveal className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-14">
          <div>
            <p className="data-label mb-3">/ Modules</p>
            <h2 className="font-heading text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight max-w-2xl">Ten offensive disciplines, one operating picture</h2>
          </div>
          <p className="text-zinc-500 max-w-sm text-sm">Every module runs an AI engine, maps findings to industry frameworks and feeds a shared, real-time severity ledger.</p>
        </Reveal>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-4 md:gap-6">
          {MODULES.map(({ id, icon: Icon, tag, title, desc, span, to, feature }, idx) => (
            <Reveal key={id} delay={(idx % 3) * 0.06} className={span}>
              <Link to={to} data-testid={`service-${id}`}
                className="group relative h-full bg-[#121212] border border-border p-6 sm:p-8 hover:border-primary/40 hover:-translate-y-0.5 transition-all duration-300 flex flex-col overflow-hidden">
                {feature && <div className="absolute -right-16 -top-16 w-56 h-56 bg-primary/[0.06] blur-3xl rounded-full pointer-events-none group-hover:bg-primary/[0.12] transition-colors" />}
                {feature && id === "scanner" && (
                  <div className="absolute right-6 top-6 w-24 h-24 pointer-events-none opacity-60">
                    <div className="absolute inset-0 rounded-full border border-primary/20" />
                    <div className="absolute inset-0 radar-sweep rounded-full" />
                  </div>
                )}
                <div className="relative flex items-start justify-between">
                  <div className="w-11 h-11 border border-border bg-[#0a0a0a] flex items-center justify-center group-hover:border-primary/40 transition-colors">
                    <Icon className="w-5 h-5 text-primary" />
                  </div>
                  <span className="data-label">{tag}</span>
                </div>
                <h3 className={`relative font-heading font-semibold mt-6 ${feature ? "text-2xl" : "text-xl"}`}>{title}</h3>
                <p className="relative text-zinc-400 mt-3 text-sm leading-relaxed flex-1 max-w-lg">{desc}</p>
                <div className="relative mt-6 pt-4 border-t border-border flex items-center gap-1.5 text-zinc-500 text-xs font-mono uppercase tracking-widest group-hover:text-primary transition-colors">
                  Open module <ArrowUpRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                </div>
              </Link>
            </Reveal>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section id="process" className="relative border-y border-border bg-[#0a0a0a]">
        <div className="max-w-7xl mx-auto px-5 sm:px-8 py-24">
          <Reveal className="mb-14">
            <p className="data-label mb-3">/ Process</p>
            <h2 className="font-heading text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight">Recon to remediation</h2>
          </Reveal>
          <div className="relative">
            <svg className="hidden lg:block absolute top-6 left-0 w-full h-1 pointer-events-none" viewBox="0 0 100 1" preserveAspectRatio="none">
              <line x1="4" y1="0.5" x2="96" y2="0.5" stroke="#FACC15" strokeOpacity="0.5" strokeWidth="0.6" className="beam-line" vectorEffect="non-scaling-stroke" />
            </svg>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {STEPS.map((s, i) => (
                <Reveal key={s.t} delay={i * 0.08}>
                  <div className="relative" data-testid={`step-${i}`}>
                    <div className="w-12 h-12 border border-primary/40 bg-[#0a0a0a] flex items-center justify-center relative z-10 glow-primary">
                      <s.icon className="w-5 h-5 text-primary" />
                    </div>
                    <p className="font-mono text-[10px] text-primary mt-4 tracking-widest">STEP {i + 1}</p>
                    <h3 className="font-heading text-lg font-semibold mt-1">{s.t}</h3>
                    <p className="text-zinc-400 text-sm mt-2 leading-relaxed">{s.d}</p>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Capabilities */}
      <section id="capabilities" className="relative max-w-7xl mx-auto px-5 sm:px-8 py-24">
        <Reveal className="mb-14"><p className="data-label mb-3">/ Capabilities</p><h2 className="font-heading text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight">Built for operators, not checklists</h2></Reveal>
        <div className="grid md:grid-cols-3 gap-px bg-border border border-border">
          {[
            { icon: Cpu, t: "AI-driven emulation", d: "Autonomous attack-vector discovery across web, mobile, code, LLMs and APIs — reviewed by a human operator before it ships." },
            { icon: Activity, t: "Live severity ledger", d: "Critical → Info scoring with OWASP / SANS-25 / CVSS mapping and a real-time dashboard across every operation." },
            { icon: GitBranch, t: "Recon to remediation", d: "Active recon surfaces exposures, scores them with CVSS and exports a client-ready PDF — findings become fixes." },
          ].map(({ icon: Icon, t, d }, i) => (
            <Reveal key={t} delay={i * 0.07}>
              <div className="bg-[#0a0a0a] p-8 h-full hover:bg-[#0c0c0c] transition-colors" data-testid={`cap-${t}`}>
                <Icon className="w-6 h-6 text-primary" />
                <h3 className="font-heading text-lg font-semibold mt-5">{t}</h3>
                <p className="text-zinc-400 text-sm mt-2 leading-relaxed">{d}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="relative max-w-7xl mx-auto px-5 sm:px-8 pb-24">
        <Reveal>
          <div className="relative border border-border bg-[#121212] p-10 sm:p-16 overflow-hidden">
            <div className="absolute -right-20 -top-20 w-80 h-80 bg-primary/10 blur-3xl rounded-full pointer-events-none" />
            <div className="absolute inset-0 scanlines pointer-events-none opacity-40" />
            <div className="relative max-w-2xl">
              <ShieldCheck className="w-9 h-9 text-primary mb-6" />
              <h2 className="font-heading text-4xl sm:text-5xl font-bold tracking-tight">Break it before they do.</h2>
              <p className="text-zinc-400 mt-4 text-lg">Open the InsafeLabs console and run an AI-assisted assessment across any surface in minutes.</p>
              <div className="flex flex-wrap gap-4 mt-8">
                <Link to="/app" data-testid="cta-console" className="bg-primary text-black font-semibold px-6 py-3.5 inline-flex items-center gap-2 hover:bg-yellow-500 transition-colors glow-primary">Enter Console <ArrowRight className="w-4 h-4" /></Link>
                <Link to="/app/scanner" data-testid="cta-scan" className="border border-zinc-700 px-6 py-3.5 hover:bg-white/5 transition-colors inline-flex items-center gap-2"><Radar className="w-4 h-4" /> Launch Attack-Surface Scan</Link>
              </div>
            </div>
          </div>
        </Reveal>
      </section>

      <footer className="border-t border-border">
        <div className="max-w-7xl mx-auto px-5 sm:px-8 py-10 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 bg-primary flex items-center justify-center"><Terminal className="w-4 h-4 text-black" strokeWidth={2.5} /></div>
            <span className="font-heading font-black">InsafeLabs</span>
            <span className="data-label ml-2">Offensive Security Platform</span>
          </div>
          <p className="font-mono text-xs text-zinc-600">© 2026 InsafeLabs · For authorized testing only</p>
        </div>
      </footer>
    </div>
  );
}
