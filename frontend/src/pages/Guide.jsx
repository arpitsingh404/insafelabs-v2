import { useState } from "react";
import {
  BookOpen, ChevronDown, ChevronRight, Search, Rocket, Radar, Fingerprint,
  Swords, Network, Share2, Binary, Wrench, Usb, Bot, Cpu, CreditCard, ShieldAlert,
  KeyRound, Link2, Settings as SettingsIcon, Activity, Layers, Target, Scale, Globe,
} from "lucide-react";

const QUICK = [
  "Left sidebar me koi bhi module — har ek alag capability hai. Ctrl/⌘+K se kisi bhi module par jump karo.",
  "Target daalo (domain/IP/URL) aur Run dabao. Sirf AUTHORIZED targets par hi use karo.",
  "Confused ho? SOC (health + IOC check) ya Playbooks (one-click workflows) se shuru karo.",
  "Full assessment ke liye VAPT (recon→infra→web→vuln) ya WAPT (OWASP Top 10) chalao — report download milti hai.",
  "Kisi client ko test karne se pehle NDA / Legal me authorization letter bana kar sign karwao.",
];

const GUIDES = [
  {
    id: "soc", icon: Activity, tag: "Operations", title: "SOC — Security Operations Center",
    desc: "Ek jagah: system health, threat counts, alert triage, operations log, aur IOC/blacklist check + watchlist.",
    steps: [
      "Open SOC — top par health chips (server/mongo/AI) aur live counts dikhte hain.",
      "IOC / Blacklist check: koi IP, domain ya email daalo → 12 IP RBLs + 5 domain blacklists (Spamhaus, SURBL, DroneBL…) ke against check.",
      "Result clean/listed dikhata hai; 'watchlist' button se track karo, alert triage aur ops-log neeche.",
    ],
    example: "IOC: 1.2.3.4  ·  example.com  ·  user@example.com",
    tip: "Red dot = kisi blacklist par listed. Clean = koi hit nahi.",
  },
  {
    id: "vapt", icon: ShieldAlert, tag: "Assessment", title: "VAPT — full assessment",
    desc: "Phased Vulnerability Assessment + Penetration Test: Recon → Infrastructure → Web → Vuln scan. Grade + risk score + report.",
    steps: [
      "Open VAPT, target daalo (URL / host / domain) aur Run VAPT.",
      "Har phase expand karo — findings (severity, evidence, remediation) dikhte hain.",
      "'download report (.md)' se poora report lo, aur 'AI executive summary' se AI ka summary banao.",
    ],
    example: "https://acme.com  ·  10.0.0.0/24  ·  acme.com",
    tip: "Non-destructive — findings manual validation maangte hain.",
  },
  {
    id: "wapt", icon: Globe, tag: "Assessment", title: "WAPT — OWASP Top 10 web test",
    desc: "Web application pentest OWASP Top 10 (2021) ke hisaab se mapped: A01 access control, A02 crypto, A03 injection, A05 misconfig, A07 auth + rate-limit…",
    steps: [
      "Open WAPT, web URL daalo (params ke saath, e.g. ?id=1) aur Run WAPT.",
      "Har OWASP category expand karke findings dekho.",
      "Report (.md) download karo ya AI executive summary banao.",
    ],
    example: "https://shop.acme.com/item?id=1",
    tip: "IDOR aur rate-limit checks A01/A07 me included hain.",
  },
  {
    id: "playbooks", icon: Layers, tag: "Guided", title: "Playbooks — one-click workflows",
    desc: "Curated tool-sequences: External Recon, Web Quick, Web Deep, Infra/TLS, Full Sweep.",
    steps: [
      "Open Playbooks aur ek card chuno.",
      "Target do aur 'Run playbook' dabao — steps live execute hote hain.",
      "Har step expand karke raw result dekho; total findings summary me.",
    ],
    example: "Full Sweep → https://acme.com",
    tip: "Pehli baar test kar rahe ho? Playbooks sabse aasan hai.",
  },
  {
    id: "killchain", icon: Target, tag: "Methodology", title: "Cyber Kill Chain",
    desc: "Lockheed Martin ke 7 phases (Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Objectives) platform ke modules se mapped.",
    steps: [
      "Open Kill Chain.",
      "Har phase par uske relevant modules ke quick links milte hain.",
      "Engagement planning / report methodology ke liye use karo.",
    ],
    example: "Exploitation phase → Vuln Suite / WAPT / VAPT / Arsenal",
    tip: "Coverage count dikhata hai ki us phase me kitni activity hui.",
  },
  {
    id: "proxy-chain", icon: Network, tag: "Infra", title: "Proxy Chain",
    desc: "Proxies ko individually test karo, ya proxychains-style real multi-hop tunnel banao (http/https CONNECT).",
    steps: [
      "Open Proxy Chain. Proxies ek-ek line par daalo (chain order me).",
      "'Test each' = har proxy se target reach karke exit-IP dikhata hai.",
      "'Chain' = hop-by-hop tunnel: proxy1→proxy2→…→target; per-hop status + final response.",
    ],
    example: "127.0.0.1:8080  ·  http://user:pass@1.2.3.4:3128",
    tip: "Chaining sirf http(s) proxies par (SOCKS individually test hote hain).",
  },
  {
    id: "legal", icon: Scale, tag: "Legal", title: "NDA & Legal documents",
    desc: "NDA, Pentest Authorization / Rules of Engagement, aur Scope letter generate karo — client ko sign karwane ke liye.",
    steps: [
      "Open NDA / Legal aur template chuno (Mutual NDA / Pentest Authorization / Scope letter).",
      "Details bharo: aapka naam/org, client, date, jurisdiction, scope, duration, contact.",
      "Generate → preview → '.md' ya '.pdf' download karke client se sign karwao.",
    ],
    example: "Template: Pentest Authorization · Scope: *.acme.com",
    tip: "Ye template hai — legal advice nahi; important engagements me counsel se review karwao.",
  },
  {
    id: "ai-agent", icon: Bot, tag: "AI", title: "AI Agent — let the AI run the tools",
    desc: "Give an instruction + target; InsafeLabs-AI plans a sequence of the app's own tools, runs them, and writes the report.",
    steps: [
      "Open AI Agent. Expand 'Tools the AI can control' to see the 15 tools it may use.",
      "Type an instruction (e.g. 'Do a full security assessment and tell me the biggest risks') and the target.",
      "Hit Run agent — the Plan shows the chosen tools, Execution shows each step's raw result, and AI Report is the write-up.",
    ],
    example: "Instruction: 'check web security and email spoofing' · Target: https://example.com",
    tip: "The AI can ONLY use the listed tools — it cannot run anything else on your machine.",
  },
  {
    id: "vuln-suite", icon: ShieldAlert, tag: "Native", title: "Vuln Suite — built-in security testing",
    desc: "Native (in-app) non-destructive testing: Web Scan, Injection (SQLi/XSS/CRLF/redirect), Params, Auth Form, TLS, VHost, DNS/AXFR, Wordlist.",
    steps: [
      "Open Vuln Suite and pick a tab.",
      "Web Scan → full passive check of a URL (headers grade, cookies, CORS, sensitive files, TLS).",
      "Injection → give a URL WITH parameters (?id=1) to test SQLi/XSS/CRLF/open-redirect.",
      "Params finds hidden parameters; Auth Form analyses a login page; VHost does virtual-host discovery; DNS/AXFR checks zone transfer + SPF; Wordlist generates a targeted wordlist.",
    ],
    example: "Web Scan: https://example.com · Injection: https://target/x?id=1",
    tip: "All checks are passive/non-destructive — nothing is exploited or modified.",
  },
  {
    id: "all-tools", icon: Wrench, tag: "Utilities", title: "All Tools — one toolbox for everything",
    desc: "12 categories / ~130 utilities: Domain, DNS, Validation, General, Status, Sysadmin, Formatter, Content, Developer, Thread Dump, Converter, Cloud.",
    steps: [
      "Open All Tools. Use the search box or pick a category tab.",
      "Converters, formatters, encoders, validators and calculators run locally in your browser (private, instant).",
      "Network tools (DNS, WHOIS, TLS, port, HTTP headers, blacklist, curl, cloud diagram…) use the backend or render locally.",
      "DNS Propagation compares answers across 6 public resolver networks at once.",
      "Copy or download any result.",
    ],
    example: "DNS Analysis: example.com · Whois: github.com · JSON→YAML · Cloud Architecture Diagram",
    tip: "Local tools never leave your browser; network tools are read-only diagnostics. Authorized use only.",
  },
  {
    id: "arsenal", icon: Wrench, tag: "Tools", title: "Arsenal — external security-tool catalog",
    desc: "95 well-known tools (Nmap, Nuclei, SQLmap, ZAP, Burp, Metasploit, Wireshark…) with auto-detection and a safe runner for the CLI ones.",
    steps: [
      "Open Arsenal. It auto-detects which tools are installed on this PC.",
      "Click a tool card to see its version/path (if installed) or the install command (copy it) + docs link.",
      "For runnable tools, pick a profile + target and hit Run — output appears in the console.",
      "After installing anything new, press 're-detect'.",
    ],
    example: "Nmap → Quick scan → 127.0.0.1",
    tip: "The runner is shell-free (argv only) with fixed profiles and validated targets — no command injection.",
  },
  {
    id: "recon-lab", icon: Radar, tag: "Recon", title: "Recon Lab — DNS / email / subdomains",
    desc: "One workspace for DNS, email security (SPF/DMARC/DKIM), subdomain enumeration and subdomain-takeover checks.",
    steps: [
      "Open Recon Lab and enter a domain.",
      "Run DNS, Email, Subdomains and Takeover — each shows its own result card.",
      "Email highlights spoofing issues; Subdomains lists what resolved; Takeover flags dangling CNAMEs.",
    ],
    example: "example.com",
    tip: "Use the Email tab's issues as quick low-hanging findings for a report.",
  },
  {
    id: "crypto-lab", icon: KeyRound, tag: "Crypto", title: "Crypto Lab — hashes & JWT",
    desc: "Identify & crack hashes, and decode / brute-force JWT secrets (HS256/384/512 + alg=none detection).",
    steps: [
      "Open Crypto Lab.",
      "Hash panel: paste a hash (optionally a custom wordlist) → identify & crack.",
      "JWT panel: paste a token → header/payload decode instantly; run to brute-force the secret.",
    ],
    example: "Hash: 5f4dcc3b5aa765d61d8327deb882cf99 → 'password'",
    tip: "A cracked JWT secret lets you forge tokens — great for impact demonstration.",
  },
  {
    id: "web-inspector", icon: Link2, tag: "Web", title: "Web Inspector — headers, TLS, CORS, replay",
    desc: "Header + TLS grade, tech/WAF fingerprint, CORS misconfig test, and a raw request replay builder.",
    steps: [
      "Open Web Inspector and enter a URL.",
      "Run Inspect (status/headers/grade/TLS), Fingerprint (tech/WAF) or CORS.",
      "Use the Replay panel to send a custom method/headers/body and read the raw response.",
    ],
    example: "https://example.com · then Replay: POST https://target/api",
    tip: "The security-header grade (A+–F) is a quick win for assessment reports.",
  },
  {
    id: "settings", icon: SettingsIcon, tag: "Console", title: "Settings — appearance, panels, data",
    desc: "Accent theme, sidebar, overview panel toggles, auto-refresh default, AI engine info, export/clear data, shortcut reference.",
    steps: [
      "Open Settings.",
      "Pick an accent theme and toggle the sidebar / overview panels.",
      "Check the AI engine status and export or clear your stored history.",
    ],
    example: "Theme: Emerald · Panels: hide Threat Map",
    tip: "All preferences are saved on this device (localStorage).",
  },
  {
    id: "scanner", icon: Radar, tag: "Recon", title: "Attack Surface Scanner",
    desc: "Scans a host's ports, SSL, DNS, CMS, web-vulns and deep secret/config exposure all at once.",
    steps: [
      "Open Attack Surface and enter a target host/domain (e.g. example.com).",
      "Enable whichever of the 22 modular toggles you need (ports, secrets, config files, templates...).",
      "Hit Run Scan — the scan runs in the background and the status updates live.",
      "Review findings, exposed secrets and endpoints in the cards. You can compare two scans in the Compare/Diff view.",
    ],
    example: "Target: scanme.nmap.org · Toggles: Ports + SSL + Secrets",
    tip: "The deep secret scan surfaces leaked API keys — validate them in Toolkit → Payment Key Recon.",
  },
  {
    id: "osint", icon: Fingerprint, tag: "OSINT", title: "OSINT Module",
    desc: "Gather public intelligence from an email, phone number or image, with an AI summary.",
    steps: [
      "Open OSINT and choose a kind (Email / Phone / Image).",
      "Enter the target value (email address / phone / image URL).",
      "Hit Lookup — you'll get breach hints, carrier/geo and an AI dossier summary.",
    ],
    example: "Email: test@example.com  ·  Phone: +14155550123",
    tip: "You can export results to an OSINT Dossier PDF for reporting.",
  },
  {
    id: "redteam", icon: Swords, tag: "Red Team", title: "Red Team Ops",
    desc: "APK static analysis, Cloud (S3) exposure, phishing methodology + AI advisor.",
    steps: [
      "Open Red Team Ops and choose a domain tab.",
      "Run a hands-on tool (like APK Analyzer / Cloud check) or ask the AI advisor for attack-path guidance.",
      "Follow the methodology steps and ATT&CK mapping.",
    ],
    example: "Analyze an APK URL or an S3 bucket name",
    tip: "To pull an APK straight from a phone, use USB Bridge → Apps → analyze.",
  },
  {
    id: "ad-enum", icon: Network, tag: "Active Directory", title: "AD / LDAP + SMB",
    desc: "Enumerate a Domain Controller — users/groups/computers, roastable accounts, BloodHound export, and SMB shares.",
    steps: [
      "Open AD / LDAP. In the LDAP Enum tab, enter the DC host/IP + (optional) creds, then hit Enumerate.",
      "AS-REP-roastable and Kerberoastable accounts are highlighted with red badges.",
      "Once bound, use the 'BloodHound JSON' button to download a ZIP → import it into BloodHound to build the attack-path graph.",
      "In the SMB Shares tab, enter a host and list shares and readable files via a null/guest/authenticated session.",
    ],
    example: "Host: dc01.corp.local · User: CORP\\jdoe (optional)",
    tip: "The cloud backend can't reach private (10.x/192.168.x) networks — this works on a public-reachable DC.",
  },
  {
    id: "netmap", icon: Share2, tag: "Network", title: "Network Mapper & Pivoting",
    desc: "Host-discovery + port/service map over a host/CIDR, a live graph, and an AI pivot-command advisor.",
    steps: [
      "Open Network Map and enter a target (a single host or a CIDR like 45.33.32.0/28).",
      "Hit Map Network — a live SVG graph of hosts and services is built.",
      "Export PNG or JSON from the graph card for reporting.",
      "In the Pivoting Advisor, describe your foothold scenario → get chisel/ssh/ligolo/msf recipes.",
    ],
    example: "Target: scanme.nmap.org  ·  Pivot: 'foothold on 10.0.0.5 → reach 10.0.1.0/24'",
    tip: "A CIDR is capped at 32 hosts to keep the scan fast.",
  },
  {
    id: "binre", icon: Binary, tag: "Reverse Eng", title: "Reverse Engineering Assistant",
    desc: "ELF/PE/Mach-O binary triage — arch, packing, imports, suspicious APIs, IOCs + AI capability summary.",
    steps: [
      "Open Reverse Eng and drop/choose a binary (.exe .dll .so ELF, up to 40 MB).",
      "The verdict banner shows a risk-score; identity, imports, suspicious APIs and URLs/secrets appear in cards.",
      "Download the report with 'Save IOC + Verdict PDF'.",
    ],
    example: "Upload: sample.exe or an ELF file like /bin/ls",
    tip: "High entropy (>7.2) = likely packed/encrypted — dig further in Ghidra/x64dbg.",
  },
  {
    id: "toolkit", icon: Wrench, tag: "Toolkit", title: "Hacker Toolkit + Payment Key Recon",
    desc: "Encoders, hashing, JWT, password, payloads, live CVE, DNS/WHOIS, IMEI and Payment Key Recon — all in one console.",
    steps: [
      "Open Hacker Toolkit and pick a tab from the top.",
      "In the Payment Key Recon tab, paste a leaked payment key (Stripe/Razorpay/PayPal etc.) and Inspect.",
      "Account identity, balance, pending funds, transactions, refunds and chargebacks are shown READ-ONLY.",
    ],
    example: "Payment Key Recon → provider Auto-detect → paste sk_live_…",
    tip: "Money-moving actions (refund/charge) are intentionally disabled — this is only for impact-assessment.",
  },
  {
    id: "device", icon: Usb, tag: "Live Device", title: "USB Device Bridge (Android)",
    desc: "Connect your Android phone live over USB in the browser and inspect it — no app install.",
    steps: [
      "Turn on USB debugging on the phone and connect it to your PC with a cable.",
      "Open USB Bridge → Connect Device → pick your phone in Chrome's USB chooser (tap 'Allow debugging' on the phone).",
      "View device info, screenshot, shell and installed apps.",
      "Hit 'analyze' on any app → its APK is pulled from the phone straight into the Static APK Analyzer.",
    ],
    example: "Only works on Chrome/Edge desktop (WebUSB); keep USB debugging on in the phone's Developer Options.",
    tip: "The USB chooser only opens when you click the button yourself — that's a Chrome security requirement.",
  },
  {
    id: "ai-pentest", icon: Bot, tag: "AI", title: "AI Pentest — Cloud & Ollama",
    desc: "Adversarial AI red-team operator. Use Cloud (ready) or your own local Ollama (free models like DeepSeek-R1).",
    steps: [
      "Open AI Pentest. The default 'Cloud' engine works instantly — write a prompt and send.",
      "For free/local models, switch to 'Ollama' at the top and choose a model from the dropdown.",
      "Reasoning models like DeepSeek-R1 show their chain-of-thought in a separate collapsible 'reasoning' panel, keeping the answer clean.",
    ],
    example: "Prompt: 'Prompt-injection test plan for a support chatbot'",
    tip: "ollama: setup is in the card below.",
  },
];

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white pl-9 pr-3 py-2.5 text-sm focus:outline-none focus:border-primary transition-colors";

function GuideItem({ g, open, onToggle }) {
  const Icon = g.icon;
  return (
    <div className="border border-border bg-[#0c0c0c]" data-testid={`guide-item-${g.id}`}>
      <button onClick={onToggle} data-testid={`guide-toggle-${g.id}`} className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/[0.02] transition-colors">
        <div className="w-9 h-9 border border-primary/30 bg-primary/5 flex items-center justify-center shrink-0"><Icon className="w-4 h-4 text-primary" /></div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-heading text-sm font-semibold text-white">{g.title}</span>
            <span className="data-label text-zinc-600">{g.tag}</span>
          </div>
          <p className="text-xs text-zinc-500 truncate">{g.desc}</p>
        </div>
        {open ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
      </button>
      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-border/60 space-y-3">
          <ol className="space-y-1.5 mt-3">
            {g.steps.map((s, i) => (
              <li key={i} className="flex items-start gap-2.5 text-sm text-zinc-300">
                <span className="font-mono text-[11px] text-black bg-primary w-5 h-5 flex items-center justify-center shrink-0 mt-0.5">{i + 1}</span>
                <span>{s}</span>
              </li>
            ))}
          </ol>
          <div className="grid sm:grid-cols-2 gap-2">
            <div className="border border-border bg-[#0a0a0a] p-3">
              <p className="data-label mb-1">Example</p>
              <p className="font-mono text-[11px] text-zinc-400 break-all">{g.example}</p>
            </div>
            <div className="border border-primary/20 bg-primary/[0.04] p-3">
              <p className="data-label mb-1 text-primary flex items-center gap-1.5"><ShieldAlert className="w-3 h-3" /> Tip</p>
              <p className="text-[11px] text-zinc-400">{g.tip}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Guide() {
  const [open, setOpen] = useState("scanner");
  const [q, setQ] = useState("");
  const filtered = GUIDES.filter((g) => (g.title + g.desc + g.tag).toLowerCase().includes(q.toLowerCase().trim()));

  return (
    <div className="p-5 md:p-8 space-y-6 max-w-4xl" data-testid="guide-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary"><BookOpen className="w-6 h-6 text-primary" /></div>
        <div>
          <p className="data-label mb-1">/ How to Use</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">InsafeLabs — Usage Guide</h1>
          <p className="text-sm text-zinc-500 mt-1">How to use each module, step-by-step. Everything is for AUTHORIZED targets only.</p>
        </div>
      </div>

      {/* Quick start */}
      <div className="border border-primary/25 bg-primary/[0.04] p-5" data-testid="guide-quickstart">
        <p className="data-label text-primary flex items-center gap-2 mb-3"><Rocket className="w-4 h-4" /> Quick Start</p>
        <ol className="space-y-2">
          {QUICK.map((s, i) => (
            <li key={i} className="flex items-start gap-2.5 text-sm text-zinc-200">
              <span className="font-mono text-[11px] text-black bg-primary w-5 h-5 flex items-center justify-center shrink-0 mt-0.5">{i + 1}</span>
              <span>{s}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* Ollama setup */}
      <div className="border border-border bg-[#0c0c0c] p-5" data-testid="guide-ollama">
        <p className="data-label flex items-center gap-2 mb-3"><Cpu className="w-4 h-4 text-primary" /> Local Ollama setup (free AI models)</p>
        <p className="text-sm text-zinc-400 mb-3">To run free models (DeepSeek-R1, Llama, Qwen) on your own PC — it connects directly from your browser.</p>
        <div className="space-y-2 font-mono text-xs">
          {[
            "1. Install Ollama (ollama.com), then start it with CORS enabled:",
            "   OLLAMA_ORIGINS=* ollama serve",
            "2. Pull a model:",
            "   ollama pull deepseek-r1   (or  ollama pull llama3.2)",
            "3. In AI Pentest switch to 'Ollama' → check the URL in the gear icon (default http://localhost:11434) → Refresh.",
          ].map((l, i) => (
            <p key={i} className={l.startsWith("   ") ? "text-primary bg-[#0a0a0a] border border-zinc-800 px-3 py-2" : "text-zinc-300"}>{l}</p>
          ))}
        </div>
      </div>

      {/* Module search + list */}
      <div className="relative">
        <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
        <input className={inputCls} value={q} onChange={(e) => setQ(e.target.value)} data-testid="guide-search" placeholder="Search modules — e.g. bloodhound, ollama, payment, apk…" />
      </div>

      <div className="space-y-2" data-testid="guide-list">
        {filtered.map((g) => (
          <GuideItem key={g.id} g={g} open={open === g.id} onToggle={() => setOpen(open === g.id ? null : g.id)} />
        ))}
        {filtered.length === 0 && <p className="text-sm text-zinc-500 text-center py-8">No module matched "{q}".</p>}
      </div>
    </div>
  );
}
