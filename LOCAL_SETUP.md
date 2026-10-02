# InsafeLabs — local setup & change log

This is the hardened / polished copy. Local-only (localhost). See `../HOSTING.md`
(if present) or the steps below.

## Run it
```powershell
# 1) create the env file (NOT committed / NOT shipped — holds secrets)
copy backend\.env.example backend\.env
#    then edit backend\.env and set:
#      MONGO_URL, DB_NAME, JWT_SECRET (long random), ADMIN_PASSWORD (strong),
#      LLM_BACKEND/LLM_* for DeepSeek
echo REACT_APP_BACKEND_URL=http://localhost:8001 > frontend\.env

# 2) install
cd backend; python -m venv venv; .\venv\Scripts\python -m pip install -r requirements-local.txt
cd ..\frontend; npx --yes yarn@1.22.22 install

# 3) run
cd ..\backend; .\venv\Scripts\python -m uvicorn server:app --host 127.0.0.1 --port 8001
# (new terminal)
cd frontend; $env:HOST="127.0.0.1"; $env:PORT="3000"; npx --yes yarn@1.22.22 start
```
- Frontend: http://localhost:3000  ·  Backend: http://127.0.0.1:8001/api/
- MongoDB required on `localhost:27017`.

## What changed in this copy

### New modules (Offensive Modules nav)
- **SOC** (`/app/soc`) — Security Operations Center: health, threat counts, alert triage, operations log, and an **IOC / Blacklist check** (12 IP RBLs + 5 domain blocklists — Spamhaus, SURCBL, DroneBL…) with a persisted IOC **watchlist**.
- **VAPT** (`/app/vapt`) — phased full assessment (Recon → Infrastructure → Web → Vuln scan) with CVSS, risk score, letter grade, Markdown report download and an AI executive summary.
- **WAPT** (`/app/wapt`) — OWASP Top 10 (2021) mapped web-app test (A01 access control incl. **IDOR**, A02 crypto, A03 injection, A05 misconfig, A06 components, A07 auth incl. **rate-limit**), report + AI summary.
- **Kill Chain** (`/app/kill-chain`) — Lockheed Martin 7 phases mapped to the platform's modules.
- **Proxy Chain** (`/app/proxy-chain`) — test proxies individually and open a real multi-hop HTTP CONNECT tunnel (proxychains-style) with per-hop status.
- **NDA / Legal** (`/app/legal`) — generate an **NDA**, **Pentest Authorization / Rules of Engagement** or **Scope letter**; preview and download as **.md or .pdf** to get signed by the client. **Auto-fill**: enter just a site/domain and it fills client name/org (page title + WHOIS), scope (`root, www.root, *.root`), date, jurisdiction and contact email for you; your own details can be saved once (provider profile) and are reused.
- **Playbooks** (`/app/playbooks`) — one-click guided workflows running a curated sequence of the platform's native tools: **External Recon**, **Web Quick Check**, **Web Deep Assessment**, **Infra / TLS**, **Full Sweep** (everything + Nuclei if installed).
- **AI Agent** (`/app/ai-agent`) — **gives InsafeLabs-AI control of the app's tools.** Give an instruction + target; the LLM plans a sequence of the app's 17 in-app tools (web_scan, injection, param_discovery, auth_form, tls_scan, vhost_discovery, dns_recon, dns_axfr, email_security, subdomain_enum, port_scan, http_inspect, fingerprint, cors_test, takeover, nmap_scan, nuclei_scan), the app executes them (all SSRF/validation guards still apply), and the AI writes the final Markdown report. Tool-calling uses a JSON plan so it works with the configured LLM (DeepSeek). Registry shared via `backend/routers/toolreg.py`.
- **Vuln Suite** (`/app/vuln-suite`) — **native, in-app** security testing (pure Python, no external binaries), non-destructive:
  - **Web Scan** — security headers + grade, cookie flags, CSP quality, clickjacking, HTTP methods/TRACE, CORS, version disclosure, HTTPS-redirect, sensitive-file probing, directory listing, TLS cert.
  - **Injection** — error/boolean **SQLi**, reflected **XSS**, **CRLF** header injection, **open redirect**, Host-header reflection (per query parameter).
  - **Params** — hidden parameter discovery (existing params, form inputs, common names that reflect/change the response).
  - **TLS** — certificate details + protocol support (TLS 1.0–1.3) with weak-protocol findings.
  - **DNS / AXFR** — records (A/AAAA/MX/TXT/NS/CNAME/SOA/CAA) + zone-transfer (AXFR) + SPF checks.
  - **Wordlist** — targeted wordlist generator (names/domain/city/year with permutations), downloadable.
- **Arsenal** (`/app/arsenal`) — catalog of **95 security tools** across 19 categories (Network, Recon, Enumeration, Web, Exploit, Password, Wireless, Network Analysis, Vuln Scan, Reverse Engineering, Mobile, Forensics, Malware, Cloud, Container, Code & Secrets, DFIR, Reporting, OSINT). Auto-detects what's installed on the host and can run a whitelisted subset with a **strict, shell-free runner** (argv only, fixed profiles, validated targets, timeout + output caps).
- **Recon Lab** (`/app/recon`) — DNS, email security (SPF/DMARC/DKIM), subdomain enum, subdomain takeover.
- **Crypto Lab** (`/app/crypto`) — hash identify/crack + JWT decode & secret brute-force.
- **Web Inspector** (`/app/web-inspect`) — headers + TLS grade, tech/WAF fingerprint, CORS test, raw request replay.
- **Settings** (`/app/settings`) — accent theme, sidebar, overview panels, auto-refresh, AI engine info, export/clear data, shortcut reference.

### Arsenal — installing tools so they show up in the panel
The detector scans: the process PATH, this app's venv, `ARSENAL_EXTRA_BIN_DIRS`
(set in `backend/.env`), Windows/WinGet dirs (`%LOCALAPPDATA%\Microsoft\WinGet\{Links,Packages}`),
`C:\Program Files\*` (one level), and the usual Python Scripts dirs. So a `pip install`
into a venv is detected even when that venv is not on PATH.

Install helper scripts live in `C:\InsafeLabs\scripts\`:
`install_tools.ps1` (pip → `C:\InsafeLabs\tools-venv`), `install_go_tools.ps1`
(Go → `C:\InsafeLabs\tools-gobin`), `install_git_tools.ps1`, `install_winget_tools.ps1`.

After installing anything, press **re-detect** on the Arsenal page (or restart the backend).

Tools that could not be auto-installed (need their own installer / GUI / git clone):
Nessus, OpenVAS/Greenbone, Metasploit, Ghidra (installer), Burp/ZAP (GUI, may need admin),
Hashcat, John, Airccrack-ng, recon-ng & spiderfoot (git clone, no setup.py),
Autopsy, CloudMapper.

### Features
- **Operations Overview** redesigned: page header + status/action bar, KPI cards,
  legends, section headers, dark basemap fix, and new controls:
  manual **refresh**, **auto-refresh interval** (15/30/60s/off), **density** toggle,
  **Security/Platform KPI** switch, **trend range** (7/14d), **Findings by Module**
  chart, **Pipeline** panel, **export snapshot (JSON)**, **copy summary**, **Quick Launch filter**,
  **sticky section quick-nav**, and **severity quick-filter chips** (jump to Findings).
- **Command palette** (Ctrl/⌘ + K) to jump between modules.
- **Accent theme switcher** (Amber / Emerald / Cyan / Crimson / Violet), persisted.
- **Collapsible sidebar** (persisted) + **panel show/hide** toggles (Threat Map, Gesture, Console, Timekeeping, Heatmap), persisted.
- **Keyboard shortcuts**: `R` refresh, `/` focus filter, `⌘/Ctrl + K` palette.
- **ErrorBoundary** so one bad component can't blank the console.

### Security hardening
- Global **rate limiter** middleware (per-IP, 600 req/min, `X-RateLimit-*` + 429 `Retry-After`).
- Auth: refuse empty `ADMIN_PASSWORD`; reject empty/oversized passwords; lockout keyed on real IP
  (`X-Forwarded-For` only with `TRUST_PROXY=1`); epoch revocation cache + atomic bump.
- **SSRF guard** (`backend/netguard.py`) on all generic fetch tools — blocks non-http(s),
  cloud metadata, link-local, and loopback/private (enable internal with `ALLOW_PRIVATE_TARGETS=1`).
- DOM-XSS fix in Leaflet tooltips; `safeHttpUrl()` on attacker/target-controlled `href`/`src`;
  ADB shell-injection fix; Ollama URL allowlist; safe HTML-entity decode; graceful IMEI handling;
  escaped scanner PDF fields; input caps on wordlists; cancel background scan jobs on eviction.

### Verification
- `backend/tests/test_security_hardening.py` — 10 tests, all passing against live localhost.
- See also `SECURITY.md` (if provided) for the full findings → fixes table.

## Still recommended
- Rotate the DeepSeek key and use a strong access code.
- Move the auth token out of `localStorage` to an HttpOnly cookie for full XSS resilience.

## Internal / localhost targets
`ALLOW_PRIVATE_TARGETS=1` is set in `backend/.env`, so the SSRF guard permits
loopback / private / LAN targets — needed to test this app itself or your own
network. Remove that line (or set it to 0) to re-block internal targets.


---

## Update 2026-10-01 — Vuln Suite extras + "All Tools" toolbox

### Vuln Suite (native checks added)
- SSTI, LFI / Path Traversal, Command Injection (time + echo based), IOC Extractor.
- Favicon fingerprint (md5/sha256 + Shodan-style mmh3), CIDR/PTR sweep, OpenAPI/Swagger analyzer, XXE tester.
- Wired into AI Agent (now 26 tools), WAPT A03/A05, VAPT web phase and the Web-Deep playbook.

### All Tools (`/app/all-tools`) — new consolidated toolbox
- 12 categories, ~130 utilities: Domain, DNS, Validation, General, Status, Sysadmin, Formatter,
  Content, Developer, Thread Dump, Converter, Cloud.
- Converters / formatters / encoders / validators / calculators run client-side (private, instant);
  network tools call the new `backend/routers/toolbox.py` (`/api/toolbox/*`, 40+ endpoints).
- Backend uses DoH (Cloudflare/Google/Quad9), RDAP/WHOIS, ipwho.is, URLhaus + DNSBLs; no extra pip deps.
- Searchable; each tool opens in a modal with copy-to-clipboard output.
- Not local-utility-able: Site24x7's cloud architecture diagram designers (AWS/Azure/GCP/Oracle/Alibaba/K8s)
  and its global multi-location checks (90 vantage points) — omitted by design.

### Fixes
- `UrlInput` ordering in `vulnsuite.py` (import-time NameError).
- Toolbox: SSL cert parsed from DER (works under CERT_NONE), domain expiry via RDAP fallback,
  DNS-propagation comparison ignores TTL/order and erroring resolvers.

### Update 2 (2026-10-01) — the "omitted" ones, added
- Curl Checker: parses a curl command (safe — never shell-executed) and runs it through the API tester.
- Cloud Architecture Diagram: text DSL (Name : layer, A -> B) rendered to an SVG you can copy/download — local substitute for the cloud diagram designers.
- DNS Propagation upgraded to true DNS-over-HTTPS wire format across 6 public resolver networks
  (Cloudflare, Google, OpenDNS, AdGuard, ControlD, NextDNS) — 6/6 respond.
- All Tools surfaced on the Landing page and in the How-to-Use guide; tool count ~131 across 12 categories.
- Remaining true non-options (documented): 90-vantage global checks (single host here) and SaaS-only diagram designers.

### Update 3 (2026-10-01) — post-login boot animation
- Replaced the plain "Verifying session…" flash with a premium ConsoleBoot animation
  (`frontend/src/components/ConsoleBoot.jsx`): amber entry flash that blends with the login
  hyperspace jump, rotating targeting reticle + radar sweep + pulsing core, a boot log that
  types out 6 init steps, and a synced 0-100% progress bar.
- ProtectedRoute now enforces a ~1.5s minimum boot and cross-fades (AnimatePresence) into the console.
- Login warp now shows an "ACCESS GRANTED / initializing command center…" readout during the jump.
- Dashboard "Loading telemetry" replaced with a matching radar/glow loader (no more bare spinner).
