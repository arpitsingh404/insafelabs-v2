import { useEffect, useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { toast } from "sonner";
import {
  Boxes, Play, Loader2, Trash2, FileCode, ShieldAlert, Package, ClipboardList,
} from "lucide-react";

const ECOSYSTEMS = ["npm", "pypi", "maven", "go", "cargo", "composer", "nuget"];

const SAMPLE = `{
  "dependencies": {
    "lodash": "4.17.15",
    "express": "4.16.0",
    "axios": "0.21.0",
    "minimist": "1.2.0",
    "jsonwebtoken": "8.5.0"
  }
}`;

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2 text-sm focus:outline-none focus:border-primary transition-colors";

export default function SCA() {
  const [scans, setScans] = useState([]);
  const [active, setActive] = useState(null);
  const [name, setName] = useState("");
  const [ecosystem, setEcosystem] = useState("npm");
  const [manifest, setManifest] = useState("");
  const [scanning, setScanning] = useState(false);
  const [tab, setTab] = useState("vulns");

  const loadScans = async () => {
    const { data } = await api.get("/sca/scans");
    setScans(data);
    if (!active && data.length) setActive(data[0]);
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { loadScans(); }, []);

  const run = async (e) => {
    e.preventDefault();
    if (!name || !manifest) { toast.error("Name and manifest required"); return; }
    setScanning(true);
    try {
      const { data } = await api.post("/sca/scan", { name, ecosystem, manifest });
      toast.success(`Scan complete — ${data.vuln_count} vulns across ${data.component_count} components`);
      setActive(data);
      setName(""); setManifest("");
      loadScans();
    } catch (e) {
      toast.error(formatApiError(e.response?.data?.detail) || "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const remove = async (id, ev) => {
    ev.stopPropagation();
    await api.delete(`/sca/scans/${id}`);
    if (active?.id === id) setActive(null);
    toast.success("Scan deleted");
    loadScans();
  };

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="sca-page">
      <div>
        <p className="data-label mb-2">/ Software Composition Analysis</p>
        <h1 className="font-heading text-3xl font-bold">SBOM &amp; CVE Detection</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan form + history */}
        <div className="space-y-6">
          <form onSubmit={run} className="bg-[#121212] border border-border p-6 space-y-4" data-testid="sca-form">
            <div>
              <label className="data-label block mb-1.5">Project Name</label>
              <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} data-testid="sca-name" placeholder="acme-web-frontend" />
            </div>
            <div>
              <label className="data-label block mb-1.5">Ecosystem</label>
              <select className={inputCls} value={ecosystem} onChange={(e) => setEcosystem(e.target.value)} data-testid="sca-ecosystem">
                {ECOSYSTEMS.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="data-label">Manifest / Dependencies</label>
                <button type="button" onClick={() => setManifest(SAMPLE)} className="text-[10px] font-mono uppercase tracking-widest text-primary hover:underline" data-testid="sca-sample">Load sample</button>
              </div>
              <textarea className={`${inputCls} min-h-[160px] font-mono text-xs`} value={manifest} onChange={(e) => setManifest(e.target.value)} data-testid="sca-manifest" placeholder="Paste package.json / requirements.txt / go.mod …" />
            </div>
            <button type="submit" disabled={scanning} data-testid="run-scan" className="w-full bg-primary text-black font-semibold py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60">
              {scanning ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing…</> : <><Play className="w-4 h-4" /> Run Scan</>}
            </button>
          </form>

          <div className="bg-[#121212] border border-border">
            <p className="data-label px-4 py-3 border-b border-border">Scan History</p>
            {scans.length === 0 ? (
              <p className="p-6 text-sm text-zinc-500 text-center">No scans yet</p>
            ) : (
              <div className="divide-y divide-border max-h-72 overflow-y-auto">
                {scans.map((s) => (
                  <button key={s.id} onClick={() => setActive(s)} data-testid={`scan-${s.id}`}
                    className={`w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-white/[0.02] transition-colors group ${active?.id === s.id ? "bg-primary/5 border-l-2 border-primary" : "border-l-2 border-transparent"}`}>
                    <FileCode className="w-4 h-4 text-zinc-500 shrink-0" />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-white truncate">{s.name}</p>
                      <p className="font-mono text-[10px] text-zinc-600">{s.ecosystem} · {s.vuln_count} vulns</p>
                    </div>
                    <Trash2 onClick={(e) => remove(s.id, e)} className="w-3.5 h-3.5 text-zinc-600 hover:text-severity-critical opacity-0 group-hover:opacity-100" />
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Results */}
        <div className="lg:col-span-2">
          {!active ? (
            <div className="bg-[#121212] border border-border p-16 text-center text-zinc-500 h-full flex flex-col items-center justify-center" data-testid="sca-empty">
              <Boxes className="w-12 h-12 mb-4 opacity-40" />
              <p>Run a scan or select one from history to view its SBOM and CVEs.</p>
            </div>
          ) : (
            <div className="space-y-6" data-testid="sca-results">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-border border border-border">
                {[
                  { l: "Components", v: active.component_count, c: "#fff" },
                  { l: "Critical", v: active.summary?.critical || 0, c: "#EF4444" },
                  { l: "High", v: active.summary?.high || 0, c: "#F97316" },
                  { l: "Med/Low", v: (active.summary?.medium || 0) + (active.summary?.low || 0), c: "#F59E0B" },
                ].map((s) => (
                  <div key={s.l} className="bg-[#121212] p-4" data-testid={`sca-stat-${s.l}`}>
                    <p className="font-mono text-2xl font-bold" style={{ color: s.c }}>{s.v}</p>
                    <p className="data-label mt-1">{s.l}</p>
                  </div>
                ))}
              </div>

              <div className="bg-[#121212] border border-border">
                <div className="flex items-center gap-1 border-b border-border px-2">
                  {[
                    { id: "vulns", label: "Vulnerabilities", icon: ShieldAlert },
                    { id: "sbom", label: "SBOM", icon: Package },
                  ].map(({ id, label, icon: Icon }) => (
                    <button key={id} onClick={() => setTab(id)} data-testid={`tab-${id}`}
                      className={`inline-flex items-center gap-2 px-4 py-3 text-sm border-b-2 -mb-px transition-colors ${tab === id ? "border-primary text-white" : "border-transparent text-zinc-500 hover:text-white"}`}>
                      <Icon className="w-4 h-4" /> {label}
                    </button>
                  ))}
                </div>

                {tab === "vulns" ? (
                  active.vulnerabilities?.length ? (
                    <div className="divide-y divide-border">
                      {active.vulnerabilities.map((v, i) => (
                        <div key={i} className="p-5" data-testid={`vuln-${i}`}>
                          <div className="flex items-center flex-wrap gap-3 mb-2">
                            <SeverityBadge severity={v.severity} />
                            <span className="font-mono text-sm text-primary">{v.cve}</span>
                            <span className="font-mono text-xs text-zinc-500">{v.component}@{v.version}</span>
                            {v.cvss != null && <span className="font-mono text-xs text-zinc-400 ml-auto">CVSS {v.cvss}</span>}
                          </div>
                          <p className="text-sm text-white font-medium">{v.title}</p>
                          <p className="text-sm text-zinc-400 mt-1 leading-relaxed">{v.description}</p>
                          {v.fixed_version && (
                            <p className="font-mono text-xs text-emerald-400 mt-2">→ upgrade to {v.fixed_version}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-12 text-center text-emerald-400/80"><ShieldAlert className="w-8 h-8 mx-auto mb-3 opacity-60" /><p className="text-sm">No known vulnerabilities detected.</p></div>
                  )
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border text-left">
                          {["Component", "Version", "License", "PURL"].map((h) => <th key={h} className="data-label font-normal px-4 py-3">{h}</th>)}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {active.components?.length ? active.components.map((c, i) => (
                          <tr key={i} className="hover:bg-white/[0.02]" data-testid={`comp-${i}`}>
                            <td className="px-4 py-2.5 text-white">{c.name}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-zinc-400">{c.version}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-zinc-500">{c.license || "—"}</td>
                            <td className="px-4 py-2.5 font-mono text-[11px] text-zinc-600 truncate max-w-[240px]">{c.purl || "—"}</td>
                          </tr>
                        )) : <tr><td colSpan={4} className="p-8 text-center text-zinc-500 flex items-center justify-center gap-2"><ClipboardList className="w-4 h-4" /> No components parsed</td></tr>}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
