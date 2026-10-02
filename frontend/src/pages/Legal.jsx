import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api, formatApiError } from "@/lib/api";
import { Markdown } from "@/components/Markdown";
import { FileText, Loader2, FileDown, Eye, Scale, Wand2 } from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm";

const FIELDS = [
  ["provider_name", "Your name / authorized signatory", "Jane Doe"],
  ["provider_org", "Your company / org", "InsafeLabs Security"],
  ["client_name", "Client signatory", "John Smith"],
  ["client_org", "Client company", "Acme Corp"],
  ["effective_date", "Effective date", "01 Oct 2026"],
  ["jurisdiction", "Governing law / jurisdiction", "India"],
  ["purpose", "Purpose", "security assessment"],
  ["scope", "Scope (targets — domains / IPs / apps)", "*.acme.com, 10.0.0.0/24, app.acme.com"],
  ["duration", "Duration / time window", "01–07 Oct 2026"],
  ["contact_email", "Client contact email", "security@acme.com"],
];

export default function Legal() {
  const [tpl, setTpl] = useState([]);
  const [template, setTemplate] = useState("nda");
  const [fields, setFields] = useState({});
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState("");
  const [site, setSite] = useState("");
  const [autoBusy, setAutoBusy] = useState(false);
  const [detected, setDetected] = useState(null);
  const [saveProfile, setSaveProfile] = useState(true);

  useEffect(() => {
    api.get("/legal/templates").then(({ data }) => setTpl(data.templates || [])).catch(() => {});
    api.get("/legal/profile").then(({ data }) => setFields((f) => ({
      ...f, provider_name: data.provider_name || "", provider_org: data.provider_org || "", jurisdiction: data.jurisdiction || "",
    }))).catch(() => {});
  }, []);

  const autoFill = async () => {
    if (!site.trim()) return toast.error("Enter a site / domain, e.g. acme.com");
    setAutoBusy(true); setRes(null);
    try {
      const { data } = await api.post("/legal/autofill", { site: site.trim() });
      const { detected: det, ...vals } = data;
      setFields((f) => ({ ...f, ...vals }));
      if (vals.template) setTemplate(vals.template);
      setDetected(det);
      if (saveProfile) {
        await api.post("/legal/profile", {
          provider_name: vals.provider_name || "", provider_org: vals.provider_org || "",
          contact_email: "", jurisdiction: vals.jurisdiction || "",
        }).catch(() => {});
      }
      toast.success(`Auto-filled from ${det?.root || site}`);
    } catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Auto-fill failed"); }
    finally { setAutoBusy(false); }
  };

  const gen = async () => {
    setBusy("gen");
    try { setRes((await api.post("/legal/generate", { template, ...fields })).data); }
    catch (e) { toast.error(formatApiError(e.response?.data?.detail) || "Failed"); }
    finally { setBusy(""); }
  };
  const dlMd = () => {
    if (!res) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([res.markdown], { type: "text/markdown" }));
    a.download = res.filename; a.click(); URL.revokeObjectURL(a.href);
  };
  const dlPdf = async () => {
    setBusy("pdf");
    try {
      const r = await api.post("/legal/generate.pdf", { template, ...fields }, { responseType: "blob" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(r.data);
      a.download = `${template}.pdf`; a.click(); URL.revokeObjectURL(a.href);
      toast.success("PDF downloaded");
    } catch { toast.error("PDF failed"); }
    finally { setBusy(""); }
  };

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="legal-page">
      <header className="relative border border-border bg-gradient-to-br from-[#161616] to-[#0c0c0c] p-5 md:p-6">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-primary" />
        <p className="data-label mb-2">/ Console</p>
        <h1 className="font-heading text-3xl font-bold flex items-center gap-3"><Scale className="w-7 h-7 text-primary" /> NDA &amp; Legal</h1>
        <p className="text-sm text-zinc-500 mt-1.5">Generate an NDA, penetration-test authorization / Rules of Engagement, or a scope letter — download it, hand it to the client, get it signed.</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 md:gap-6">
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#121212] border border-primary/30 p-5 space-y-2" data-testid="legal-autofill">
            <div className="flex items-center gap-2"><Wand2 className="w-4 h-4 text-primary" /><p className="data-label !text-primary">Auto-fill from site</p></div>
            <p className="text-xs text-zinc-500">Sirf site/domain daalo — client name/org, scope, date, jurisdiction aur email khud bhar jayenge (WHOIS + page title + aapki saved details se).</p>
            <div className="flex flex-col sm:flex-row gap-2">
              <input value={site} onChange={(e) => setSite(e.target.value)} data-testid="legal-site" placeholder="acme.com" className={inputCls} />
              <button onClick={autoFill} disabled={autoBusy} data-testid="legal-autofill-btn" className={btnCls}>
                {autoBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wand2 className="w-4 h-4" />} Auto-fill
              </button>
            </div>
            <label className="flex items-center gap-2 text-[11px] text-zinc-500">
              <input type="checkbox" checked={saveProfile} onChange={(e) => setSaveProfile(e.target.checked)} data-testid="legal-save-profile" /> save my details for next time
            </label>
            {detected && (
              <p className="font-mono text-[10px] text-zinc-600">detected: {detected.title || "—"} · {detected.whois_org || "—"} · {detected.whois_country || "—"}</p>
            )}
          </div>

          <div className="bg-[#121212] border border-border p-5 space-y-3">
            <p className="data-label">Template</p>
            <div className="space-y-1.5">
              {tpl.map((t) => (
                <button key={t.id} onClick={() => { setTemplate(t.id); setRes(null); }} data-testid={`legal-tpl-${t.id}`}
                  className={`w-full text-left border px-3 py-2 transition-colors ${template === t.id ? "border-primary/60 bg-primary/5 text-white" : "border-border text-zinc-400 hover:text-white"}`}>
                  <span className="font-heading text-sm font-semibold">{t.name}</span>
                  <p className="text-[11px] text-zinc-500 mt-0.5">{t.desc}</p>
                </button>
              ))}
            </div>
          </div>

          <div className="bg-[#121212] border border-border p-5 space-y-3">
            <p className="data-label">Details</p>
            {FIELDS.map(([k, label, ph]) => (
              <div key={k}>
                <p className="text-[11px] text-zinc-500 mb-1">{label}</p>
                {k === "scope" ? (
                  <textarea value={fields[k] || ""} onChange={(e) => setFields((f) => ({ ...f, [k]: e.target.value }))} data-testid={`legal-${k}`} placeholder={ph} className={inputCls + " min-h-[70px] resize-y"} />
                ) : (
                  <input value={fields[k] || ""} onChange={(e) => setFields((f) => ({ ...f, [k]: e.target.value }))} data-testid={`legal-${k}`} placeholder={ph} className={inputCls} />
                )}
              </div>
            ))}
            <div className="flex flex-wrap gap-2 pt-1">
              <button onClick={gen} disabled={!!busy} data-testid="legal-generate" className={btnCls}>
                {busy === "gen" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />} Generate
              </button>
              <button onClick={dlMd} disabled={!res} data-testid="legal-download-md" className="inline-flex items-center gap-2 border border-border px-3 py-2 text-xs font-mono uppercase tracking-wider text-zinc-300 hover:text-primary hover:border-primary/50 disabled:opacity-40">
                <FileDown className="w-3.5 h-3.5" /> .md
              </button>
              <button onClick={dlPdf} disabled={!!busy} data-testid="legal-download-pdf" className="inline-flex items-center gap-2 border border-border px-3 py-2 text-xs font-mono uppercase tracking-wider text-zinc-300 hover:text-primary hover:border-primary/50 disabled:opacity-40">
                {busy === "pdf" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileDown className="w-3.5 h-3.5" />} .pdf
              </button>
            </div>
          </div>
        </div>

        <div className="lg:col-span-7 bg-[#121212] border border-border p-5 min-h-[400px]" data-testid="legal-preview">
          <div className="flex items-center gap-2 mb-3"><FileText className="w-4 h-4 text-primary" /><h3 className="font-heading text-sm font-semibold">Preview</h3></div>
          {res ? <Markdown>{res.markdown}</Markdown> : <p className="text-sm text-zinc-600">Fill the details and press Generate.</p>}
        </div>
      </div>
    </div>
  );
}
