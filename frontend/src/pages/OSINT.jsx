import { useState, useEffect } from "react";
import { api, formatApiError } from "@/lib/api";
import { statusBadges } from "@/lib/imei";
import { safeHttpUrl } from "@/lib/safeUrl";
import { toast } from "sonner";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ClearModuleButton } from "@/components/ClearHistoryControls";
import {
  Fingerprint, Mail, Phone, Image as ImageIcon, AtSign, Loader2, Search,
  MapPin, ShieldCheck, ShieldX, Server, ExternalLink, CheckCircle2, XCircle,
  HelpCircle, Globe2, User, Camera, FolderOpen, FileDown, Trash2, Smartphone, Cpu, Eye,
  ScanSearch, Upload, Link2, LifeBuoy, AlertTriangle,
} from "lucide-react";

function StatusBadges({ result, testId }) {
  const badges = statusBadges(result);
  if (!badges.length) return null;
  return (
    <span className="inline-flex flex-wrap gap-1.5" data-testid={testId}>
      {badges.map((b, i) => (
        <span key={i} className="font-mono text-xs font-bold px-2.5 py-1 border" data-testid={`imei-badge-${b.label.split(' ')[0].toLowerCase()}`}
          style={{ color: b.color, borderColor: b.color + "66", background: b.color + "14" }}>{b.label}</span>
      ))}
    </span>
  );
}

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm focus:outline-none focus:border-primary transition-colors";
const cardCls = "bg-[#121212] border border-border p-5 animate-fade-up";

function Row({ label, value, mono = true, testId }) {
  if (value == null || value === "") return null;
  return (
    <div className="flex items-start justify-between gap-3 border-b border-border/50 py-1.5" data-testid={testId}>
      <span className="data-label shrink-0 pt-0.5">{label}</span>
      <span className={`text-right text-white break-all ${mono ? "font-mono text-xs" : "text-sm"}`}>{value}</span>
    </div>
  );
}

function SubmitBtn({ busy, label, testId }) {
  return (
    <button type="submit" disabled={busy} data-testid={testId}
      className="bg-primary text-black font-semibold px-5 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 glow-primary">
      {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} {label}
    </button>
  );
}

/* ---------------- EMAIL ---------------- */
function EmailTab({ onDone }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault();
    if (!email.trim()) return toast.error("Enter an email");
    setBusy(true); setRes(null);
    try {
      const { data } = await api.post("/osint/email", { email: email.trim() });
      setRes(data.result); toast.success("Email intelligence gathered"); onDone?.();
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Lookup failed"); }
    finally { setBusy(false); }
  };
  const g = res?.gravatar; const m = res?.mail;
  const accounts = g?.profile?.accounts || [];
  const expScore = (g?.exists ? 2 : 0) + (accounts.length ? 2 : 0) + (m?.deliverable_domain ? 1 : 0);
  const exp = expScore >= 4 ? { label: "High footprint", color: "#F97316" }
    : expScore >= 2 ? { label: "Moderate footprint", color: "#F59E0B" }
    : { label: "Low footprint", color: "#3B82F6" };
  return (
    <div className="space-y-5">
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2" data-testid="osint-email-form">
        <div className="relative flex-1">
          <Mail className="w-4 h-4 text-zinc-600 absolute left-3 top-1/2 -translate-y-1/2" />
          <input className={inputCls + " pl-9"} value={email} onChange={(e) => setEmail(e.target.value)} data-testid="osint-email-input" placeholder="target@example.com" type="email" />
        </div>
        <SubmitBtn busy={busy} label="Investigate" testId="osint-email-submit" />
      </form>
      {res && (
        <div className="space-y-5" data-testid="osint-email-result">
          {/* Summary strip */}
          <div className="bg-gradient-to-r from-[#141414] to-[#101010] border border-border p-5 flex flex-col sm:flex-row sm:items-center gap-4">
            {g?.has_avatar
              ? <img src={g.avatar} alt="avatar" className="w-16 h-16 border border-border object-cover shrink-0" data-testid="osint-email-avatar" />
              : <div className="w-16 h-16 border border-border bg-[#0a0a0a] flex items-center justify-center shrink-0"><User className="w-7 h-7 text-zinc-600" /></div>}
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <p className="text-white font-mono text-base truncate">{res.email}</p>
              </div>
              <p className="data-label mt-1">{g?.exists ? (g.profile?.display_name || "Public Gravatar identity") : "No public Gravatar identity"}</p>
            </div>
            <div className="flex flex-col gap-2 sm:items-end shrink-0">
              <span className="font-mono text-xs font-bold px-3 py-1.5 border" style={{ color: exp.color, borderColor: exp.color + "66", background: exp.color + "14" }}>{exp.label}</span>
              {m?.spf
                ? <span className="inline-flex items-center gap-1.5 text-emerald-400 text-xs font-mono px-3 py-1.5 border border-emerald-500/40 bg-emerald-500/10"><ShieldCheck className="w-3.5 h-3.5" /> DOMAIN PROTECTED</span>
                : <span className="inline-flex items-center gap-1.5 text-severity-high text-xs font-mono px-3 py-1.5 border border-severity-high/40 bg-severity-high/10"><ShieldX className="w-3.5 h-3.5" /> SPOOFABLE</span>}
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-5">
            <div className={cardCls}>
              <p className="data-label mb-3 flex items-center gap-2"><User className="w-3.5 h-3.5 text-primary" /> Public Identity</p>
              {g?.profile ? (
                <div className="space-y-0.5">
                  <Row label="Name" value={g.profile.display_name} mono={false} />
                  <Row label="Username" value={g.profile.username} />
                  <Row label="Location" value={g.profile.location} mono={false} />
                  {g.profile.about && <p className="text-xs text-zinc-400 mt-2 leading-relaxed">{g.profile.about}</p>}
                  {g.profile.profile_url && <a href={safeHttpUrl(g.profile.profile_url)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary mt-2 hover:underline">Open Gravatar profile <ExternalLink className="w-3 h-3" /></a>}
                  {accounts.length > 0 && (
                    <div className="mt-3"><p className="data-label mb-1.5">Linked accounts</p>
                      <div className="flex flex-wrap gap-2">
                        {accounts.map((a, i) => <a key={i} href={safeHttpUrl(a.url)} target="_blank" rel="noreferrer" className="font-mono text-[11px] border border-primary/30 bg-primary/5 px-2 py-1 text-primary hover:bg-primary/10">{a.name}</a>)}
                      </div>
                    </div>
                  )}
                </div>
              ) : <p className="text-sm text-zinc-600">No public profile linked to this email hash.</p>}
            </div>
            <div className={cardCls}>
              <p className="data-label mb-3 flex items-center gap-2"><Server className="w-3.5 h-3.5 text-primary" /> Mail Infrastructure</p>
              <Row label="Provider" value={m?.provider} mono={false} />
              <Row label="Deliverable" value={m?.deliverable_domain ? "Yes — MX present" : "No MX records"} />
              <div className="flex items-center justify-between border-b border-border/50 py-1.5">
                <span className="data-label">SPF / Spoofable</span>
                {m?.spf ? <span className="inline-flex items-center gap-1 text-emerald-400 text-xs"><ShieldCheck className="w-3.5 h-3.5" /> protected</span>
                        : <span className="inline-flex items-center gap-1 text-severity-high text-xs"><ShieldX className="w-3.5 h-3.5" /> spoofable</span>}
              </div>
              {(m?.mx || []).length > 0 && (
                <div className="mt-2"><p className="data-label mb-1">MX records</p>
                  {m.mx.map((r, i) => <p key={i} className="font-mono text-[10px] text-zinc-500 break-all">{r}</p>)}</div>
              )}
            </div>
          </div>

          <div className={cardCls}>
            <p className="data-label mb-2">Candidate profiles · @{res.derived_username}</p>
            <div className="flex flex-wrap gap-2">
              {(res.candidate_profiles || []).map((p, i) => (
                <a key={i} href={safeHttpUrl(p.url)} target="_blank" rel="noreferrer" className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2.5 py-1.5 text-zinc-300 hover:border-primary/50 hover:text-primary transition-colors inline-flex items-center gap-1.5"><ExternalLink className="w-3 h-3" /> {p.platform}</a>
              ))}
            </div>
          </div>

          {res.ai_summary && (
            <div className={cardCls}>
              <p className="data-label mb-2 flex items-center gap-2"><Fingerprint className="w-3.5 h-3.5 text-primary" /> AI Analyst Summary</p>
              <p className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap">{res.ai_summary}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ---------------- PHONE ---------------- */
function PhoneTab({ onDone }) {
  const [phone, setPhone] = useState("");
  const [region, setRegion] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault();
    if (!phone.trim()) return toast.error("Enter a phone number");
    setBusy(true); setRes(null);
    try {
      const { data } = await api.post("/osint/phone", { phone: phone.trim(), region: region.trim() || null });
      setRes(data.result); toast.success("Number analyzed"); onDone?.();
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Lookup failed"); }
    finally { setBusy(false); }
  };
  return (
    <div className="space-y-5">
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2" data-testid="osint-phone-form">
        <input className={inputCls} value={phone} onChange={(e) => setPhone(e.target.value)} data-testid="osint-phone-input" placeholder="+14155552671" />
        <input className={`${inputCls} sm:w-28`} value={region} onChange={(e) => setRegion(e.target.value)} data-testid="osint-phone-region" placeholder="region (US)" maxLength={2} />
        <SubmitBtn busy={busy} label="Analyze" testId="osint-phone-submit" />
      </form>
      {res && (
        <div className="grid md:grid-cols-2 gap-5" data-testid="osint-phone-result">
          <div className={cardCls}>
            <div className="flex items-center justify-between mb-3">
              <p className="font-mono text-lg text-white">{res.formats?.international || res.input}</p>
              {res.valid ? <span className="inline-flex items-center gap-1 text-emerald-400 text-xs"><CheckCircle2 className="w-3.5 h-3.5" /> valid</span>
                         : <span className="inline-flex items-center gap-1 text-severity-high text-xs"><XCircle className="w-3.5 h-3.5" /> invalid</span>}
            </div>
            <Row label="Country" value={res.region} mono={false} />
            <Row label="Country code" value={res.country_code} />
            <Row label="Carrier" value={res.carrier} mono={false} />
            <Row label="Line type" value={res.line_type} mono={false} />
            <Row label="E.164" value={res.formats?.e164} />
            <Row label="National" value={res.formats?.national} />
          </div>
          <div className={cardCls}>
            <p className="data-label mb-3 flex items-center gap-2"><Globe2 className="w-3.5 h-3.5 text-primary" /> Timezones</p>
            <div className="flex flex-wrap gap-2">
              {(res.timezones || []).map((t, i) => <span key={i} className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2 py-1 text-zinc-300">{t}</span>)}
              {(res.timezones || []).length === 0 && <p className="text-sm text-zinc-500">No timezone data.</p>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- IMAGE ---------------- */
function ImageTab({ onDone }) {
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault();
    if (!file && !url.trim()) return toast.error("Enter an image URL or upload a file");
    setBusy(true); setRes(null);
    try {
      const fd = new FormData();
      if (file) fd.append("image", file);
      else fd.append("image_url", url.trim());
      const { data } = await api.post("/osint/image", fd);
      setRes(data.result); toast.success("Image analyzed"); onDone?.();
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Analysis failed"); }
    finally { setBusy(false); }
  };
  const meta = res?.metadata; const exif = res?.exif || {};
  const enc = res ? encodeURIComponent(res.image_url) : "";
  const REV = res ? [
    { name: "Google Lens", url: `https://lens.google.com/uploadbyurl?url=${enc}` },
    { name: "Yandex", url: `https://yandex.com/images/search?rpt=imageview&url=${enc}` },
    { name: "TinEye", url: `https://www.tineye.com/search?url=${enc}` },
    { name: "Bing", url: `https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:${enc}` },
  ] : [];
  return (
    <div className="space-y-5">
      <form onSubmit={run} className="space-y-2" data-testid="osint-image-form">
        <div className="flex flex-col sm:flex-row gap-2">
          <input className={inputCls} value={url} onChange={(e) => { setUrl(e.target.value); setFile(null); }} data-testid="osint-image-input" placeholder="https://example.com/photo.jpg  (public image URL)" />
          <SubmitBtn busy={busy} label="Analyze" testId="osint-image-submit" />
        </div>
        <label className="flex items-center justify-center gap-2 border border-dashed border-zinc-700 py-2.5 text-sm text-zinc-400 cursor-pointer hover:border-primary/50 hover:text-primary transition-colors" data-testid="osint-image-upload-label">
          <Upload className="w-4 h-4" /> {file ? file.name : "…or upload an image file (vision model)"}
          <input type="file" accept="image/*" className="hidden" data-testid="osint-image-upload" onChange={(e) => { setFile(e.target.files?.[0] || null); setUrl(""); }} />
        </label>
      </form>
      {res && (
        <div className="grid md:grid-cols-2 gap-5" data-testid="osint-image-result">
          <div className={cardCls}>
            <img src={safeHttpUrl(res.image_url)} alt="target" className="w-full border border-border bg-black mb-3" data-testid="osint-image-preview" />
            <Row label="Format" value={meta?.format} />
            <Row label="Dimensions" value={meta ? `${meta.width}×${meta.height}` : null} />
            <Row label="Size" value={meta ? `${meta.size_kb} KB` : null} />
            {Object.entries(exif).map(([k, v]) => <Row key={k} label={k} value={v} />)}
            {Object.keys(exif).length === 0 && <p className="text-xs text-zinc-500 mt-2">No EXIF metadata (likely stripped by host).</p>}
            {res.gps && (
              <a href={safeHttpUrl(res.gps.maps_url)} target="_blank" rel="noreferrer" data-testid="osint-image-gps"
                className="inline-flex items-center gap-1.5 text-xs text-severity-high border border-severity-high/40 bg-severity-high/10 px-2.5 py-1.5 mt-3 hover:bg-severity-high/20">
                <MapPin className="w-3.5 h-3.5" /> GPS: {res.gps.lat}, {res.gps.lon} — open map
              </a>
            )}
          </div>
          <div className={cardCls}>
            <p className="data-label mb-2 flex items-center gap-2"><Camera className="w-3.5 h-3.5 text-primary" /> AI Vision Analysis</p>
            {res.ai_analysis ? <p className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap" data-testid="osint-image-analysis">{res.ai_analysis}</p>
                             : <p className="text-sm text-zinc-500" data-testid="osint-image-analysis">Image too small or unclear for AI analysis — try a larger, clearer image.</p>}
            {!res.is_upload && (<>
            <p className="data-label mt-4 mb-2 flex items-center gap-1.5"><Search className="w-3 h-3 text-primary" /> Reverse image pivot</p>
            <div className="flex flex-wrap gap-2" data-testid="osint-reverse-pivot">
              {REV.map((r, i) => (
                <a key={i} href={safeHttpUrl(r.url)} target="_blank" rel="noreferrer" data-testid={`reverse-${r.name.split(' ')[0].toLowerCase()}`}
                  className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2.5 py-1.5 text-zinc-300 hover:border-primary/50 hover:text-primary transition-colors inline-flex items-center gap-1.5">
                  <ExternalLink className="w-3 h-3" /> {r.name}
                </a>
              ))}
            </div>
            </>)}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- USERNAME ---------------- */
function UsernameTab({ onDone }) {
  const [username, setUsername] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const run = async (e) => {
    e.preventDefault();
    if (!username.trim()) return toast.error("Enter a username");
    setBusy(true); setRes(null);
    try {
      const { data } = await api.post("/osint/username", { username: username.trim() });
      setRes(data.result); toast.success(`${data.result.found_count} likely hits across ${data.result.checked} sites`); onDone?.();
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Lookup failed"); }
    finally { setBusy(false); }
  };
  const badge = (s) => s === "found"
    ? <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]"><CheckCircle2 className="w-3 h-3" /> found</span>
    : s === "not found" ? <span className="inline-flex items-center gap-1 text-zinc-600 text-[11px]"><XCircle className="w-3 h-3" /> none</span>
    : <span className="inline-flex items-center gap-1 text-zinc-500 text-[11px]"><HelpCircle className="w-3 h-3" /> unknown</span>;
  return (
    <div className="space-y-5">
      <form onSubmit={run} className="flex flex-col sm:flex-row gap-2" data-testid="osint-username-form">
        <input className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} data-testid="osint-username-input" placeholder="handle (no @)" />
        <SubmitBtn busy={busy} label="Hunt" testId="osint-username-submit" />
      </form>
      {res && (
        <div className={cardCls} data-testid="osint-username-result">
          <p className="data-label mb-3">@{res.username} · {res.found_count}/{res.checked} likely present</p>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {res.results.map((r, i) => (
              <a key={i} href={safeHttpUrl(r.url)} target="_blank" rel="noreferrer" data-testid={`osint-site-${r.site}`}
                className={`flex items-center justify-between gap-2 border px-3 py-2 transition-colors ${r.status === "found" ? "border-emerald-500/40 bg-emerald-500/5" : "border-border bg-[#0a0a0a] hover:border-zinc-600"}`}>
                <span className="text-sm text-white truncate">{r.site}</span>
                {badge(r.status)}
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- IMEI ---------------- */
function ImeiTab({ onDone }) {
  const [imei, setImei] = useState("");
  const [serviceId, setServiceId] = useState(0);
  const [services, setServices] = useState([]);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  useEffect(() => { api.get("/toolkit/imei/services").then(({ data }) => setServices(data)).catch(() => {}); }, []);
  const run = async (e) => {
    e.preventDefault();
    if (!imei.trim()) return toast.error("Enter an IMEI");
    setBusy(true); setRes(null);
    try {
      const { data } = await api.post("/osint/imei", { imei: imei.trim(), service_id: Number(serviceId) });
      setRes(data.result); toast.success(`${data.result?.status || "Done"} · ${data.result?.service || "IMEI"}`); onDone?.();
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "IMEI lookup failed"); }
    finally { setBusy(false); }
  };
  const device = res?.result;
  const meta = device && typeof device === "object"
    ? Object.entries(device).filter(([k]) => !["brand_name", "model", "image"].includes(k)) : [];
  return (
    <div className="space-y-5">
      <form onSubmit={run} className="grid sm:grid-cols-[1fr_auto_auto] gap-2" data-testid="osint-imei-form">
        <input className="w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors" value={imei} onChange={(e) => setImei(e.target.value)} data-testid="osint-imei-input" placeholder="356166091795616" inputMode="numeric" />
        <select className="bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm focus:outline-none focus:border-primary" value={serviceId} onChange={(e) => setServiceId(e.target.value)} data-testid="osint-imei-service">
          {services.length === 0 && <option value={0}>Basic IMEI Check</option>}
          {services.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
        <SubmitBtn busy={busy} label="Check" testId="osint-imei-submit" />
      </form>
      {res && (
        <div className={cardCls} data-testid="osint-imei-result">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-11 h-11 border border-border bg-[#0a0a0a] flex items-center justify-center shrink-0"><Cpu className="w-5 h-5 text-primary" /></div>
            <div className="min-w-0">
              <p className="font-heading text-lg font-semibold truncate" data-testid="osint-imei-device">{device?.brand_name ? `${device.brand_name} ${device.model || ""}`.trim() : (device?.manufacturer ? `${device.manufacturer} ${device.model || device.model_name || ""}`.trim() : (res.service || "Result"))}</p>
              <p className="data-label mt-0.5">{res.service} · {res.status}{res.token_request_price ? ` · ${res.token_request_price} tokens` : ""}</p>
            </div>
            {res && <span className="ml-auto"><StatusBadges result={device} testId="osint-imei-blacklist-badge" /></span>}
          </div>
          <div className="space-y-0.5">
            <Row label="IMEI" value={res.imei} />
            {meta.map(([k, v]) => <Row key={k} label={k} value={typeof v === "object" ? JSON.stringify(v) : String(v)} />)}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- IMAGE FOOTPRINT (reverse image + takedown) ---------------- */
function Thumb({ url }) {
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" className="block border border-border bg-black overflow-hidden group">
      <img src={url} alt="" loading="lazy" referrerPolicy="no-referrer"
        className="w-full h-24 object-cover group-hover:opacity-80 transition-opacity"
        onError={(e) => { const p = e.currentTarget.parentElement; if (p) p.style.display = "none"; }} />
    </a>
  );
}

const REPORT_LINKS = [
  { name: "Google — Remove results about you", url: "https://support.google.com/websearch/answer/9673730" },
  { name: "Google — Remove explicit/intimate images", url: "https://support.google.com/websearch/answer/6302812" },
  { name: "Meta (Instagram/Facebook) report", url: "https://www.facebook.com/help/contact/144059062408922" },
  { name: "X (Twitter) — private info report", url: "https://help.twitter.com/en/forms/private-information" },
  { name: "Reddit — report content", url: "https://www.reddit.com/report" },
  { name: "TikTok — report", url: "https://www.tiktok.com/legal/report/feedback" },
  { name: "StopNCII.org (adult NCII)", url: "https://stopncii.org/" },
  { name: "Take It Down (NCMEC · minors)", url: "https://takeitdown.ncmec.org/" },
  { name: "India Cyber Crime (helpline 1930)", url: "https://cybercrime.gov.in/" },
];

function TakedownAdvisor({ initialWhere }) {
  const [desc, setDesc] = useState("");
  const [busy, setBusy] = useState(false);
  const [answer, setAnswer] = useState("");
  const run = async () => {
    if (!desc.trim()) return toast.error("Describe the situation briefly");
    setBusy(true); setAnswer("");
    try {
      const { data } = await api.post("/osint/takedown-advise", { description: desc.trim(), where: initialWhere || null }, { timeout: 60000 });
      setAnswer(data.answer);
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Advisor failed"); }
    finally { setBusy(false); }
  };
  return (
    <div className={cardCls} data-testid="osint-takedown">
      <p className="data-label mb-2 flex items-center gap-2"><LifeBuoy className="w-3.5 h-3.5 text-primary" /> Takedown / Removal Advisor</p>
      <p className="text-xs text-zinc-500 mb-3">A step-by-step plan to get an unwanted / non-consensual photo of you or someone else removed (Google removal, DMCA, platform reports, StopNCII). For victim support.</p>
      <textarea className={inputCls + " min-h-[80px] resize-y"} value={desc} onChange={(e) => setDesc(e.target.value)} data-testid="osint-takedown-input"
        placeholder="e.g. Someone posted a private photo of me without permission on a forum and Instagram — how do I get it removed?" />
      <button onClick={run} disabled={busy} data-testid="osint-takedown-run"
        className="mt-3 bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60">
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <LifeBuoy className="w-4 h-4" />} Get Removal Plan
      </button>
      {answer && <div className="mt-4 border border-border bg-[#0a0a0a] p-4 font-mono text-[13px] text-zinc-200 whitespace-pre-wrap leading-relaxed max-h-[420px] overflow-y-auto" data-testid="osint-takedown-out">{answer}</div>}
      <p className="data-label mt-4 mb-2">Direct report / removal links</p>
      <div className="flex flex-wrap gap-2" data-testid="osint-report-links">
        {REPORT_LINKS.map((l, i) => (
          <a key={i} href={safeHttpUrl(l.url)} target="_blank" rel="noopener noreferrer"
            className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2.5 py-1.5 text-zinc-300 hover:border-primary/50 hover:text-primary transition-colors inline-flex items-center gap-1.5">
            <ExternalLink className="w-3 h-3" /> {l.name}
          </a>
        ))}
      </div>
    </div>
  );
}

function FootprintTab({ onDone }) {
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState("");

  const run = async (e) => {
    e.preventDefault();
    if (!file && !url.trim()) return toast.error("Paste an image URL or upload a file");
    setBusy(true); setRes(null); setErr("");
    try {
      const fd = new FormData();
      if (file) fd.append("image", file);
      else fd.append("image_url", url.trim());
      const { data } = await api.post("/osint/reverse-image", fd);
      setRes(data.result);
      const c = data.result?.counts || {};
      toast.success(`Found on ${c.pages || 0} page(s) · ${c.full || 0} exact match(es)`);
      onDone?.();
    } catch (e2) {
      const detail = formatApiError(e2.response?.data?.detail) || "Reverse image search failed";
      setErr(detail);
      toast.error(detail);
    } finally { setBusy(false); }
  };

  const c = res?.counts || {};
  return (
    <div className="space-y-5">
      <form onSubmit={run} className="bg-[#121212] border border-border p-5 space-y-3" data-testid="osint-footprint-form">
        <div className="relative">
          <Link2 className="w-4 h-4 text-zinc-600 absolute left-3 top-1/2 -translate-y-1/2" />
          <input className={inputCls + " pl-9"} value={url} onChange={(e) => { setUrl(e.target.value); setFile(null); }} data-testid="osint-footprint-url" placeholder="https://example.com/photo.jpg  (public image URL)" />
        </div>
        <div className="flex flex-col sm:flex-row gap-2">
          <label className="flex-1 flex items-center justify-center gap-2 border border-dashed border-zinc-700 py-2.5 text-sm text-zinc-400 cursor-pointer hover:border-primary/50 hover:text-primary transition-colors" data-testid="osint-footprint-upload-label">
            <Upload className="w-4 h-4" /> {file ? file.name : "…or upload an image file"}
            <input type="file" accept="image/*" className="hidden" data-testid="osint-footprint-upload" onChange={(e) => { setFile(e.target.files?.[0] || null); setUrl(""); }} />
          </label>
          <button type="submit" disabled={busy} data-testid="osint-footprint-submit"
            className="bg-primary text-black font-semibold px-5 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 glow-primary">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ScanSearch className="w-4 h-4" />} Find Copies Online
          </button>
        </div>
        <p className="text-[11px] text-zinc-600">Pixel-match reverse search (Google Vision Web Detection) — finds where this image appears across the web.</p>
      </form>

      {err && (
        <div className="border border-severity-high/40 bg-severity-high/10 p-4 flex items-start gap-2" data-testid="osint-footprint-error">
          <AlertTriangle className="w-4 h-4 text-severity-high shrink-0 mt-0.5" />
          <p className="text-sm text-zinc-300">{err}</p>
        </div>
      )}

      {res && (
        <div className="space-y-5" data-testid="osint-footprint-result">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {[["Pages", c.pages], ["Exact", c.full], ["Partial", c.partial], ["Similar", c.similar]].map(([l, v]) => (
              <div key={l} className="border border-border bg-[#0a0a0a] p-3">
                <p className="data-label">{l}</p>
                <p className="font-mono text-2xl text-white mt-1">{v ?? 0}</p>
              </div>
            ))}
          </div>

          {(res.best_guess || []).length > 0 && (
            <div className={cardCls}>
              <p className="data-label mb-2">Best guess</p>
              <div className="flex flex-wrap gap-2">
                {res.best_guess.map((b, i) => <span key={i} className="font-mono text-xs border border-primary/40 bg-primary/5 text-primary px-2.5 py-1">{b}</span>)}
              </div>
            </div>
          )}

          {(res.pages || []).length > 0 && (
            <div className={cardCls} data-testid="osint-footprint-pages">
              <p className="data-label mb-3 flex items-center gap-2"><Globe2 className="w-3.5 h-3.5 text-primary" /> Pages with this image ({c.pages})</p>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {res.pages.map((p, i) => (
                  <div key={i} className="flex items-start gap-3 border-b border-border/40 pb-2" data-testid={`footprint-page-${i}`}>
                    {(p.full[0] || p.partial[0]) && <img src={p.full[0] || p.partial[0]} alt="" referrerPolicy="no-referrer" className="w-14 h-14 object-cover border border-border bg-black shrink-0" onError={(e) => { e.currentTarget.style.display = "none"; }} />}
                    <div className="min-w-0 flex-1">
                      <a href={safeHttpUrl(p.url)} target="_blank" rel="noopener noreferrer" className="text-sm text-white hover:text-primary transition-colors line-clamp-2">{p.title || p.url}</a>
                      <p className="font-mono text-[10px] text-zinc-600 truncate">{p.url}</p>
                      {p.full.length > 0 && <span className="font-mono text-[10px] text-severity-critical">exact match on page</span>}
                    </div>
                    <a href={safeHttpUrl(p.url)} target="_blank" rel="noopener noreferrer" className="text-zinc-600 hover:text-primary shrink-0"><ExternalLink className="w-4 h-4" /></a>
                  </div>
                ))}
              </div>
            </div>
          )}

          {(res.full_matching || []).length > 0 && (
            <div className={cardCls}>
              <p className="data-label mb-3">Exact matching images ({c.full})</p>
              <div className="grid grid-cols-3 sm:grid-cols-5 gap-2">{res.full_matching.slice(0, 15).map((u, i) => <Thumb key={i} url={u} />)}</div>
            </div>
          )}
          {(res.visually_similar || []).length > 0 && (
            <div className={cardCls}>
              <p className="data-label mb-3">Visually similar ({c.similar})</p>
              <div className="grid grid-cols-3 sm:grid-cols-5 gap-2">{res.visually_similar.slice(0, 15).map((u, i) => <Thumb key={i} url={u} />)}</div>
            </div>
          )}
          {(res.web_entities || []).length > 0 && (
            <div className={cardCls}>
              <p className="data-label mb-2">Related web entities</p>
              <div className="flex flex-wrap gap-2">
                {res.web_entities.map((e, i) => <span key={i} className="font-mono text-[11px] border border-border bg-[#0a0a0a] px-2 py-1 text-zinc-400">{e.description}</span>)}
              </div>
            </div>
          )}
        </div>
      )}

      <TakedownAdvisor initialWhere={res?.source} />
    </div>
  );
}

export default function OSINT() {
  const [reloadKey, setReloadKey] = useState(0);
  const onDone = () => setReloadKey((k) => k + 1);
  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="osint-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary">
          <Fingerprint className="w-6 h-6 text-primary" />
        </div>
        <div>
          <p className="data-label mb-1">/ Open-Source Intelligence</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">OSINT Investigator</h1>
          <p className="text-sm text-zinc-500 mt-1">Pivot on an email, phone number, image or username to map a target's public footprint.</p>
        </div>
      </div>

      <Tabs defaultValue="email" className="w-full">
        <TabsList className="bg-[#121212] border border-border p-1 h-auto flex-wrap justify-start" data-testid="osint-tabs">
          <TabsTrigger value="email" data-testid="osint-tab-email" className="data-[state=active]:bg-primary data-[state=active]:text-black gap-2 px-4 py-2"><Mail className="w-4 h-4" /> Email</TabsTrigger>
          <TabsTrigger value="phone" data-testid="osint-tab-phone" className="data-[state=active]:bg-primary data-[state=active]:text-black gap-2 px-4 py-2"><Phone className="w-4 h-4" /> Phone</TabsTrigger>
          <TabsTrigger value="image" data-testid="osint-tab-image" className="data-[state=active]:bg-primary data-[state=active]:text-black gap-2 px-4 py-2"><ImageIcon className="w-4 h-4" /> Image</TabsTrigger>
          <TabsTrigger value="footprint" data-testid="osint-tab-footprint" className="data-[state=active]:bg-primary data-[state=active]:text-black gap-2 px-4 py-2"><ScanSearch className="w-4 h-4" /> Image Footprint</TabsTrigger>
          <TabsTrigger value="username" data-testid="osint-tab-username" className="data-[state=active]:bg-primary data-[state=active]:text-black gap-2 px-4 py-2"><AtSign className="w-4 h-4" /> Username</TabsTrigger>
          <TabsTrigger value="imei" data-testid="osint-tab-imei" className="data-[state=active]:bg-primary data-[state=active]:text-black gap-2 px-4 py-2"><Smartphone className="w-4 h-4" /> IMEI</TabsTrigger>
        </TabsList>
        <div className="mt-5">
          <TabsContent value="email"><EmailTab onDone={onDone} /></TabsContent>
          <TabsContent value="phone"><PhoneTab onDone={onDone} /></TabsContent>
          <TabsContent value="image"><ImageTab onDone={onDone} /></TabsContent>
          <TabsContent value="footprint"><FootprintTab onDone={onDone} /></TabsContent>
          <TabsContent value="username"><UsernameTab onDone={onDone} /></TabsContent>
          <TabsContent value="imei"><ImeiTab onDone={onDone} /></TabsContent>
        </div>
      </Tabs>

      <CaseFile reloadKey={reloadKey} />
    </div>
  );
}

/* ---------------- CASE FILE / DOSSIER ---------------- */
const KIND_ICON = { email: Mail, phone: Phone, image: ImageIcon, "reverse-image": ScanSearch, username: AtSign, imei: Smartphone };

function LookupDetail({ it }) {
  if (!it) return null;
  const r = it.result || {};
  if (it.kind === "email") {
    const g = r.gravatar || {}; const m = r.mail || {};
    return (
      <div className="space-y-2">
        <Row label="Email" value={r.email} />
        <Row label="Provider" value={m.provider} mono={false} />
        <Row label="SPF" value={m.spf ? "protected" : "spoofable"} mono={false} />
        <Row label="Gravatar" value={g.exists ? (g.profile?.display_name || "found") : "none"} mono={false} />
        {r.ai_summary && <p className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap pt-2">{r.ai_summary}</p>}
      </div>
    );
  }
  if (it.kind === "phone") {
    return (
      <div className="space-y-2">
        <Row label="Number" value={r.formats?.international || r.input} />
        <Row label="Valid" value={String(r.valid)} />
        <Row label="Region" value={r.region} mono={false} />
        <Row label="Carrier" value={r.carrier} mono={false} />
        <Row label="Line type" value={r.line_type} mono={false} />
        <Row label="Timezones" value={(r.timezones || []).join(", ")} />
      </div>
    );
  }
  if (it.kind === "image") {
    return (
      <div className="space-y-2">
        <img src={r.image_url} alt="target" className="w-full border border-border bg-black" />
        {Object.entries(r.exif || {}).map(([k, v]) => <Row key={k} label={k} value={String(v)} />)}
        {r.gps && <Row label="GPS" value={`${r.gps.lat}, ${r.gps.lon}`} />}
        {r.ai_analysis && <p className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap pt-2">{r.ai_analysis}</p>}
      </div>
    );
  }
  if (it.kind === "username") {
    const found = (r.results || []).filter((x) => x.status === "found");
    return (
      <div className="space-y-2">
        <Row label="Username" value={r.username} />
        <Row label="Likely present" value={`${r.found_count} / ${r.checked} sites`} />
        <div className="flex flex-wrap gap-2 pt-1">{found.map((x, i) => <a key={i} href={safeHttpUrl(x.url)} target="_blank" rel="noreferrer" className="font-mono text-[11px] border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 px-2 py-1">{x.site}</a>)}</div>
      </div>
    );
  }
  if (it.kind === "imei") {
    const d = r.result || {};
    return (
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <span className="data-label">{r.service} · {r.status}</span>
          <StatusBadges result={d} />
        </div>
        <Row label="IMEI" value={r.imei} />
        {Object.entries(d).filter(([k]) => !["image"].includes(k)).map(([k, v]) => <Row key={k} label={k} value={typeof v === "object" ? JSON.stringify(v) : String(v)} />)}
      </div>
    );
  }
  return <pre className="font-mono text-xs text-zinc-300 whitespace-pre-wrap break-all">{JSON.stringify(r, null, 2)}</pre>;
}

function CaseFile({ reloadKey }) {
  const [items, setItems] = useState([]);
  const [sel, setSel] = useState({});
  const [busy, setBusy] = useState(false);
  const [detail, setDetail] = useState(null);
  const load = async () => {
    try { const { data } = await api.get("/osint/history"); setItems(data); } catch { /* noop */ }
  };
  useEffect(() => { load(); }, [reloadKey]);
  const toggle = (id) => setSel((s) => ({ ...s, [id]: !s[id] }));
  const selectedIds = Object.keys(sel).filter((k) => sel[k]);
  const download = async () => {
    setBusy(true);
    try {
      const { data } = await api.post("/osint/report", { lookup_ids: selectedIds },
        { responseType: "blob" });
      const u = window.URL.createObjectURL(new Blob([data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = u; a.download = "InsafeLabs-OSINT-Dossier.pdf"; a.click();
      window.URL.revokeObjectURL(u);
      toast.success("Dossier downloaded");
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "No lookups to compile"); }
    finally { setBusy(false); }
  };
  const del = async (id) => { await api.delete(`/osint/history/${id}`); load(); };
  return (
    <div className="bg-[#121212] border border-border" data-testid="osint-casefile">
      <div className="flex items-center gap-2 px-6 py-4 border-b border-border">
        <FolderOpen className="w-4 h-4 text-primary" />
        <h3 className="font-heading text-lg font-semibold">Case File</h3>
        <span className="ml-auto data-label">{items.length} lookups · {selectedIds.length} selected</span>
        {items.length > 0 && <ClearModuleButton module="osint" onCleared={load} testId="osint-clear" />}
        <button onClick={download} disabled={busy} data-testid="osint-download-dossier"
          className="ml-3 bg-primary text-black font-semibold px-4 py-2 inline-flex items-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60 text-sm glow-primary">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileDown className="w-4 h-4" />} {selectedIds.length ? "Dossier (selected)" : "Full Dossier"}
        </button>
      </div>
      {items.length === 0 ? (
        <p className="p-6 text-sm text-zinc-500 text-center">No lookups yet. Run an investigation above — results are saved here, tap any row to view full details on screen or compile a PDF dossier.</p>
      ) : (
        <div className="divide-y divide-border max-h-80 overflow-y-auto">
          {items.map((it) => {
            const Icon = KIND_ICON[it.kind] || Fingerprint;
            return (
              <div key={it.id} className="flex items-center gap-3 px-6 py-3 hover:bg-white/[0.02]" data-testid={`case-item-${it.id}`}>
                <input type="checkbox" checked={!!sel[it.id]} onChange={() => toggle(it.id)} className="accent-primary cursor-pointer" data-testid={`case-check-${it.id}`} />
                <Icon className="w-4 h-4 text-zinc-500 shrink-0" />
                <span className="data-label w-16 shrink-0">{it.kind}</span>
                <button onClick={() => setDetail(it)} data-testid={`case-view-${it.id}`} className="text-sm text-white truncate flex-1 text-left hover:text-primary transition-colors">{it.query}</button>
                <span className="font-mono text-[10px] text-zinc-600 hidden sm:block">{it.created_at?.slice(0, 16).replace("T", " ")}</span>
                <button onClick={() => setDetail(it)} data-testid={`case-eye-${it.id}`} className="text-zinc-600 hover:text-primary"><Eye className="w-3.5 h-3.5" /></button>
                <button onClick={() => del(it.id)} data-testid={`case-del-${it.id}`} className="text-zinc-600 hover:text-severity-critical"><Trash2 className="w-3.5 h-3.5" /></button>
              </div>
            );
          })}
        </div>
      )}

      <Dialog open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <DialogContent className="bg-[#121212] border-border max-w-lg max-h-[85vh] overflow-y-auto" data-testid="case-detail-dialog">
          <DialogHeader>
            <DialogTitle className="font-heading flex items-center gap-2">
              {(() => { const I = KIND_ICON[detail?.kind] || Fingerprint; return <I className="w-4 h-4 text-primary" />; })()}
              <span className="truncate">{detail?.query}</span>
            </DialogTitle>
          </DialogHeader>
          <LookupDetail it={detail} />
        </DialogContent>
      </Dialog>
    </div>
  );
}
