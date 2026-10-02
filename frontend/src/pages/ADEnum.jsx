import { useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { toast } from "sonner";
import {
  Network, Loader2, ShieldAlert, ShieldCheck, Users, Boxes, Server,
  KeyRound, Flame, Bot, Send, Crown, Download, HardDrive, FolderOpen, Share2,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60";
const ghostBtn = "border border-border px-3 py-1.5 text-xs font-mono uppercase tracking-wider text-zinc-300 hover:border-primary/50 hover:text-primary transition-colors inline-flex items-center gap-1.5";

const Card = ({ icon: Icon, title, extra, children, testId }) => (
  <div className="border border-border bg-[#0c0c0c]" data-testid={testId}>
    <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border">
      <Icon className="w-4 h-4 text-primary" />
      <span className="data-label">{title}</span>
      {extra != null && <span className="ml-auto data-label text-zinc-500">{extra}</span>}
    </div>
    <div className="p-4">{children}</div>
  </div>
);

function LdapPanel() {
  const [form, setForm] = useState({ host: "", port: 389, use_ssl: false, base_dn: "", username: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [exp, setExp] = useState(false);
  const [res, setRes] = useState(null);
  const [q, setQ] = useState("");
  const [advBusy, setAdvBusy] = useState(false);
  const [adv, setAdv] = useState("");

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));
  const payload = () => ({
    host: form.host.trim(), port: Number(form.port) || 389, use_ssl: form.use_ssl,
    base_dn: form.base_dn.trim() || null, username: form.username.trim() || null, password: form.password || null,
  });

  const run = async (e) => {
    e.preventDefault();
    if (!form.host.trim()) return toast.error("Enter a DC / LDAP host");
    setBusy(true); setRes(null);
    try {
      const { data } = await api.post("/offensive/ad/enumerate", payload(), { timeout: 60000 });
      setRes(data);
      if (data.bound) toast.success(`Bound to ${data.host} (${data.auth})`);
      else toast.error(data.error || "Bind failed");
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Enumeration failed"); }
    finally { setBusy(false); }
  };

  const exportBloodhound = async () => {
    setExp(true);
    try {
      const { data } = await api.post("/offensive/ad/bloodhound", payload(), { responseType: "blob", timeout: 60000 });
      const u = URL.createObjectURL(data);
      const a = document.createElement("a"); a.href = u; a.download = "insafelabs-bloodhound.zip"; a.click();
      URL.revokeObjectURL(u);
      toast.success("BloodHound JSON exported (users/groups/computers/domains)");
    } catch { toast.error("Export failed — enumerate & bind first"); }
    finally { setExp(false); }
  };

  const advise = async () => {
    if (!q.trim()) return toast.error("Describe your situation");
    setAdvBusy(true); setAdv("");
    try {
      const ctx = res?.base_dn ? `base_dn=${res.base_dn}; users=${res.counts?.users}; kerberoastable=${res.counts?.kerberoastable}; asrep=${res.counts?.asrep_roastable}` : "";
      const { data } = await api.post("/offensive/ad/advise", { question: q.trim(), context: ctx }, { timeout: 60000 });
      setAdv(data.answer);
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "Advisor failed"); }
    finally { setAdvBusy(false); }
  };

  const asrepSet = new Set(res?.asrep_roastable || []);
  const kerbSet = new Set((res?.kerberoastable || []).map((k) => k.sam));

  return (
    <>
      <form onSubmit={run} className="bg-[#121212] border border-border p-5 space-y-3">
        <div className="grid sm:grid-cols-[1fr_110px_auto] gap-2">
          <input className={inputCls} value={form.host} onChange={(e) => set("host", e.target.value)} data-testid="ad-host" placeholder="dc01.corp.local or LDAP IP" />
          <input className={inputCls} type="number" value={form.port} onChange={(e) => set("port", e.target.value)} data-testid="ad-port" placeholder="389" />
          <label className="flex items-center gap-2 text-sm text-zinc-400 px-2 border border-zinc-800 bg-[#0a0a0a]">
            <input type="checkbox" checked={form.use_ssl} onChange={(e) => set("use_ssl", e.target.checked)} data-testid="ad-ssl" className="accent-primary" /> LDAPS
          </label>
        </div>
        <div className="grid sm:grid-cols-3 gap-2">
          <input className={inputCls} value={form.base_dn} onChange={(e) => set("base_dn", e.target.value)} data-testid="ad-basedn" placeholder="base DN (optional) dc=corp,dc=local" />
          <input className={inputCls} value={form.username} onChange={(e) => set("username", e.target.value)} data-testid="ad-user" placeholder="user (optional) — CORP\\user or user@corp" autoComplete="off" />
          <input className={inputCls} type="password" value={form.password} onChange={(e) => set("password", e.target.value)} data-testid="ad-pass" placeholder="password (optional)" autoComplete="off" />
        </div>
        <button className={btnCls} disabled={busy} data-testid="ad-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Network className="w-4 h-4" />} Enumerate</button>
      </form>

      {res && (
        <div className="space-y-4" data-testid="ad-result">
          <div className="border p-4 flex items-center gap-3" data-testid="ad-status"
            style={{ borderColor: res.bound ? "#22C55E66" : "#EF444466", background: res.bound ? "#22C55E14" : "#EF444414" }}>
            {res.bound ? <ShieldCheck className="w-5 h-5 text-emerald-400" /> : <ShieldAlert className="w-5 h-5 text-severity-critical" />}
            <div className="min-w-0 flex-1">
              <p className="font-heading text-sm font-semibold" style={{ color: res.bound ? "#22C55E" : "#EF4444" }}>
                {res.bound ? `BOUND · ${res.auth.toUpperCase()}` : "BIND FAILED"}
              </p>
              <p className="data-label mt-0.5">{res.host}:{res.port} · base: {res.base_dn || "—"}{res.domain_fqdn ? ` · ${res.domain_fqdn}` : ""}</p>
              {res.error && <p className="text-xs text-zinc-400 mt-1">{res.error}</p>}
            </div>
            {res.bound && (
              <button onClick={exportBloodhound} disabled={exp} data-testid="ad-bloodhound" className={ghostBtn}>
                {exp ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />} BloodHound JSON
              </button>
            )}
          </div>

          {res.counts && (
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2" data-testid="ad-counts">
              {[["Users", res.counts.users, Users], ["Groups", res.counts.groups, Boxes], ["Computers", res.counts.computers, Server], ["AS-REP", res.counts.asrep_roastable, Flame], ["Kerberoast", res.counts.kerberoastable, KeyRound]].map(([l, v, Ic]) => (
                <div key={l} className="border border-border bg-[#0a0a0a] p-3">
                  <p className="data-label flex items-center gap-1.5"><Ic className="w-3 h-3" /> {l}</p>
                  <p className="font-mono text-2xl text-white mt-1">{v ?? 0}</p>
                </div>
              ))}
            </div>
          )}

          {(res.users || []).length > 0 && (
            <Card icon={Users} title="Users" extra={res.counts?.users} testId="ad-users">
              <div className="max-h-80 overflow-y-auto space-y-1">
                {res.users.map((u, i) => (
                  <div key={i} className="flex items-center gap-2 border-b border-border/40 py-1.5 flex-wrap" data-testid={`ad-user-${i}`}>
                    <span className="font-mono text-xs text-white">{u.sam || u.upn || "—"}</span>
                    {u.admin && <span className="font-mono text-[10px] border border-primary/50 text-primary px-1.5 py-0.5 inline-flex items-center gap-1"><Crown className="w-3 h-3" /> admin</span>}
                    {asrepSet.has(u.sam) && <span className="font-mono text-[10px] border border-severity-critical/50 bg-severity-critical/10 text-severity-critical px-1.5 py-0.5">AS-REP ROASTABLE</span>}
                    {kerbSet.has(u.sam) && <span className="font-mono text-[10px] border border-severity-high/50 bg-severity-high/10 text-severity-high px-1.5 py-0.5">KERBEROASTABLE</span>}
                    {(u.flags || []).filter((f) => f !== "NORMAL_ACCOUNT").map((f) => <span key={f} className="font-mono text-[10px] border border-border text-zinc-500 px-1.5 py-0.5">{f}</span>)}
                    {u.desc && <span className="text-[11px] text-zinc-600 truncate ml-auto max-w-[40%]">{u.desc}</span>}
                  </div>
                ))}
              </div>
            </Card>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            {(res.groups || []).length > 0 && (
              <Card icon={Boxes} title="Groups" extra={res.counts?.groups} testId="ad-groups">
                <div className="max-h-64 overflow-y-auto space-y-1 font-mono text-xs">
                  {res.groups.map((g, i) => (
                    <div key={i} className="flex items-center gap-2 border-b border-border/40 py-1">
                      <span className="text-zinc-300">{g.cn}</span>
                      {g.admin && <span className="text-[10px] border border-primary/50 text-primary px-1.5 py-0.5">adminCount</span>}
                    </div>
                  ))}
                </div>
              </Card>
            )}
            {(res.computers || []).length > 0 && (
              <Card icon={Server} title="Computers" extra={res.counts?.computers} testId="ad-computers">
                <div className="max-h-64 overflow-y-auto space-y-1 font-mono text-xs">
                  {res.computers.map((c, i) => (
                    <div key={i} className="border-b border-border/40 py-1">
                      <span className="text-zinc-300">{c.cn}</span>
                      {c.os && <span className="text-zinc-600 ml-2">{c.os}</span>}
                    </div>
                  ))}
                </div>
              </Card>
            )}
          </div>

          {(res.notes || []).length > 0 && (
            <div className="bg-[#0a0a0a] border border-border p-4">
              <p className="data-label mb-2">Notes</p>
              {res.notes.map((n, i) => <p key={i} className="font-mono text-[11px] text-zinc-500">• {n}</p>)}
            </div>
          )}
        </div>
      )}

      {/* AI Advisor */}
      <div className="bg-[#121212] border border-border" data-testid="ad-advisor">
        <div className="flex items-center gap-2 px-5 py-3 border-b border-border"><Bot className="w-4 h-4 text-primary" /><span className="font-heading text-sm font-semibold">AD Attack Advisor</span></div>
        <div className="p-5 space-y-3">
          <div className="flex flex-col sm:flex-row gap-2">
            <input className={inputCls} value={q} onChange={(e) => setQ(e.target.value)} data-testid="ad-advisor-input" placeholder="e.g. I have a low-priv domain user — what's my privesc path?" />
            <button className={btnCls} disabled={advBusy} onClick={advise} data-testid="ad-advisor-run">{advBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />} Advise</button>
          </div>
          {adv && <div className="border border-border bg-[#0a0a0a] p-4 font-mono text-[13px] text-zinc-200 whitespace-pre-wrap leading-relaxed max-h-[420px] overflow-y-auto" data-testid="ad-advisor-out">{adv}</div>}
        </div>
      </div>
    </>
  );
}

function SmbPanel() {
  const [f, setF] = useState({ host: "", username: "", password: "", domain: "" });
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const set = (k, v) => setF((s) => ({ ...s, [k]: v }));

  const run = async (e) => {
    e.preventDefault();
    if (!f.host.trim()) return toast.error("Enter an SMB host / IP");
    setBusy(true); setRes(null);
    try {
      const { data } = await api.post("/offensive/smb/enumerate", {
        host: f.host.trim(), username: f.username.trim() || null, password: f.password || null, domain: f.domain.trim() || "",
      }, { timeout: 45000 });
      setRes(data);
      if (data.connected) toast.success(`Connected · ${data.shares.length} share(s)`);
      else toast.error(data.error || "SMB connect failed");
    } catch (err) { toast.error(formatApiError(err.response?.data?.detail) || "SMB enum failed"); }
    finally { setBusy(false); }
  };

  return (
    <>
      <p className="text-xs text-zinc-500 font-mono">Null / guest / authenticated SMB session → list shares & readable files. Modern Windows blocks null sessions by default. Authorized hosts only.</p>
      <form onSubmit={run} className="bg-[#121212] border border-border p-5 space-y-3">
        <input className={inputCls} value={f.host} onChange={(e) => set("host", e.target.value)} data-testid="smb-host" placeholder="fileserver.corp.local or IP (SMB / port 445)" />
        <div className="grid sm:grid-cols-3 gap-2">
          <input className={inputCls} value={f.username} onChange={(e) => set("username", e.target.value)} data-testid="smb-user" placeholder="username (blank = null/guest)" autoComplete="off" />
          <input className={inputCls} type="password" value={f.password} onChange={(e) => set("password", e.target.value)} data-testid="smb-pass" placeholder="password" autoComplete="off" />
          <input className={inputCls} value={f.domain} onChange={(e) => set("domain", e.target.value)} data-testid="smb-domain" placeholder="domain / workgroup (optional)" />
        </div>
        <button className={btnCls} disabled={busy} data-testid="smb-run">{busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <HardDrive className="w-4 h-4" />} Enumerate Shares</button>
      </form>

      {res && (
        <div className="space-y-4" data-testid="smb-result">
          <div className="border p-4 flex items-center gap-3" data-testid="smb-status"
            style={{ borderColor: res.connected ? "#22C55E66" : "#EF444466", background: res.connected ? "#22C55E14" : "#EF444414" }}>
            {res.connected ? <ShieldCheck className="w-5 h-5 text-emerald-400" /> : <ShieldAlert className="w-5 h-5 text-severity-critical" />}
            <div className="min-w-0">
              <p className="font-heading text-sm font-semibold" style={{ color: res.connected ? "#22C55E" : "#EF4444" }}>
                {res.connected ? `CONNECTED · ${res.session}` : "SMB CONNECT FAILED"}
              </p>
              <p className="data-label mt-0.5">{res.host}:445 · {res.shares?.length || 0} share(s)</p>
              {res.error && <p className="text-xs text-zinc-400 mt-1">{res.error}</p>}
            </div>
          </div>

          {(res.shares || []).map((sh, i) => (
            <Card key={i} icon={sh.special ? Server : FolderOpen} title={`\\\\${res.host}\\${sh.name}`}
              extra={sh.readable ? `${sh.file_count} items` : (sh.special ? "special" : "no access")} testId={`smb-share-${i}`}>
              {sh.comments && <p className="text-[11px] text-zinc-500 mb-2">{sh.comments}</p>}
              {sh.readable ? (
                <div className="max-h-48 overflow-y-auto grid sm:grid-cols-2 gap-x-4 gap-y-0.5 font-mono text-[11px] text-zinc-400">
                  {sh.files.map((fn, j) => <div key={j} className="truncate">• {fn}</div>)}
                  {sh.files.length === 0 && <p className="text-zinc-600">empty (readable)</p>}
                </div>
              ) : (
                <p className="text-xs text-zinc-600">{sh.special ? "IPC$/admin share — not listed." : (sh.error || "Access denied.")}</p>
              )}
            </Card>
          ))}

          {(res.notes || []).length > 0 && (
            <div className="bg-[#0a0a0a] border border-border p-4">
              <p className="data-label mb-2">Notes</p>
              {res.notes.map((n, i) => <p key={i} className="font-mono text-[11px] text-zinc-500">• {n}</p>)}
            </div>
          )}
        </div>
      )}
    </>
  );
}

export default function ADEnum() {
  const [tab, setTab] = useState("ldap");
  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="ad-enum-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary"><Network className="w-6 h-6 text-primary" /></div>
        <div>
          <p className="data-label mb-1">/ Active Directory</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">AD / LDAP Enumeration</h1>
          <p className="text-sm text-zinc-500 mt-1">Enumerate a Domain Controller over LDAP (users/groups/computers, roastable accounts, BloodHound export) or map SMB shares. Authorized targets only.</p>
        </div>
      </div>

      <div className="flex border border-border w-fit" data-testid="ad-tabs">
        {[["ldap", "LDAP Enum", Network], ["smb", "SMB Shares", Share2]].map(([v, label, Ic]) => (
          <button key={v} onClick={() => setTab(v)} data-testid={`ad-tab-${v}`}
            className={`inline-flex items-center gap-1.5 px-4 py-2 text-xs font-mono uppercase tracking-wider transition-colors ${tab === v ? "bg-primary text-black" : "text-zinc-400 hover:text-primary"}`}>
            <Ic className="w-3.5 h-3.5" /> {label}
          </button>
        ))}
      </div>

      {tab === "ldap" ? <LdapPanel /> : <SmbPanel />}
    </div>
  );
}
