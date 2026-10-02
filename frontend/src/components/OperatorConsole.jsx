import { useEffect, useState } from "react";
import { api, formatApiError } from "@/lib/api";
import { toast } from "sonner";
import {
  Clock, MapPin, Wifi, Search, Loader2, Globe2, ShieldAlert, Radio, Server, LocateFixed,
} from "lucide-react";
import { OperatorMiniMap } from "@/components/GeoMaps";
import { useOperatorLocation } from "@/context/OperatorLocationContext";

const flagUrl = (cc) => (cc ? `https://flagcdn.com/w40/${cc.toLowerCase()}.png` : null);

function useNow() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

function GeoDetail({ node }) {
  if (!node) return null;
  return (
    <div className="space-y-1.5 font-mono text-xs" data-testid="geo-detail">
      <div className="flex items-center gap-2">
        <span data-testid="geo-source" className={`text-[10px] uppercase tracking-widest px-1.5 py-0.5 border ${node.source === "gps" ? "text-emerald-400 border-emerald-400/40" : "text-primary border-primary/40"}`}>
          {node.source === "gps" ? "GPS · Real Location" : "IP-Based Location"}
        </span>
      </div>
      <div className="flex items-center gap-2">
        {flagUrl(node.countryCode) && <img src={flagUrl(node.countryCode)} alt={node.countryCode} className="w-6 h-auto border border-border" />}
        <span className="text-white text-sm">{node.city}, {node.regionName}</span>
        <span className="text-zinc-500">{node.country}</span>
      </div>
      <Row k="IP" v={node.query || "—"} accent />
      <Row k="ISP" v={node.isp || "—"} />
      <Row k="Org" v={node.org || "—"} />
      <Row k="ASN" v={node.as || "—"} />
      <Row k="Coords" v={`${node.lat}, ${node.lon}`} />
      {node.accuracy != null && <Row k="GPS Accuracy" v={`± ${node.accuracy} m`} />}
      <Row k="Timezone" v={node.timezone || "—"} />
      <div className="flex gap-2 pt-1">
        {node.proxy && <span className="text-[10px] uppercase tracking-widest text-severity-high border border-severity-high/40 px-1.5 py-0.5">Proxy/VPN</span>}
        {node.hosting && <span className="text-[10px] uppercase tracking-widest text-severity-low border border-severity-low/40 px-1.5 py-0.5">Hosting</span>}
        {node.mobile && <span className="text-[10px] uppercase tracking-widest text-zinc-400 border border-border px-1.5 py-0.5">Mobile</span>}
      </div>
    </div>
  );
}

const Row = ({ k, v, accent }) => (
  <div className="flex items-center justify-between gap-3 border-b border-border/40 pb-1">
    <span className="text-zinc-500">{k}</span>
    <span className={`truncate max-w-[62%] ${accent ? "text-primary" : "text-zinc-300"}`}>{v}</span>
  </div>
);

export function LiveCommandBar() {
  const now = useNow();
  const { node, locating, recenter } = useOperatorLocation();
  const [lookup, setLookup] = useState("");
  const [lookupRes, setLookupRes] = useState(null);
  const [looking, setLooking] = useState(false);

  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const timeStr = now.toLocaleTimeString("en-GB", { hour12: false });
  const dateStr = now.toLocaleDateString("en-US", { weekday: "short", year: "numeric", month: "short", day: "numeric" });
  const utcStr = now.toISOString().slice(11, 19);

  const doLookup = async (e) => {
    e.preventDefault();
    if (!lookup.trim()) return;
    setLooking(true);
    setLookupRes(null);
    try {
      const { data } = await api.get("/tools/ipinfo", { params: { ip: lookup.trim() } });
      setLookupRes(data);
    } catch (err) {
      toast.error(formatApiError(err.response?.data?.detail) || "Lookup failed");
    } finally {
      setLooking(false);
    }
  };

  return (
    <div className="relative border border-border bg-[#0c0c0c] overflow-hidden" data-testid="live-command-bar">
      <div className="absolute inset-0 pointer-events-none" style={{ backgroundImage: "linear-gradient(rgba(250,204,21,0.03) 1px, transparent 1px)", backgroundSize: "100% 3px" }} />
      <div className="relative grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-border">
        {/* Clock */}
        <div className="lg:col-span-4 p-6" data-testid="clock-panel">
          <div className="flex items-center gap-2 mb-4">
            <Radio className="w-4 h-4 text-primary animate-pulse-glow" />
            <span className="data-label !text-primary">Live Operations · Real-Time</span>
          </div>
          <div className="flex items-baseline gap-2">
            <Clock className="w-5 h-5 text-zinc-500" />
            <span className="font-mono text-4xl md:text-5xl font-bold text-white tracking-tight tabular-nums" data-testid="live-clock">{timeStr}</span>
          </div>
          <p className="text-sm text-zinc-400 mt-2">{dateStr}</p>
          <div className="grid grid-cols-2 gap-3 mt-4">
            <div className="border border-border bg-[#0a0a0a] px-3 py-2">
              <p className="data-label">Timezone</p>
              <p className="font-mono text-xs text-primary mt-0.5 truncate">{tz}</p>
            </div>
            <div className="border border-border bg-[#0a0a0a] px-3 py-2">
              <p className="data-label">UTC</p>
              <p className="font-mono text-xs text-zinc-300 mt-0.5 tabular-nums">{utcStr}</p>
            </div>
          </div>
        </div>

        {/* Operator node / geo */}
        <div className="lg:col-span-4 p-6" data-testid="node-panel">
          <div className="flex items-center gap-2 mb-4">
            <MapPin className="w-4 h-4 text-primary" />
            <span className="data-label">Operator Node · Live Location</span>
            <span className="ml-auto flex items-center gap-1.5 data-label" data-testid="node-source-badge">
              {node && node.source === "gps"
                ? <><MapPin className="w-3 h-3 text-emerald-400" /> gps fix</>
                : <><Wifi className="w-3 h-3 text-emerald-400" /> ip-based</>}
            </span>
            <button type="button" onClick={() => recenter()} disabled={locating} data-testid="recenter-btn" title="Recenter on my live GPS"
              className="flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider border border-primary/40 text-primary px-2 py-1 hover:bg-primary/10 transition-colors disabled:opacity-60">
              {locating ? <Loader2 className="w-3 h-3 animate-spin" /> : <LocateFixed className="w-3 h-3" />} me
            </button>
          </div>
          {node === null ? (
            <div className="flex items-center gap-2 text-zinc-500 text-sm py-6"><Loader2 className="w-4 h-4 animate-spin" /> triangulating node…</div>
          ) : node === false ? (
            <p className="text-sm text-zinc-500 py-6">Geo lookup unavailable.</p>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              <OperatorMiniMap lat={node.lat} lon={node.lon} />
              <GeoDetail node={node} />
            </div>
          )}
        </div>

        {/* IP lookup tool */}
        <div className="lg:col-span-4 p-6" data-testid="iplookup-panel">
          <div className="flex items-center gap-2 mb-4">
            <Globe2 className="w-4 h-4 text-primary" />
            <span className="data-label">IP / Domain Geo-Lookup</span>
          </div>
          <form onSubmit={doLookup} className="flex gap-2">
            <input value={lookup} onChange={(e) => setLookup(e.target.value)} data-testid="iplookup-input"
              placeholder="8.8.8.8 or target.com"
              className="flex-1 bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors" />
            <button type="submit" disabled={looking} data-testid="iplookup-btn"
              className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center gap-1.5 hover:bg-yellow-500 transition-colors disabled:opacity-60">
              {looking ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            </button>
          </form>
          <div className="mt-4">
            {lookupRes ? (
              <div className="border border-border bg-[#0a0a0a] p-3" data-testid="iplookup-result">
                <div className="flex items-center gap-2 mb-2">
                  {flagUrl(lookupRes.countryCode) && <img src={flagUrl(lookupRes.countryCode)} alt="" className="w-6 h-auto border border-border" />}
                  <span className="text-white text-sm">{lookupRes.city}, {lookupRes.country}</span>
                </div>
                <div className="font-mono text-[11px] text-zinc-400 space-y-1">
                  <p><span className="text-zinc-600">IP:</span> <span className="text-primary">{lookupRes.query}</span></p>
                  <p><span className="text-zinc-600">ISP:</span> {lookupRes.isp}</p>
                  <p><span className="text-zinc-600">Coords:</span> {lookupRes.lat}, {lookupRes.lon} · {lookupRes.timezone}</p>
                  {(lookupRes.proxy || lookupRes.hosting) && (
                    <p className="text-severity-high inline-flex items-center gap-1"><ShieldAlert className="w-3 h-3" /> {lookupRes.proxy ? "Proxy/VPN " : ""}{lookupRes.hosting ? "Hosting" : ""}</p>
                  )}
                </div>
              </div>
            ) : (
              <div className="border border-dashed border-border p-4 text-center text-zinc-600 text-xs flex flex-col items-center gap-2">
                <Server className="w-5 h-5 opacity-50" />
                Resolve any IP or domain to its geo-location, ISP and threat flags.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
