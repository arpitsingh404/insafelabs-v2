import { useEffect, useState } from "react";
import { Bell, ShieldAlert, Globe2, Maximize2, X, Crosshair, Flame, MapPin } from "lucide-react";
import { ThreatGlobe } from "@/components/GeoMaps";
import { useOperatorLocation } from "@/context/OperatorLocationContext";

const MODES = [
  { key: "beams", label: "Live Attack", icon: Crosshair },
  { key: "heatmap", label: "Heatmap", icon: Flame },
  { key: "markers", label: "Markers", icon: MapPin },
];

function ModeToggle({ mode, setMode, scope = "" }) {
  return (
    <div className="flex border border-border" data-testid={`threat-mode-toggle${scope}`}>
      {MODES.map(({ key, label, icon: Icon }) => (
        <button key={key} onClick={() => setMode(key)} data-testid={`threat-mode-${key}${scope}`}
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider transition-colors ${mode === key ? "bg-primary text-black" : "text-zinc-400 hover:text-primary"}`}>
          <Icon className="w-3 h-3" /> <span className="hidden sm:inline">{label}</span>
        </button>
      ))}
    </div>
  );
}

export function ThreatMap({ points = [] }) {
  const { node } = useOperatorLocation();
  const op = node && node.lat != null ? { lat: node.lat, lon: node.lon } : null;
  const [mode, setMode] = useState("beams");
  const [fs, setFs] = useState(false);

  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") setFs(false); };
    if (fs) { document.addEventListener("keydown", onKey); document.body.style.overflow = "hidden"; }
    return () => { document.removeEventListener("keydown", onKey); document.body.style.overflow = ""; };
  }, [fs]);

  const geoPts = (points || []).filter((p) => p.lat != null && p.lon != null);

  const Header = ({ inFs }) => (
    <div className="px-5 py-4 border-b border-border space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="data-label">Global Recon</p>
          <h3 className="font-heading text-lg font-semibold mt-1 truncate">Threat Map</h3>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="inline-flex items-center gap-1.5 data-label text-emerald-400"><span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" /> live</span>
          <button onClick={() => setFs(!inFs)} data-testid={inFs ? "threat-fs-close" : "threat-fs-open"}
            className="border border-border p-1.5 text-zinc-400 hover:text-primary hover:border-primary/50 transition-colors">
            {inFs ? <X className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>
      <div className="flex items-center gap-3 flex-wrap">
        <ModeToggle mode={mode} setMode={setMode} scope={inFs ? "-fs" : ""} />
        <span className="inline-flex items-center gap-1.5 data-label whitespace-nowrap" data-testid="threat-origin">
          <Crosshair className="w-3.5 h-3.5 text-primary" /> {node && node.source === "gps" ? "from your node" : "from ip node"}
        </span>
        <span className="inline-flex items-center gap-1.5 data-label whitespace-nowrap"><Globe2 className="w-3.5 h-3.5" /> {geoPts.length} points</span>
      </div>
    </div>
  );

  return (
    <>
      <div className="bg-[#121212] border border-border" data-testid="threat-map">
        <Header inFs={false} />
        <div className="relative">
          <ThreatGlobe points={geoPts} operator={op} mode={mode} />
          {geoPts.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-[500]">
              <p className="data-label bg-black/70 px-4 py-2 border border-border">No geo-located scans yet — run the Attack Surface Scanner</p>
            </div>
          )}
        </div>
      </div>

      {fs && (
        <div className="fixed inset-0 z-[9999] bg-[#0a0a0a] flex flex-col" data-testid="threat-fullscreen">
          <Header inFs={true} />
          <div className="relative flex-1">
            <ThreatGlobe points={geoPts} operator={op} mode={mode} fill />
            {geoPts.length === 0 && (
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-[500]">
                <p className="data-label bg-black/70 px-4 py-2 border border-border">No geo-located scans yet</p>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export function AlertsFeed({ alerts = [] }) {
  return (
    <div className="bg-[#121212] border border-border flex flex-col" data-testid="alerts-feed">
      <div className="px-5 py-4 border-b border-border flex items-center gap-2">
        <Bell className="w-4 h-4 text-primary" />
        <h3 className="font-heading text-sm font-semibold">Exposure Alerts</h3>
        <span className="ml-auto data-label">{alerts.length}</span>
      </div>
      <div className="divide-y divide-border flex-1 overflow-y-auto max-h-[360px]">
        {alerts.length === 0 ? (
          <p className="p-6 text-sm text-zinc-500 text-center">No new-exposure alerts yet. Scheduled monitors post here when a target changes.</p>
        ) : (
          alerts.map((a, i) => (
            <div key={i} className="p-4" data-testid={`alert-${i}`}>
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5 text-severity-high" />
                <span className="font-mono text-xs text-white truncate">{a.target}</span>
                <span className="ml-auto data-label">{a.count} new</span>
              </div>
              <p className="text-xs text-zinc-400 mt-1.5 line-clamp-2">{(a.new_findings || []).slice(0, 3).join(" · ")}</p>
              <p className="data-label mt-1">{a.created_at?.slice(0, 16).replace("T", " ")}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
