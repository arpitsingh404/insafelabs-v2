import { useEffect, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import "leaflet.heat";
import { escapeHtml } from "@/lib/safeUrl";

// Leaflet renders tooltip strings as HTML — never interpolate raw scan data.
const markerTip = (p, color) =>
  `<b style="color:${escapeHtml(color)}">${escapeHtml(p.host || "target")}</b><br/>${escapeHtml(p.country || "")} · risk ${escapeHtml(p.risk_score ?? "—")}`;

const DARK_TILES = "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}";
const SAT_TILES = "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}";
const SAT_LABELS = "https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}";
const ATTR = '© Esri, HERE, Garmin, OpenStreetMap contributors';
const SAT_ATTR = 'Imagery © Esri, Maxar, Earthstar Geographics';
const POSTURE_COLOR = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#71717A" };

// Basemap presets — all free / no API key required.
const THEMES = {
  satellite: { label: "Satellite", url: SAT_TILES, attr: SAT_ATTR, maxZoom: 19, labels: SAT_LABELS },
  dark: { label: "Dark", url: DARK_TILES, attr: ATTR, maxZoom: 19 },
  terrain: { label: "Terrain", url: "https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png", attr: "© OpenTopoMap (CC-BY-SA)", sub: "abc", maxZoom: 17 },
  streets: { label: "Streets", url: "https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}", attr: "© Esri", maxZoom: 19 },
};

function applyBaseTheme(map, key, refs) {
  const th = THEMES[key] || THEMES.dark;
  if (refs.base) { try { map.removeLayer(refs.base); } catch (e) {} refs.base = null; }
  if (refs.labels) { try { map.removeLayer(refs.labels); } catch (e) {} refs.labels = null; }
  refs.base = L.tileLayer(th.url, { subdomains: th.sub || "abc", maxZoom: th.maxZoom || 19, attribution: th.attr, noWrap: false }).addTo(map);
  refs.base.setZIndex(0);
  if (th.labels) {
    refs.labels = L.tileLayer(th.labels, { maxZoom: th.maxZoom || 19, opacity: 0.85 }).addTo(map);
    refs.labels.setZIndex(1);
  }
}

function ThemeSwitcher({ theme, setTheme, testId = "map-theme" }) {
  return (
    <div className="absolute top-2 right-2 z-[500] flex gap-1" data-testid={testId}>
      {Object.entries(THEMES).map(([k, t]) => (
        <button key={k} type="button" onClick={() => setTheme(k)} data-testid={`${testId}-${k}`}
          className={`text-[10px] font-mono uppercase tracking-wider px-2 py-1 border transition-colors ${theme === k ? "bg-primary text-black border-primary" : "bg-black/70 backdrop-blur text-primary border-primary/40 hover:bg-primary/20"}`}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

function pulseIcon(color, size = 16) {
  return L.divIcon({
    className: "",
    html: `<span class="daxx-pulse" style="--c:${color};width:${size}px;height:${size}px"></span>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

/* Operator node — realistic map centered on the live coords. 4 basemap presets. */
export function OperatorMiniMap({ lat, lon }) {
  const elRef = useRef(null);
  const mapRef = useRef(null);
  const layerRefs = useRef({ base: null, labels: null });
  const [theme, setTheme] = useState("satellite");

  useEffect(() => {
    if (lat == null || lon == null || !elRef.current) return;
    const map = L.map(elRef.current, {
      center: [lat, lon], zoom: 13, zoomControl: false, attributionControl: true,
      scrollWheelZoom: false, dragging: true, doubleClickZoom: true, keyboard: false,
    });
    mapRef.current = map;
    L.circle([lat, lon], { radius: 1400, color: "#FACC15", weight: 1, opacity: 0.6, fillColor: "#FACC15", fillOpacity: 0.06 }).addTo(map);
    L.marker([lat, lon], { icon: pulseIcon("#FACC15", 16) }).addTo(map);
    L.control.zoom({ position: "bottomright" }).addTo(map);
    const t = setTimeout(() => map.invalidateSize(), 250);
    return () => { clearTimeout(t); map.remove(); mapRef.current = null; layerRefs.current = { base: null, labels: null }; };
  }, [lat, lon]);

  useEffect(() => {
    if (mapRef.current) applyBaseTheme(mapRef.current, theme, layerRefs.current);
  }, [theme, lat, lon]);

  return (
    <div className="relative">
      <div ref={elRef} className="w-full h-44 border border-border" data-testid="geo-map" style={{ background: "#0a0a0a" }} />
      <div className="absolute inset-0 pointer-events-none border border-primary/10" style={{ boxShadow: "inset 0 0 40px rgba(0,0,0,0.6)" }} />
      <ThemeSwitcher theme={theme} setTheme={setTheme} testId="geo-map-theme" />
    </div>
  );
}

/* Threat map — real dark world map. mode: 'beams' (live attack anim) | 'heatmap' | 'markers' */
export function ThreatGlobe({ points = [], operator, mode = "beams", fill = false }) {
  const elRef = useRef(null);
  const mapRef = useRef(null);
  const layerRefs = useRef({ base: null, labels: null });
  const themeRef = useRef("dark");
  const timers = useRef({ raf: null, interval: null });
  const [theme, setTheme] = useState("dark");

  useEffect(() => {
    if (!elRef.current) return;
    const tm = timers.current;
    const map = L.map(elRef.current, {
      center: [22, 10], zoom: fill ? 2 : 2, minZoom: 1, maxZoom: 6, zoomControl: false,
      attributionControl: true, scrollWheelZoom: fill, worldCopyJump: true,
      maxBounds: [[-85, -200], [85, 200]], maxBoundsViscosity: 0.6,
    });
    mapRef.current = map;
    applyBaseTheme(map, themeRef.current, layerRefs.current);
    L.control.zoom({ position: "bottomright" }).addTo(map);

    const opLL = operator && operator.lat != null ? [operator.lat, operator.lon] : null;
    const geo = (points || []).filter((p) => p.lat != null && p.lon != null);

    if (mode === "heatmap") {
      const heatPts = geo.map((p) => [p.lat, p.lon, Math.max(0.35, (p.risk_score || 30) / 100)]);
      if (heatPts.length) {
        L.heatLayer(heatPts, {
          radius: fill ? 40 : 28, blur: fill ? 30 : 20, max: 1.0, minOpacity: 0.35,
          gradient: { 0.2: "#1d4ed8", 0.4: "#22c55e", 0.6: "#F59E0B", 0.8: "#F97316", 1.0: "#EF4444" },
        }).addTo(map);
      }
      geo.forEach((p) => {
        const color = POSTURE_COLOR[p.posture] || "#3B82F6";
        L.circleMarker([p.lat, p.lon], { radius: 3, color, weight: 1, fillColor: color, fillOpacity: 0.9 })
          .addTo(map).bindTooltip(markerTip(p, color), { className: "daxx-tip", direction: "top", opacity: 1 });
      });
    } else {
      // markers + (optional) beams
      geo.forEach((p) => {
        const color = POSTURE_COLOR[p.posture] || "#3B82F6";
        if (mode === "beams" && opLL) {
          L.polyline([opLL, [p.lat, p.lon]], { color, weight: 1, opacity: 0.28, dashArray: "3 7", interactive: false }).addTo(map);
        }
        L.circleMarker([p.lat, p.lon], { radius: 5, color, weight: 1.5, fillColor: color, fillOpacity: 0.85 })
          .addTo(map).bindTooltip(markerTip(p, color), { className: "daxx-tip", direction: "top", opacity: 1 });
      });

      // Live attack animation: fire a tracer from operator to each target, one by one
      if (mode === "beams" && opLL && geo.length) {
        const fxLayer = L.layerGroup().addTo(map);
        let idx = 0;
        const fire = () => {
          const p = geo[idx % geo.length];
          idx += 1;
          const color = POSTURE_COLOR[p.posture] || "#3B82F6";
          const from = L.latLng(opLL[0], opLL[1]);
          const to = L.latLng(p.lat, p.lon);
          const tracer = L.polyline([from, from], { color, weight: 2, opacity: 0.9, interactive: false }).addTo(fxLayer);
          const bullet = L.circleMarker(from, { radius: 3, color: "#fff", weight: 1, fillColor: color, fillOpacity: 1, interactive: false }).addTo(fxLayer);
          const dur = 850;
          const start = performance.now();
          const step = (now) => {
            const k = Math.min(1, (now - start) / dur);
            const cur = L.latLng(from.lat + (to.lat - from.lat) * k, from.lng + (to.lng - from.lng) * k);
            tracer.setLatLngs([from, cur]);
            bullet.setLatLng(cur);
            if (k < 1) {
              timers.current.raf = requestAnimationFrame(step);
            } else {
              // impact flash
              const ping = L.circleMarker(to, { radius: 4, color, weight: 2, fillColor: color, fillOpacity: 0.6, interactive: false }).addTo(fxLayer);
              let r = 4, op = 0.6;
              const grow = () => {
                r += 1.4; op -= 0.06;
                ping.setRadius(r); ping.setStyle({ fillOpacity: Math.max(0, op), opacity: Math.max(0, op) });
                if (op > 0) timers.current.raf = requestAnimationFrame(grow); else fxLayer.removeLayer(ping);
              };
              timers.current.raf = requestAnimationFrame(grow);
              setTimeout(() => { fxLayer.removeLayer(tracer); fxLayer.removeLayer(bullet); }, 500);
            }
          };
          timers.current.raf = requestAnimationFrame(step);
        };
        fire();
        timers.current.interval = setInterval(fire, 1400);
      }
    }

    if (opLL) {
      L.marker(opLL, { icon: pulseIcon("#FACC15", 18), zIndexOffset: 1000 }).addTo(map)
        .bindTooltip('<b style="color:#FACC15">OPERATOR NODE</b>', { className: "daxx-tip", direction: "top", opacity: 1 });
    }

    const t = setTimeout(() => map.invalidateSize(), 250);
    return () => {
      clearTimeout(t);
      if (tm.raf) cancelAnimationFrame(tm.raf);
      if (tm.interval) clearInterval(tm.interval);
      map.remove();
      mapRef.current = null;
      layerRefs.current = { base: null, labels: null };
    };
  }, [points, operator, mode, fill]);

  // swap basemap when theme changes, without rebuilding the whole globe
  useEffect(() => {
    themeRef.current = theme;
    if (mapRef.current) applyBaseTheme(mapRef.current, theme, layerRefs.current);
  }, [theme]);

  return (
    <div className={`relative w-full ${fill ? "h-full" : ""}`} style={fill ? undefined : { aspectRatio: "2 / 1" }}>
      <div ref={elRef} className="w-full h-full" style={{ background: "#0a0a0a" }} data-testid="threat-globe" />
      <ThemeSwitcher theme={theme} setTheme={setTheme} testId="threat-globe-theme" />
    </div>
  );
}
