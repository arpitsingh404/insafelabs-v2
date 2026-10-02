import { createContext, useContext, useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";

const Ctx = createContext(null);

async function reverseGeocode(lat, lon) {
  try {
    const r = await fetch(`https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${lat}&longitude=${lon}&localityLanguage=en`);
    const g = await r.json();
    return {
      city: g.city || g.locality || "Unknown",
      regionName: g.principalSubdivision || "",
      country: g.countryName || "",
      countryCode: g.countryCode || "",
    };
  } catch (e) {
    return {};
  }
}

export function OperatorLocationProvider({ children }) {
  const [node, setNode] = useState(null); // null=loading, false=unavailable, obj=data
  const [locating, setLocating] = useState(false);
  const alive = useRef(true);

  const loadIp = useCallback(() => {
    api.get("/tools/ipinfo")
      .then(({ data }) => { if (alive.current) setNode((prev) => ({ ...(prev || {}), ...data, source: prev && prev.source === "gps" ? "gps" : "ip" })); })
      .catch(() => { if (alive.current) setNode((prev) => prev || false); });
  }, []);

  const recenter = useCallback(() => {
    if (typeof navigator === "undefined" || !navigator.geolocation) return;
    setLocating(true);
    navigator.geolocation.getCurrentPosition(
      async (posn) => {
        const { latitude, longitude, accuracy } = posn.coords;
        const geo = await reverseGeocode(latitude, longitude);
        if (!alive.current) return;
        setNode((prev) => ({
          ...(prev || {}), ...geo,
          lat: +latitude.toFixed(5), lon: +longitude.toFixed(5),
          accuracy: Math.round(accuracy), source: "gps",
        }));
        setLocating(false);
      },
      () => { if (alive.current) setLocating(false); },
      { enableHighAccuracy: true, timeout: 12000, maximumAge: 0 }
    );
  }, []);

  useEffect(() => {
    alive.current = true;
    loadIp();
    recenter();
    return () => { alive.current = false; };
  }, [loadIp, recenter]);

  return <Ctx.Provider value={{ node, locating, recenter }}>{children}</Ctx.Provider>;
}

export function useOperatorLocation() {
  return useContext(Ctx) || { node: null, locating: false, recenter: () => {} };
}
