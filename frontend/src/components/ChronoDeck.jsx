import { useEffect, useState } from "react";
import { Clock, Globe2, CalendarDays, Timer, Sun, Moon, Plus, X } from "lucide-react";

function useNow() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

const CITY_CATALOG = [
  { city: "Los Angeles", tz: "America/Los_Angeles", cc: "us" },
  { city: "New York", tz: "America/New_York", cc: "us" },
  { city: "São Paulo", tz: "America/Sao_Paulo", cc: "br" },
  { city: "London", tz: "Europe/London", cc: "gb" },
  { city: "Berlin", tz: "Europe/Berlin", cc: "de" },
  { city: "Moscow", tz: "Europe/Moscow", cc: "ru" },
  { city: "Dubai", tz: "Asia/Dubai", cc: "ae" },
  { city: "Mumbai", tz: "Asia/Kolkata", cc: "in" },
  { city: "Singapore", tz: "Asia/Singapore", cc: "sg" },
  { city: "Hong Kong", tz: "Asia/Hong_Kong", cc: "hk" },
  { city: "Tokyo", tz: "Asia/Tokyo", cc: "jp" },
  { city: "Sydney", tz: "Australia/Sydney", cc: "au" },
];
const DEFAULT_CITIES = ["Los Angeles", "New York", "London", "Dubai", "Mumbai", "Tokyo"];
const LS_KEY = "daxx_world_clocks";

function AnalogClock({ now }) {
  const s = now.getSeconds();
  const m = now.getMinutes();
  const h = now.getHours() % 12;
  const secA = s * 6;
  const minA = m * 6 + s / 10;
  const hourA = h * 30 + m * 0.5;
  const hand = (angle, len, w, color, key) => {
    const rad = ((angle - 90) * Math.PI) / 180;
    return <line key={key} x1="50" y1="50" x2={50 + len * Math.cos(rad)} y2={50 + len * Math.sin(rad)}
      stroke={color} strokeWidth={w} strokeLinecap="round" />;
  };
  return (
    <svg viewBox="0 0 100 100" className="w-28 h-28" data-testid="chrono-analog">
      <circle cx="50" cy="50" r="47" fill="#0a0a0a" stroke="#27272a" strokeWidth="1.5" />
      {Array.from({ length: 12 }).map((_, i) => {
        const a = ((i * 30 - 90) * Math.PI) / 180;
        const r1 = i % 3 === 0 ? 38 : 41;
        return <line key={i} x1={50 + r1 * Math.cos(a)} y1={50 + r1 * Math.sin(a)}
          x2={50 + 44 * Math.cos(a)} y2={50 + 44 * Math.sin(a)}
          stroke={i % 3 === 0 ? "#FACC15" : "#3f3f46"} strokeWidth={i % 3 === 0 ? 2 : 1} />;
      })}
      {hand(hourA, 24, 3, "#e4e4e7", "h")}
      {hand(minA, 34, 2, "#a1a1aa", "m")}
      {hand(secA, 38, 1, "#FACC15", "s")}
      <circle cx="50" cy="50" r="2.5" fill="#FACC15" />
    </svg>
  );
}

function MiniCalendar({ now }) {
  const year = now.getFullYear();
  const month = now.getMonth();
  const today = now.getDate();
  const first = new Date(year, month, 1).getDay();
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const cells = [];
  for (let i = 0; i < first; i++) cells.push(null);
  for (let d = 1; d <= daysInMonth; d++) cells.push(d);
  const monthName = now.toLocaleDateString("en-US", { month: "long", year: "numeric" });
  return (
    <div data-testid="mini-calendar">
      <p className="font-mono text-xs text-primary mb-2">{monthName}</p>
      <div className="grid grid-cols-7 gap-0.5 text-center">
        {["S", "M", "T", "W", "T", "F", "S"].map((d, i) => (
          <span key={i} className="data-label text-[9px] text-zinc-600 pb-1">{d}</span>
        ))}
        {cells.map((d, i) => (
          <span key={i} className={`font-mono text-[10px] py-1 rounded-sm ${
            d === today ? "bg-primary text-black font-bold" : d ? "text-zinc-400 hover:bg-white/5" : "text-transparent"
          }`}>{d || "."}</span>
        ))}
      </div>
    </div>
  );
}

function WorldClocks({ now }) {
  const [cities, setCities] = useState(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(LS_KEY));
      if (Array.isArray(saved) && saved.length) return saved;
    } catch { /* ignore */ }
    return DEFAULT_CITIES;
  });
  const [adding, setAdding] = useState(false);
  useEffect(() => { try { localStorage.setItem(LS_KEY, JSON.stringify(cities)); } catch { /* ignore */ } }, [cities]);

  const active = cities.map((name) => CITY_CATALOG.find((c) => c.city === name)).filter(Boolean);
  const available = CITY_CATALOG.filter((c) => !cities.includes(c.city));
  const add = (city) => { setCities((c) => [...c, city]); setAdding(false); };
  const remove = (city) => setCities((c) => c.filter((x) => x !== city));

  return (
    <div data-testid="world-clocks">
      <div className="flex items-center gap-2 mb-4">
        <Globe2 className="w-4 h-4 text-primary" /><span className="data-label">World Clocks</span>
        <div className="ml-auto relative">
          <button onClick={() => setAdding((a) => !a)} disabled={!available.length} data-testid="world-add-btn"
            className="border border-border p-1 text-zinc-400 hover:text-primary hover:border-primary/50 transition-colors disabled:opacity-30"><Plus className="w-3.5 h-3.5" /></button>
          {adding && available.length > 0 && (
            <div className="absolute right-0 top-8 z-30 w-44 bg-[#121212] border border-border max-h-52 overflow-y-auto shadow-2xl" data-testid="world-add-menu">
              {available.map((c) => (
                <button key={c.city} onClick={() => add(c.city)} data-testid={`world-add-${c.cc}`}
                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-zinc-300 hover:bg-primary/10 hover:text-white transition-colors">
                  <img src={`https://flagcdn.com/w20/${c.cc}.png`} alt="" className="w-4 h-auto border border-border" /> {c.city}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
      <div className="space-y-2">
        {active.map((w) => {
          const t = now.toLocaleTimeString("en-GB", { hour12: false, timeZone: w.tz });
          const d = now.toLocaleDateString("en-US", { weekday: "short", timeZone: w.tz });
          return (
            <div key={w.city} className="group flex items-center justify-between gap-2 border-b border-border/40 pb-1.5" data-testid={`world-row-${w.cc}`}>
              <div className="flex items-center gap-2 min-w-0">
                <img src={`https://flagcdn.com/w20/${w.cc}.png`} alt="" className="w-4 h-auto border border-border shrink-0" />
                <span className="text-xs text-zinc-300 truncate">{w.city}</span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className="font-mono text-sm text-white tabular-nums">{t}</span>
                <span className="font-mono text-[9px] text-zinc-600 w-7">{d}</span>
                <button onClick={() => remove(w.city)} data-testid={`world-remove-${w.cc}`} className="opacity-0 group-hover:opacity-100 text-zinc-600 hover:text-severity-critical transition-opacity"><X className="w-3 h-3" /></button>
              </div>
            </div>
          );
        })}
        {active.length === 0 && <p className="text-xs text-zinc-600">No cities — add one with the + button</p>}
      </div>
    </div>
  );
}

export function ChronoDeck() {
  const now = useNow();
  const timeStr = now.toLocaleTimeString("en-GB", { hour12: false });
  const dateStr = now.toLocaleDateString("en-US", { weekday: "long", month: "short", day: "numeric" });
  const utc = now.toISOString().slice(11, 19);
  const dayOfYear = Math.floor((now - new Date(now.getFullYear(), 0, 0)) / 86400000);
  const weekNo = Math.ceil(dayOfYear / 7);
  const yearProgress = Math.round((dayOfYear / 365) * 100);
  const isDay = now.getHours() >= 6 && now.getHours() < 18;

  return (
    <div className="relative border border-border bg-[#0c0c0c] overflow-hidden" data-testid="chrono-deck">
      <div className="absolute inset-0 pointer-events-none" style={{ backgroundImage: "linear-gradient(rgba(250,204,21,0.03) 1px, transparent 1px)", backgroundSize: "100% 3px" }} />
      <div className="relative grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-border">
        {/* Chronometer */}
        <div className="lg:col-span-5 p-6" data-testid="chrono-panel">
          <div className="flex items-center gap-2 mb-4">
            <Timer className="w-4 h-4 text-primary" />
            <span className="data-label !text-primary">System Chronometer</span>
            {isDay ? <Sun className="w-3.5 h-3.5 text-primary ml-auto" /> : <Moon className="w-3.5 h-3.5 text-zinc-500 ml-auto" />}
          </div>
          <div className="flex items-center gap-5">
            <AnalogClock now={now} />
            <div className="min-w-0">
              <div className="flex items-baseline gap-2">
                <Clock className="w-4 h-4 text-zinc-500 shrink-0" />
                <span className="font-mono text-3xl md:text-4xl font-bold text-white tabular-nums leading-none" data-testid="chrono-digital">{timeStr}</span>
              </div>
              <p className="text-sm text-zinc-400 mt-2">{dateStr}</p>
              <p className="font-mono text-[11px] text-zinc-500 mt-1">UTC {utc}</p>
              <div className="flex gap-2 mt-2">
                <span className="font-mono text-[10px] border border-border bg-[#0a0a0a] px-1.5 py-0.5 text-zinc-400">DAY {dayOfYear}/365</span>
                <span className="font-mono text-[10px] border border-border bg-[#0a0a0a] px-1.5 py-0.5 text-zinc-400">WK {weekNo}</span>
              </div>
            </div>
          </div>
          <div className="mt-4">
            <div className="flex justify-between data-label mb-1"><span>Year progress</span><span className="text-primary">{yearProgress}%</span></div>
            <div className="h-1.5 bg-[#0a0a0a] border border-border overflow-hidden">
              <div className="h-full bg-primary transition-all duration-1000" style={{ width: `${yearProgress}%` }} />
            </div>
          </div>
        </div>

        {/* World clocks */}
        <div className="lg:col-span-4 p-6">
          <WorldClocks now={now} />
        </div>

        {/* Calendar */}
        <div className="lg:col-span-3 p-6" data-testid="calendar-panel">
          <div className="flex items-center gap-2 mb-4"><CalendarDays className="w-4 h-4 text-primary" /><span className="data-label">Mission Calendar</span></div>
          <MiniCalendar now={now} />
        </div>
      </div>
    </div>
  );
}
