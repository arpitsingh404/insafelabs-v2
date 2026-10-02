import { useState } from "react";
import { Palette } from "lucide-react";
import { ACCENTS, applyAccent, getAccent } from "@/lib/theme";

export function AccentSwitcher() {
  const [open, setOpen] = useState(false);
  const [cur, setCur] = useState(() => getAccent().id);
  const pick = (id) => { applyAccent(id); setCur(id); setOpen(false); };

  return (
    <div className="relative">
      <button onClick={() => setOpen((o) => !o)} data-testid="accent-switcher" title="Accent theme"
        className="inline-flex items-center gap-1.5 border border-border px-2.5 py-1 text-[11px] font-mono text-zinc-400 hover:text-primary hover:border-primary/50 transition-colors">
        <Palette className="w-3.5 h-3.5 text-primary" /> <span className="hidden md:inline">theme</span>
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-[60]" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-9 z-[61] w-44 border border-border bg-[#0c0c0c] shadow-2xl p-2" data-testid="accent-menu">
            {ACCENTS.map((a) => (
              <button key={a.id} onClick={() => pick(a.id)} data-testid={`accent-${a.id}`}
                className={`w-full flex items-center gap-2 px-2 py-1.5 text-xs font-mono transition-colors ${cur === a.id ? "text-white bg-white/5" : "text-zinc-400 hover:bg-white/[0.03]"}`}>
                <span className="w-3 h-3 border border-border" style={{ background: `hsl(${a.hsl})` }} />
                {a.label}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
