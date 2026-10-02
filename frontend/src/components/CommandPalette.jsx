import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search, CornerDownLeft } from "lucide-react";

// Quick module jump (Ctrl/⌘ + K). Filters the console nav and navigates on Enter/click.
export function CommandPalette({ items, open, setOpen }) {
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const inputRef = useRef(null);
  const navigate = useNavigate();

  const filtered = useMemo(() => {
    const t = q.trim().toLowerCase();
    return t ? items.filter((i) => i.label.toLowerCase().includes(t)) : items;
  }, [q, items]);

  useEffect(() => {
    if (open) { setQ(""); setIdx(0); setTimeout(() => inputRef.current?.focus(), 0); }
  }, [open]);

  if (!open) return null;

  const go = (item) => { if (!item) return; setOpen(false); navigate(item.to); };

  return (
    <div className="fixed inset-0 z-[9998] bg-black/60 backdrop-blur-sm flex items-start justify-center pt-[12vh] px-4"
      onClick={() => setOpen(false)} data-testid="command-palette" role="dialog" aria-modal="true">
      <div className="w-full max-w-lg border border-border bg-[#0c0c0c] shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 px-4 h-12 border-b border-border">
          <Search className="w-4 h-4 text-primary" />
          <input ref={inputRef} value={q}
            onChange={(e) => { setQ(e.target.value); setIdx(0); }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(i + 1, filtered.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(i - 1, 0)); }
              else if (e.key === "Enter") { e.preventDefault(); go(filtered[idx]); }
              else if (e.key === "Escape") { setOpen(false); }
            }}
            placeholder="Jump to a module…" data-testid="command-palette-input" aria-label="Command palette search"
            className="flex-1 bg-transparent text-white text-sm font-mono outline-none placeholder:text-zinc-600" />
          <kbd className="text-[10px] text-zinc-600 border border-border px-1.5 py-0.5 font-mono">esc</kbd>
        </div>
        <div className="max-h-80 overflow-y-auto py-1" data-testid="command-palette-list">
          {filtered.length === 0 ? (
            <p className="px-4 py-6 text-sm text-zinc-600 text-center">No matching module.</p>
          ) : filtered.map((it, i) => (
            <button key={it.id} onClick={() => go(it)} onMouseEnter={() => setIdx(i)} data-testid={`palette-${it.id}`}
              className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm text-left transition-colors ${i === idx ? "bg-primary/10 text-white" : "text-zinc-400 hover:bg-white/[0.03]"}`}>
              <it.icon className="w-4 h-4 text-primary shrink-0" />
              <span className="flex-1">{it.label}</span>
              {i === idx && <CornerDownLeft className="w-3.5 h-3.5 text-zinc-600" />}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
