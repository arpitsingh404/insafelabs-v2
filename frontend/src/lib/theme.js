// Accent theme presets. The app's Tailwind tokens use `hsl(var(--primary))`, so
// switching --primary / --ring recolours buttons, links, nav-active and accents.
export const ACCENTS = [
  { id: "amber", label: "Amber", hsl: "48 96% 53%" },
  { id: "emerald", label: "Emerald", hsl: "152 76% 44%" },
  { id: "cyan", label: "Cyan", hsl: "189 94% 43%" },
  { id: "crimson", label: "Crimson", hsl: "0 84% 60%" },
  { id: "violet", label: "Violet", hsl: "262 83% 58%" },
];

const KEY = "insafe_accent";

export function getAccent() {
  const id = localStorage.getItem(KEY) || "amber";
  return ACCENTS.find((a) => a.id === id) || ACCENTS[0];
}

export function applyAccent(id) {
  const a = ACCENTS.find((x) => x.id === id) || ACCENTS[0];
  const root = document.documentElement;
  root.style.setProperty("--primary", a.hsl);
  root.style.setProperty("--ring", a.hsl);
  root.dataset.accent = a.id;
  try { localStorage.setItem(KEY, a.id); } catch { /* ignore */ }
  return a;
}
