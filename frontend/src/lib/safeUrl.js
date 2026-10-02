// Security helpers — keep untrusted/target-derived values out of dangerous sinks.

/**
 * Return the URL only when it is a safe http(s) URL (or a same-origin path).
 * Blocks javascript:, data:, vbscript:, file:, blob: and similar.
 * Use for any href / img src / window.open target built from scan output.
 */
export function safeHttpUrl(u) {
  if (typeof u !== "string") return null;
  const s = u.trim();
  if (!s) return null;
  // same-origin relative path (but not protocol-relative //evil.com)
  if (/^\/(?!\/)/.test(s) || /^\.\.?\//.test(s)) return s;
  try {
    const url = new URL(s, window.location.origin);
    if (url.protocol === "http:" || url.protocol === "https:") return s;
  } catch { /* not a URL */ }
  return null;
}

/** Escape a string for safe interpolation into HTML (Leaflet tooltips, etc.). */
export function escapeHtml(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

/** Escape an HTML attribute value. */
export function attr(v) {
  return escapeHtml(v);
}
