// Ollama browser-direct client. App runs in the user's browser, so it can reach
// the user's local Ollama (http://localhost:11434) just like the WebUSB bridge.
const LS_URL = "insafelabs_ollama_url";
const DEFAULT_URL = "http://localhost:11434";

export function getOllamaUrl() {
  const raw = (localStorage.getItem(LS_URL) || DEFAULT_URL).replace(/\/+$/, "");
  return sanitizeOllamaUrl(raw) || DEFAULT_URL;
}

export function setOllamaUrl(url) {
  const clean = sanitizeOllamaUrl((url || "").trim());
  localStorage.setItem(LS_URL, clean || DEFAULT_URL);
}

// Only http(s); non-private hosts must use https so chat data isn't sent in cleartext
// to an arbitrary server if the stored value is tampered with.
function sanitizeOllamaUrl(u) {
  try {
    const url = new URL(u);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    const host = url.hostname.toLowerCase();
    const isPrivate = host === "localhost" || host === "127.0.0.1" || host === "::1"
      || host.endsWith(".local") || host.endsWith(".internal")
      || /^10\./.test(host) || /^192\.168\./.test(host)
      || /^172\.(1[6-9]|2\d|3[01])\./.test(host);
    if (!isPrivate && url.protocol !== "https:") return null;
    return url.origin;
  } catch { return null; }
}

export async function listOllamaModels() {
  const res = await fetch(`${getOllamaUrl()}/api/tags`);
  if (!res.ok) throw new Error(`Ollama responded ${res.status}`);
  const data = await res.json();
  return (data.models || []).map((m) => m.name).filter(Boolean);
}

// Streams a chat completion (NDJSON). Calls onDelta(text) per token chunk.
// Returns the full assembled response text.
export async function streamOllamaChat({ model, messages, signal, onDelta }) {
  const res = await fetch(`${getOllamaUrl()}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model, messages, stream: true }),
    signal,
  });
  if (!res.ok || !res.body) throw new Error(`Ollama responded ${res.status}`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let full = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop();
    for (const line of lines) {
      const l = line.trim();
      if (!l) continue;
      let obj;
      try { obj = JSON.parse(l); } catch { continue; }
      const delta = obj?.message?.content || "";
      if (delta) { full += delta; onDelta?.(delta); }
      if (obj.done) return full;
    }
  }
  return full;
}
