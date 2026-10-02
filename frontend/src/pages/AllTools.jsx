import { useState, useMemo } from "react";
import { api, formatApiError } from "@/lib/api";
import { toast } from "sonner";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  Wrench, Globe, ShieldCheck, Calculator, Activity, Cloud, ServerCog, Braces,
  FileSearch, Code2, Layers, ArrowRightLeft, Search, Play, Loader2, Copy,
} from "lucide-react";

const inputCls = "w-full bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary transition-colors";
const areaCls = inputCls + " min-h-[160px] resize-y";
const btnCls = "bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60";

/* ============================================================================
 * Pure (client-side) helpers
 * ==========================================================================*/
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64e = (s) => btoa(String.fromCharCode(...enc.encode(s)));
const b64d = (s) => dec.decode(Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0)));
const b64urlDecode = (s) => dec.decode(Uint8Array.from(atob((s || "").replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), (c) => c.charCodeAt(0)));

const fmtJson = (s, i = 2) => JSON.stringify(JSON.parse(s), null, i);
const minJson = (s) => JSON.stringify(JSON.parse(s));

const scalar = (v) => {
  if (v === null || v === undefined) return "null";
  if (typeof v === "string") return /[:#\-{}[\],&*?|<>=!%@`"']/.test(v) || v === "" ? JSON.stringify(v) : v;
  return String(v);
};
function jsonToYaml(obj, ind = 0) {
  const pad = "  ".repeat(ind);
  if (obj === null || obj === undefined) return "null";
  if (Array.isArray(obj)) {
    if (!obj.length) return "[]";
    return obj.map((v) => (typeof v === "object" && v !== null ? pad + "-\n" + jsonToYaml(v, ind + 1) : pad + "- " + scalar(v))).join("\n");
  }
  if (typeof obj === "object") {
    const e = Object.entries(obj);
    if (!e.length) return "{}";
    return e.map(([k, v]) => (typeof v === "object" && v !== null ? pad + k + ":\n" + jsonToYaml(v, ind + 1) : pad + k + ": " + scalar(v))).join("\n");
  }
  return pad + scalar(obj);
}
function parseYamlScalar(v) {
  const t = v.trim();
  if (t === "" || t === "null" || t === "~") return null;
  if (t === "true") return true;
  if (t === "false") return false;
  if (/^-?\d+$/.test(t)) return parseInt(t, 10);
  if (/^-?\d+\.\d+$/.test(t)) return parseFloat(t);
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) return t.slice(1, -1);
  if (t.startsWith("[") || t.startsWith("{")) { try { return JSON.parse(t); } catch (e) { return t; } }
  return t;
}
function yamlToObj(text) {
  const raw = text.split(/\r?\n/);
  const lines = [];
  for (const l of raw) { if (!l.trim() || /^\s*#/.test(l)) continue; lines.push({ ind: l.match(/^\s*/)[0].length, txt: l.trim() }); }
  let pos = 0;
  function map(indent) {
    const obj = {};
    while (pos < lines.length) {
      const l = lines[pos];
      if (l.ind < indent) break;
      if (l.ind > indent) { pos++; continue; }
      const m = l.txt.match(/^([^:]+):\s*(.*)$/);
      if (!m) { pos++; continue; }
      const key = m[1].trim(); const rest = m[2]; pos++;
      if (rest === "") { obj[key] = pos < lines.length && lines[pos].ind > indent ? (lines[pos].txt.startsWith("-") ? list(lines[pos].ind) : map(lines[pos].ind)) : null; }
      else obj[key] = parseYamlScalar(rest);
    }
    return obj;
  }
  function list(indent) {
    const arr = [];
    while (pos < lines.length) {
      const l = lines[pos];
      if (l.ind < indent) break;
      if (l.ind > indent) { pos++; continue; }
      if (!l.txt.startsWith("-")) break;
      const rest = l.txt.slice(1).trim(); pos++;
      if (rest === "") { arr.push(pos < lines.length && lines[pos].ind > indent ? map(lines[pos].ind) : null); }
      else if (/^[^:]+:/.test(rest)) {
        const mm = rest.match(/^([^:]+):\s*(.*)$/);
        const o = {}; const k = mm[1].trim(); const v = mm[2];
        o[k] = v === "" ? (pos < lines.length && lines[pos].ind > indent ? map(lines[pos].ind) : null) : parseYamlScalar(v);
        while (pos < lines.length && lines[pos].ind > indent && !lines[pos].txt.startsWith("-")) {
          const l2 = lines[pos]; const m2 = l2.txt.match(/^([^:]+):\s*(.*)$/); if (!m2) break; pos++;
          o[m2[1].trim()] = m2[2] === "" ? (pos < lines.length && lines[pos].ind > l2.ind ? map(lines[pos].ind) : null) : parseYamlScalar(m2[2]);
        }
        arr.push(o);
      } else arr.push(parseYamlScalar(rest));
    }
    return arr;
  }
  return lines.length ? (lines[0].txt.startsWith("-") ? list(lines[0].ind) : map(lines[0].ind)) : null;
}
const yamlToJson = (s) => JSON.stringify(yamlToObj(s), null, 2);
const jsonToYamlStr = (s) => jsonToYaml(JSON.parse(s));

/* ---- CSV ---- */
function parseCsv(text, delim = ",") {
  const rows = []; let row = []; let cur = ""; let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === delim) { row.push(cur); cur = ""; }
    else if (c === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; }
    else if (c !== "\r") cur += c;
  }
  if (cur !== "" || row.length) { row.push(cur); rows.push(row); }
  return rows.filter((r) => r.some((c) => c !== ""));
}
const csvToJson = (s, d = ",") => { const rows = parseCsv(s, d); const [h, ...r] = rows; return JSON.stringify(r.map((row) => Object.fromEntries(h.map((k, i) => [k, row[i] ?? ""]))), null, 2); };
const csvToYaml = (s, d = ",") => jsonToYaml(JSON.parse(csvToJson(s, d)));
const csvToXml = (s, d = ",") => jsonToXml(JSON.parse(csvToJson(s, d)));
const csvToSql = (s, d = ",") => {
  const rows = parseCsv(s, d); const [h, ...r] = rows;
  return r.map((row) => `INSERT INTO table_name (${h.join(", ")}) VALUES (${row.map((v) => (v === "" || /^-?\d+(\.\d+)?$/.test(v) ? (v === "" ? "NULL" : v) : `'${String(v).replace(/'/g, "''")}'`)).join(", ")});`).join("\n");
};

/* ---- JSON <-> XML ---- */
function jsonToXml(obj, root = "root") {
  const esc = (v) => String(v == null ? "" : v).replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c]));
  const build = (key, val) => {
    if (Array.isArray(val)) return val.map((v) => build(key, v)).join("");
    if (val && typeof val === "object") return `<${key}>${Object.entries(val).map(([k, v]) => build(k, v)).join("")}</${key}>`;
    return `<${key}>${esc(val)}</${key}>`;
  };
  return `<?xml version="1.0" encoding="UTF-8"?>\n` + build(root, obj);
}
function xmlNodeToJson(node) {
  const children = [...node.children];
  if (!children.length) return node.textContent.trim();
  const obj = {};
  for (const c of children) {
    const v = xmlNodeToJson(c);
    if (obj[c.tagName] === undefined) obj[c.tagName] = v;
    else if (Array.isArray(obj[c.tagName])) obj[c.tagName].push(v);
    else obj[c.tagName] = [obj[c.tagName], v];
  }
  return obj;
}
function parseXml(s) {
  const d = new DOMParser().parseFromString(s, "application/xml");
  if (d.querySelector("parsererror")) throw new Error("Invalid XML");
  return d;
}
const xmlToJson = (s) => JSON.stringify(xmlNodeToJson(parseXml(s).documentElement), null, 2);
const xmlToYaml = (s) => jsonToYaml(JSON.parse(xmlToJson(s)));
function fmtXml(s) {
  const d = parseXml(s);
  const ser = new XMLSerializer();
  let xml = ser.serializeToString(d);
  xml = xml.replace(/></g, ">\n<");
  let depth = 0;
  return xml.split("\n").map((line) => {
    if (/^<\/.+/.test(line)) depth = Math.max(0, depth - 1);
    const out = "  ".repeat(depth) + line;
    if (/^<[^!?/].*[^/]>$/.test(line) && !/<\/.+>$/.test(line)) depth++;
    return out;
  }).join("\n");
}
function jsonToXsd(json) {
  const obj = JSON.parse(json);
  const infer = (v) => (typeof v === "number" ? (Number.isInteger(v) ? "xs:integer" : "xs:decimal") : typeof v === "boolean" ? "xs:boolean" : "xs:string");
  const elements = Object.entries(obj).map(([k, v]) => `      <xs:element name="${k}" type="${infer(Array.isArray(v) ? v[0] : v)}" minOccurs="0"/>`).join("\n");
  return `<?xml version="1.0"?>\n<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">\n  <xs:element name="root">\n    <xs:complexType>\n      <xs:sequence>\n${elements}\n      </xs:sequence>\n    </xs:complexType>\n  </xs:element>\n</xs:schema>`;
}

/* ---- INI ---- */
function iniToJson(s) {
  const out = {}; let cur = out;
  for (const line of s.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith(";") || t.startsWith("#")) continue;
    const sec = t.match(/^\[(.+)\]$/);
    if (sec) { out[sec[1]] = out[sec[1]] || {}; cur = out[sec[1]]; continue; }
    const kv = t.match(/^([^=]+)=(.*)$/);
    if (kv) cur[kv[1].trim()] = kv[2].trim();
  }
  return JSON.stringify(out, null, 2);
}
const iniToXml = (s) => jsonToXml(JSON.parse(iniToJson(s)));
const iniToYaml = (s) => jsonToYaml(JSON.parse(iniToJson(s)));

/* ---- SQL ---- */
function fmtSql(s) {
  const kw = ["SELECT", "FROM", "WHERE", "AND", "OR", "JOIN", "LEFT JOIN", "RIGHT JOIN", "INNER JOIN", "ON", "GROUP BY", "ORDER BY", "HAVING", "LIMIT", "INSERT INTO", "VALUES", "UPDATE", "SET", "DELETE FROM", "CREATE TABLE", "UNION"];
  let out = s.replace(/\s+/g, " ").trim();
  kw.forEach((k) => { out = out.replace(new RegExp(`\\b${k.replace(/ /g, "\\s+")}\\b`, "gi"), "\n" + k); });
  return out.trim();
}
function sqlToMongo(s) {
  const m = s.match(/select\s+(.+?)\s+from\s+(\w+)(?:\s+where\s+(.+?))?(?:\s+limit\s+(\d+))?;?\s*$/i);
  if (!m) throw new Error("Only simple SELECT ... FROM ... [WHERE ...] [LIMIT n] is supported");
  const fields = m[1].trim() === "*" ? null : Object.fromEntries(m[1].split(",").map((f) => [f.trim(), 1]));
  const filter = {};
  if (m[3]) {
    for (const cond of m[3].split(/\s+and\s+/i)) {
      const c = cond.match(/^(\w+)\s*(=|!=|<>|>|<|>=|<=)\s*(.+)$/);
      if (!c) continue;
      const val = /^'.*'$/.test(c[3]) ? c[3].slice(1, -1) : (isNaN(Number(c[3])) ? c[3] : Number(c[3]));
      filter[c[1]] = { "=": val, "!=": { $ne: val }, "<>": { $ne: val }, ">": { $gt: val }, "<": { $lt: val }, ">=": { $gte: val }, "<=": { $lte: val } }[c[2]];
    }
  }
  const args = [JSON.stringify(filter)];
  if (fields) args.push(JSON.stringify(fields));
  let q = `db.${m[2]}.find(${args.join(", ")})`;
  if (m[4]) q += `.limit(${m[4]})`;
  return q;
}

/* ---- JS / CSS / HTML minify & beautify (heuristic) ---- */
const jsMinify = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1").replace(/\n{2,}/g, "\n").replace(/^\s+|\s+$/gm, "").trim();
const cssMinify = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\s*([{}:;,>])\s*/g, "$1").replace(/;}/g, "}").replace(/\s+/g, " ").trim();
function jsBeautify(s) {
  let out = s.replace(/\s*\{\s*/g, " {\n").replace(/;\s*/g, ";\n").replace(/\}\s*/g, "}\n");
  let depth = 0;
  return out.split("\n").map((l) => {
    const t = l.trim(); if (!t) return null;
    if (t.startsWith("}")) depth = Math.max(0, depth - 1);
    const line = "  ".repeat(depth) + t;
    if (t.endsWith("{")) depth++;
    return line;
  }).filter(Boolean).join("\n");
}
const cssBeautify = (s) => s.replace(/\s*\{\s*/g, " {\n").replace(/;\s*/g, ";\n").replace(/\s*\}\s*/g, "\n}\n").trim();
function htmlBeautify(s) {
  const xml = s.replace(/<(?!\/?(?:br|img|input|hr|meta|link)\b)([^>]+)>/g, "\n<$1>").replace(/>\s+</g, ">\n<");
  let depth = 0;
  return xml.split("\n").map((l) => {
    const t = l.trim(); if (!t) return null;
    if (/^<\//.test(t)) depth = Math.max(0, depth - 1);
    const line = "  ".repeat(depth) + t;
    if (/^<[^/!][^>]*[^/]>$/.test(t) && !/^<(br|img|input|hr|meta|link)\b/i.test(t)) depth++;
    return line;
  }).filter(Boolean).join("\n");
}
const codeCleaner = (s) => s.replace(/<!--[\s\S]*?-->/g, "").replace(/\s{2,}/g, " ").replace(/\n{2,}/g, "\n").trim();
const lynxView = (s) => {
  const d = new DOMParser().parseFromString(s, "text/html");
  d.querySelectorAll("script,style,noscript").forEach((n) => n.remove());
  let text = d.body ? d.body.innerText || d.body.textContent : s;
  return (text || "").replace(/\n{3,}/g, "\n\n").trim();
};

/* ---- encoders ---- */
const urlEnc = (s) => encodeURIComponent(s);
const urlDec = (s) => decodeURIComponent(s);
const htmlEnc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const htmlDec = (s) => { const d = new DOMParser().parseFromString(s, "text/html"); return d.documentElement.textContent; };
const jsEsc = (s) => JSON.stringify(s).slice(1, -1);
const jsUnesc = (s) => JSON.parse('"' + s + '"');
const xmlEsc = htmlEnc;
const xmlUnesc = htmlDec;

/* ---- validators ---- */
const validateYaml = (s) => { yamlToObj(s); return "✅ Valid YAML (parsed successfully)"; };
const validateJs = (s) => { /* eslint-disable-next-line no-new-func */ new Function(s); return "✅ No syntax errors detected"; };
const validateHtml = (s) => {
  const d = new DOMParser().parseFromString(s, "text/html");
  const errs = [...d.querySelectorAll("parsererror")].map((e) => e.textContent);
  const stack = [];
  const re = /<\/?([a-zA-Z][\w-]*)[^>]*?(\/?)>/g; let m;
  const voidTags = new Set(["br", "img", "input", "hr", "meta", "link", "area", "base", "col", "embed", "source", "track", "wbr"]);
  while ((m = re.exec(s))) {
    const tag = m[1].toLowerCase();
    if (voidTags.has(tag) || m[2] === "/") continue;
    if (m[0][1] === "/") { if (stack.pop() !== tag) errs.push(`Unexpected closing </${tag}>`); }
    else stack.push(tag);
  }
  if (stack.length) errs.push("Unclosed tags: " + stack.join(", "));
  return errs.length ? "❌ Issues:\n" + errs.slice(0, 40).join("\n") : "✅ No obvious HTML issues found";
};

/* ---- JSONPath (subset) & XPath ---- */
function jsonPathEval(json, path) {
  let data = JSON.parse(json);
  const clean = path.replace(/^\$/, "").replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean);
  for (const k of clean) {
    if (data == null) return null;
    if (Array.isArray(data) && /^\d+$/.test(k)) data = data[Number(k)];
    else if (k === "*") return data;
    else data = data[k];
  }
  return data;
}
const jsonPathFinder = (json) => { const paths = []; const walk = (o, p) => { if (Array.isArray(o)) o.forEach((v, i) => walk(v, `${p}[${i}]`)); else if (o && typeof o === "object") Object.entries(o).forEach(([k, v]) => walk(v, `${p}.${k}`)); else paths.push(`${p} = ${JSON.stringify(o)}`); }; walk(JSON.parse(json), "$"); return paths.join("\n"); };
function xpathEval(xml, expr) {
  const d = parseXml(xml);
  const it = d.evaluate(expr, d, null, XPathResult.ANY_TYPE, null);
  const out = []; let n = it.iterateNext();
  while (n && out.length < 200) { out.push(n.textContent ?? n.nodeValue ?? String(n)); n = it.iterateNext(); }
  return out.length ? out.join("\n") : "(no matches)";
}

/* ---- misc ---- */
const urlSplit = (s) => { const u = new URL(s.includes("://") ? s : "https://" + s); return JSON.stringify({ protocol: u.protocol, username: u.username, password: u.password, hostname: u.hostname, port: u.port, pathname: u.pathname, search: u.search, hash: u.hash, params: Object.fromEntries(u.searchParams.entries()), origin: u.origin }, null, 2); };
const jwtDecode = (s) => { const [h, p] = s.trim().split("."); return "HEADER:\n" + JSON.stringify(JSON.parse(b64urlDecode(h)), null, 2) + "\n\nPAYLOAD:\n" + JSON.stringify(JSON.parse(b64urlDecode(p)), null, 2); };
const idnConvert = (s) => { const u = new URL("http://" + s.trim()); return `Unicode: ${s}\nASCII/IDN (punycode): ${u.hostname}\nProtocol: ${u.protocol.replace(":", "")}\nPort: ${u.port || "default"}`; };
const ipv4ToIpv6 = (s) => s.trim().split(/\r?\n/).map((ip) => { const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/); return m ? `::ffff:${m[1]}.${m[2]}.${m[3]}.${m[4]}` : `# invalid: ${ip}`; }).join("\n");
function ipv6Compress(s) {
  return s.trim().split(/\r?\n/).map((addr) => {
    let a = addr.trim().toLowerCase();
    if (!a.includes(":")) return `# not ipv6: ${addr}`;
    const [head, tail] = a.split("::");
    const expand = (part) => part.split(":").map((g) => g.replace(/^0+/, "") || "0");
    let groups = a.includes("::") ? [...expand(head), ...Array(8 - expand(head).length - (tail ? expand(tail).length : 0)).fill("0"), ...(tail ? expand(tail) : [])] : expand(a);
    groups = groups.map((g) => g || "0");
    let best = -1, bestLen = 0, cur = -1, curLen = 0;
    groups.forEach((g, i) => { if (g === "0") { if (cur === -1) cur = i; curLen++; if (curLen > bestLen) { bestLen = curLen; best = cur; } } else { cur = -1; curLen = 0; } });
    if (bestLen < 2) return groups.join(":");
    return (groups.slice(0, best).join(":") + "::" + groups.slice(best + bestLen).join(":")).replace(/^:+/, "::");
  }).join("\n");
}
function subnetCalc(ip, cidr, v6) {
  const full = v6 ? ip + "/" + cidr : null;
  if (v6) {
    const base = ipaddress6Prefix(full); return base;
  }
  const parts = ip.split(".").map(Number); const prefix = Number(cidr);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255) || prefix < 0 || prefix > 32) throw new Error("Enter a valid IPv4 and prefix 0-32");
  const ipInt = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const net = (ipInt & mask) >>> 0; const bcast = (net | (~mask >>> 0)) >>> 0;
  const toIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  return `Network:     ${toIp(net)}/${prefix}\nNetmask:     ${toIp(mask)}\nBroadcast:   ${toIp(bcast)}\nFirst host:  ${toIp(net + 1)}\nLast host:   ${toIp(bcast - 1)}\nTotal hosts: ${Math.max(0, Math.pow(2, 32 - prefix) - 2)}\nWildcard:    ${toIp(~mask >>> 0)}`;
}
function ipaddress6Prefix(full) {
  const [addr] = full.split("/");
  const g = addr.split(":").filter(Boolean);
  return `IPv6 (as given): ${full}\nGroups: ${g.length} (full form has 8)`;
}

/* ---- diff ---- */
function diffText(a, b) {
  const A = a.split("\n"), B = b.split("\n");
  const dp = Array.from({ length: A.length + 1 }, () => new Array(B.length + 1).fill(0));
  for (let i = A.length - 1; i >= 0; i--) for (let j = B.length - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < A.length && j < B.length) { if (A[i] === B[j]) { out.push("  " + A[i]); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push("- " + A[i]); i++; } else { out.push("+ " + B[j]); j++; } }
  while (i < A.length) out.push("- " + A[i++]);
  while (j < B.length) out.push("+ " + B[j++]);
  return out.join("\n");
}

/* ---- thread dump ---- */
function threadDumpAnalysis(s) {
  const threads = [...s.matchAll(/"([^"]+)"[^\n]*\n([\s\S]*?)(?=\n"|\n*$)/g)];
  const deadlocks = /Found one Java-level deadlock|deadlock/i.test(s);
  const lines = [`Threads found: ${threads.length}`, `Deadlock detected: ${deadlocks ? "YES ⚠" : "no"}`];
  const blocked = threads.filter((t) => /BLOCKED/.test(t[0])).length;
  const waiting = threads.filter((t) => /WAITING|TIMED_WAITING/.test(t[0])).length;
  lines.push(`BLOCKED: ${blocked}`, `WAITING/TIMED_WAITING: ${waiting}`, `RUNNABLE: ${threads.filter((t) => /RUNNABLE/.test(t[0])).length}`);
  return lines.join("\n");
}
function threadMethodSummary(s) {
  const m = {};
  for (const line of s.split("\n")) {
    const x = line.match(/^\s*at\s+([\w.$]+)\(/);
    if (x) m[x[1]] = (m[x[1]] || 0) + 1;
  }
  return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 100).map(([k, v]) => `${String(v).padStart(4)}  ${k}`).join("\n") || "(no stack frames found)";
}
function threadStackLength(s) {
  const buckets = {};
  for (const blk of s.split(/\n\s*\n/)) {
    const depth = (blk.match(/^\s*at\s+/gm) || []).length;
    if (depth) { const b = Math.floor(depth / 10) * 10; buckets[b] = (buckets[b] || 0) + 1; }
  }
  return Object.entries(buckets).sort((a, b) => a[0] - b[0]).map(([k, v]) => `stack length ${k}-${Number(k) + 9}: ${v} thread(s)`).join("\n") || "(no stacks found)";
}

/* ---- ICS ---- */
function icsView(s) {
  const events = s.split("BEGIN:VEVENT").slice(1);
  return events.map((e, i) => {
    const get = (k) => (e.match(new RegExp(`${k}[^:]*:(.*)`)) || [])[1];
    return `Event ${i + 1}\n  Summary: ${get("SUMMARY") || ""}\n  Start:   ${get("DTSTART") || ""}\n  End:     ${get("DTEND") || ""}\n  Location:${get("LOCATION") || ""}\n  Organizer:${get("ORGANIZER") || ""}`;
  }).join("\n\n") || "(no VEVENT blocks found)";
}

/* ---- HAR ---- */
const harView = (s) => { const j = JSON.parse(s); const e = j.log?.entries || []; return e.map((x, i) => `${String(i + 1).padStart(3)} ${x.response?.status} ${x.request?.method} ${x.request?.url}`).join("\n") || "(no entries)"; };
const harSanitize = (s) => {
  const j = JSON.parse(s);
  const scrub = (h = []) => h.filter((x) => !/^(cookie|authorization|set-cookie|x-auth|proxy-authorization)$/i.test(x.name));
  (j.log?.entries || []).forEach((e) => { if (e.request) e.request.headers = scrub(e.request.headers); if (e.request) e.request.cookies = []; if (e.response) { e.response.headers = scrub(e.response.headers); e.response.cookies = []; } });
  return JSON.stringify(j, null, 2);
};

/* ---- generators / calculators ---- */
function genPassword(len, upper, lower, digits, symbols) {
  let set = ""; if (upper) set += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; if (lower) set += "abcdefghijklmnopqrstuvwxyz"; if (digits) set += "0123456789"; if (symbols) set += "!@#$%^&*()-_=+[]{};:,.?/";
  if (!set) return "Select at least one character set";
  const a = new Uint32Array(len); crypto.getRandomValues(a);
  return [...a].map((n) => set[n % set.length]).join("");
}
function cronExpr(min, hour, dom, month, dow) { return [min, hour, dom, month, dow].map((x) => (x === "" ? "*" : x)).join(" "); }
const slaDowntime = (pct) => { const frac = 100 - Number(pct); const per = { "Per day": 86400, "Per week": 604800, "Per month": 2592000, "Per year": 31536000 }; return Object.entries(per).map(([k, sec]) => `${k}: ${((frac / 100) * sec).toFixed(2)} s (${((frac / 100) * sec / 60).toFixed(2)} min)`).join("\n"); };
function dataUnitConverter(val, from, to) { const units = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4, Kb: 1000 / 8, Mb: 1e6 / 8, Gb: 1e9 / 8 }; const bytes = Number(val) * units[from]; return `${val} ${from} = ${(bytes / units[to]).toFixed(4)} ${to}`; }
function downloadTime(sizeMB, speedMbps) { const sec = (Number(sizeMB) * 8) / Number(speedMbps); return `Estimated time: ${sec.toFixed(2)} s (${(sec / 60).toFixed(2)} min) at ${speedMbps} Mbps for ${sizeMB} MB`; }
function bandwidthCalc(pageSizeKB, viewsPerMonth) { const gb = (Number(pageSizeKB) * Number(viewsPerMonth)) / (1024 * 1024); return `Monthly transfer: ${gb.toFixed(2)} GB\nYearly transfer:  ${(gb * 12).toFixed(2)} GB`; }
function errorBudget(slo, periodDays) { const allowed = (100 - Number(slo)) / 100 * Number(periodDays) * 86400; return `Allowed downtime: ${allowed.toFixed(1)} s (${(allowed / 60).toFixed(1)} min) over ${periodDays} days at ${slo}% SLO`; }
function browserFingerprint() {
  return JSON.stringify({
    userAgent: navigator.userAgent, platform: navigator.platform, language: navigator.language,
    languages: navigator.languages, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: `${screen.width}x${screen.height} @${window.devicePixelRatio}x`, colorDepth: screen.colorDepth,
    cores: navigator.hardwareConcurrency, memoryGB: navigator.deviceMemory, touch: "ontouchstart" in window,
    cookieEnabled: navigator.cookieEnabled, doNotTrack: navigator.doNotTrack,
  }, null, 2);
}
const textRatioClient = (s) => { const t = s.replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim(); return `HTML size: ${s.length} bytes\nText size: ${t.length} chars\nText ratio: ${(t.length / Math.max(s.length, 1) * 100).toFixed(2)}%\nWords: ${t.split(/\s+/).filter(Boolean).length}`; };

const avgColorFromImage = (dataUrl) => new Promise((resolve) => {
  const img = new Image();
  img.onload = () => {
    const c = document.createElement("canvas");
    c.width = img.width;
    c.height = img.height;
    const ctx = c.getContext("2d");
    ctx.drawImage(img, 0, 0);
    const d = ctx.getImageData(0, 0, c.width, c.height).data;
    let r = 0, g = 0, b = 0, n = 0;
    for (let i = 0; i < d.length; i += 40) { r += d[i]; g += d[i + 1]; b += d[i + 2]; n++; }
    r = Math.round(r / n); g = Math.round(g / n); b = Math.round(b / n);
    const hex = "#" + [r, g, b].map((x) => x.toString(16).padStart(2, "0")).join("");
    resolve("Average colour: rgb(" + r + ", " + g + ", " + b + ")  " + hex);
  };
  img.onerror = () => resolve("Could not load image");
  img.src = dataUrl;
});

/* ---- curl parser (safe: never shells out) ---- */
function tokenizeCurl(s) {
  const out = []; let cur = ""; let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === q) q = null; else cur += c; }
    else if (c === '"' || c === "'") q = c;
    else if (/\s/.test(c)) { if (cur) { out.push(cur); cur = ""; } }
    else cur += c;
  }
  if (cur) out.push(cur);
  return out;
}
function parseCurl(cmd) {
  const t = tokenizeCurl(String(cmd).replace(/^\s*curl\s+/i, "").replace(/\\\r?\n/g, " "));
  let method = "GET", url = ""; const headers = {}; let body = "";
  for (let i = 0; i < t.length; i++) {
    const a = t[i];
    if (a === "-X" || a === "--request") method = (t[++i] || "GET").toUpperCase();
    else if (a === "-H" || a === "--header") { const h = t[++i] || ""; const k = h.indexOf(":"); if (k > 0) headers[h.slice(0, k).trim()] = h.slice(k + 1).trim(); }
    else if (a === "-d" || a === "--data" || a === "--data-raw" || a === "--data-binary" || a === "--data-urlencode") { body = t[++i] || ""; if (method === "GET") method = "POST"; }
    else if (a === "-I" || a === "--head") method = "HEAD";
    else if (a === "-u" || a === "--user") headers["Authorization"] = "Basic " + btoa(t[++i] || "");
    else if (a === "-b" || a === "--cookie") headers["Cookie"] = t[++i] || "";
    else if (a === "-A" || a === "--user-agent") headers["User-Agent"] = t[++i] || "";
    else if (a.startsWith("-")) { if (t[i + 1] && !t[i + 1].startsWith("-") && !/^https?:/i.test(t[i + 1]) && !url) i++; }
    else if (!url) url = a;
  }
  return { method, url, headers, body };
}

/* ---- cloud architecture diagram (DSL -> SVG) ---- */
function cloudDiagram(spec) {
  const nodes = {}; const edges = []; const layers = [];
  String(spec).split(/\r?\n/).forEach((line) => {
    const l = line.trim();
    if (!l || l.startsWith("#")) return;
    const edge = l.match(/^(.+?)\s*->\s*(.+)$/);
    if (edge) { edges.push([edge[1].trim(), edge[2].trim()]); return; }
    const m = l.match(/^([^:]+):\s*(.+)$/);
    const name = (m ? m[1] : l).trim();
    const layer = (m ? m[2] : "default").trim();
    nodes[name] = { name, layer };
    if (!layers.includes(layer)) layers.push(layer);
  });
  const colW = 200, rowH = 74, pad = 30, boxW = 150, boxH = 44;
  const layerY = {};
  layers.forEach((ly) => { layerY[ly] = pad + 8; });
  const pos = {};
  Object.values(nodes).forEach((n) => {
    const x = pad + layers.indexOf(n.layer) * colW;
    const y = layerY[n.layer];
    pos[n.name] = { x, y, cx: x + boxW / 2, cy: y + boxH / 2 };
    layerY[n.layer] += rowH;
  });
  const width = pad * 2 + Math.max(1, layers.length) * colW;
  const height = Math.max(120, ...layers.map((ly) => layerY[ly])) + pad;
  const esc = (t) => String(t).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
  const p = [];
  p.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="monospace">`);
  p.push(`<rect width="${width}" height="${height}" fill="#0a0a0a"/>`);
  layers.forEach((ly, i) => p.push(`<text x="${pad + i * colW}" y="20" fill="#eab308" font-size="12">${esc(ly)}</text>`));
  edges.forEach(([a, b]) => { if (pos[a] && pos[b]) p.push(`<line x1="${pos[a].cx}" y1="${pos[a].cy}" x2="${pos[b].cx}" y2="${pos[b].cy}" stroke="#52525b" stroke-width="1.5"/>`); });
  Object.values(nodes).forEach((n) => { const q = pos[n.name]; p.push(`<rect x="${q.x}" y="${q.y}" width="${boxW}" height="${boxH}" rx="4" fill="#18181b" stroke="#eab308"/>`); p.push(`<text x="${q.cx}" y="${q.cy + 4}" fill="#fafafa" font-size="12" text-anchor="middle">${esc(n.name)}</text>`); });
  p.push("</svg>");
  return p.join("");
}

/* ---- JSON code generators ---- */
function jsonToClass(json, lang) {
  const obj = JSON.parse(json);
  const fields = Object.entries(obj).map(([k, v]) => [k, Array.isArray(v) ? v[0] : v]);
  const typeOf = (v) => (typeof v === "number" ? (Number.isInteger(v) ? "int" : "double") : typeof v === "boolean" ? "boolean" : "String");
  if (lang === "java") return `public class Root {\n${fields.map(([k, v]) => `    private ${typeOf(v)} ${k};`).join("\n")}\n${fields.map(([k]) => `    public Object get${k[0].toUpperCase() + k.slice(1)}() { return ${k}; }\n    public void set${k[0].toUpperCase() + k.slice(1)}(Object v) { this.${k} = v; }`).join("\n")}\n}`;
  if (lang === "csharp") return `public class Root\n{\n${fields.map(([k, v]) => `    public ${typeOf(v) === "String" ? "string" : typeOf(v)} ${k[0].toUpperCase() + k.slice(1)} { get; set; }`).join("\n")}\n}`;
  if (lang === "php") return `<?php\nclass Root {\n${fields.map(([k]) => `    public $${k};`).join("\n")}\n${fields.map(([k]) => `    public function set${k[0].toUpperCase() + k.slice(1)}($v){ $this->${k}=$v; }`).join("\n")}\n}`;
  if (lang === "protobuf") return `syntax = "proto3";\n\nmessage Root {\n${fields.map(([k, v], i) => `  ${typeOf(v) === "String" ? "string" : typeOf(v) === "boolean" ? "bool" : typeOf(v)} ${k} = ${i + 1};`).join("\n")}\n}`;
  return "";
}

/* ============================================================================
 * Generic tool engines
 * ==========================================================================*/
function TransformTool({ tool }) {
  const [input, setInput] = useState("");
  const [out, setOut] = useState("");
  const [err, setErr] = useState("");
  const run = () => { try { setOut(String(tool.fn(input))); setErr(""); } catch (e) { setErr(String(e.message || e)); setOut(""); } };
  return (
    <div className="space-y-3">
      <p className="text-xs text-zinc-500">{tool.desc}</p>
      <textarea value={input} onChange={(e) => setInput(e.target.value)} className={areaCls} placeholder={tool.placeholder || "Paste input here…"} data-testid={`tool-input-${tool.id}`} />
      <div className="flex gap-2">
        <button onClick={run} disabled={!input.trim()} className={btnCls} data-testid={`tool-run-${tool.id}`}><Play className="w-4 h-4" /> Run</button>
        {out && <button onClick={() => { navigator.clipboard.writeText(out); toast.success("Copied"); }} className="px-4 py-2.5 border border-border text-zinc-300 hover:text-primary inline-flex items-center gap-2"><Copy className="w-4 h-4" /> Copy</button>}
      </div>
      {err && <pre className="text-severity-high text-xs font-mono whitespace-pre-wrap border border-severity-high/40 bg-severity-high/5 p-3" data-testid={`tool-error-${tool.id}`}>{err}</pre>}
      {out && <pre className="text-xs font-mono whitespace-pre-wrap border border-border bg-[#0a0a0a] p-3 max-h-96 overflow-auto text-zinc-200" data-testid={`tool-output-${tool.id}`}>{out}</pre>}
    </div>
  );
}

function FormTool({ tool }) {
  const [vals, setVals] = useState(() => Object.fromEntries((tool.fields || []).map((f) => [f.key, f.default ?? ""])));
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const set = (k, v) => setVals((s) => ({ ...s, [k]: v }));
  const run = async () => {
    setBusy(true); setErr("");
    try { setRes(await tool.run(vals)); } catch (e) { setErr(String(e.message || e)); setRes(null); } finally { setBusy(false); }
  };
  return (
    <div className="space-y-3">
      <p className="text-xs text-zinc-500">{tool.desc}</p>
      {(tool.fields || []).map((f) => (
        <div key={f.key}>
          <label className="data-label block mb-1">{f.label}</label>
          {f.type === "select" ? (
            <select value={vals[f.key]} onChange={(e) => set(f.key, e.target.value)} className={inputCls}>{f.options.map((o) => <option key={o} value={o}>{o}</option>)}</select>
          ) : f.type === "textarea" ? (
            <textarea value={vals[f.key]} onChange={(e) => set(f.key, e.target.value)} className={areaCls} placeholder={f.placeholder || ""} />
          ) : f.type === "file" ? (
            <input type="file" onChange={(e) => { const file = e.target.files?.[0]; if (!file) return; const fr = new FileReader(); fr.onload = () => set(f.key, fr.result); fr.readAsDataURL(file); }} className="text-xs text-zinc-400" />
          ) : f.type === "checkbox" ? (
            <input type="checkbox" checked={!!vals[f.key]} onChange={(e) => set(f.key, e.target.checked)} />
          ) : (
            <input type={f.type === "number" ? "number" : "text"} value={vals[f.key]} onChange={(e) => set(f.key, e.target.value)} className={inputCls} placeholder={f.placeholder || ""} data-testid={`tool-field-${tool.id}-${f.key}`} />
          )}
        </div>
      ))}
      <button onClick={run} disabled={busy} className={btnCls} data-testid={`tool-run-${tool.id}`}>
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Run
      </button>
      {err && <pre className="text-severity-high text-xs font-mono whitespace-pre-wrap border border-severity-high/40 bg-severity-high/5 p-3">{err}</pre>}
      {res && typeof res === "string" && <pre className="text-xs font-mono whitespace-pre-wrap border border-border bg-[#0a0a0a] p-3 max-h-96 overflow-auto text-zinc-200" data-testid={`tool-output-${tool.id}`}>{res}</pre>}
      {res && typeof res === "object" && <ResultTable data={res} />}
    </div>
  );
}

function NetTool({ tool }) {
  const [vals, setVals] = useState(() => Object.fromEntries((tool.fields || []).map((f) => [f.key, f.default ?? ""])));
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const set = (k, v) => setVals((s) => ({ ...s, [k]: v }));
  const run = async () => {
    setBusy(true); setErr("");
    try {
      const body = {};
      for (const f of tool.fields || []) {
        let v = vals[f.key];
        if (f.type === "number") v = Number(v);
        else if (f.type === "json") { try { v = v ? JSON.parse(v) : undefined; } catch (e) { throw new Error(`${f.label} must be valid JSON`); } }
        body[f.key] = v;
      }
      const { data } = await api.post(tool.path, body);
      setRes(data);
    } catch (e) { setErr(formatApiError(e.response?.data?.detail) || String(e.message || e)); setRes(null); } finally { setBusy(false); }
  };
  return (
    <div className="space-y-3">
      <p className="text-xs text-zinc-500">{tool.desc}</p>
      {(tool.fields || []).map((f) => (
        <div key={f.key}>
          <label className="data-label block mb-1">{f.label}</label>
          {f.type === "select" ? (
            <select value={vals[f.key]} onChange={(e) => set(f.key, e.target.value)} className={inputCls}>{f.options.map((o) => <option key={o} value={o}>{o}</option>)}</select>
          ) : f.type === "textarea" ? (
            <textarea value={vals[f.key]} onChange={(e) => set(f.key, e.target.value)} className={areaCls} placeholder={f.placeholder || ""} />
          ) : (
            <input type={f.type === "number" ? "number" : "text"} value={vals[f.key]} onChange={(e) => set(f.key, e.target.value)} className={inputCls} placeholder={f.placeholder || ""} data-testid={`tool-field-${tool.id}-${f.key}`} />
          )}
        </div>
      ))}
      <button onClick={run} disabled={busy} className={btnCls} data-testid={`tool-run-${tool.id}`}>
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Run
      </button>
      {err && <pre className="text-severity-high text-xs font-mono whitespace-pre-wrap border border-severity-high/40 bg-severity-high/5 p-3">{err}</pre>}
      {res && <NetResult data={res} />}
    </div>
  );
}

function ResultTable({ data }) {
  return <pre className="text-xs font-mono whitespace-pre-wrap border border-border bg-[#0a0a0a] p-3 max-h-96 overflow-auto text-zinc-200">{JSON.stringify(data, null, 2)}</pre>;
}
function NetResult({ data }) {
  if (data && Array.isArray(data.output)) {
    return <pre className="text-xs font-mono whitespace-pre border border-border bg-[#0a0a0a] p-3 max-h-96 overflow-auto text-zinc-200">{data.output.join("\n")}</pre>;
  }
  return <ResultTable data={data} />;
}

/* ============================================================================
 * Catalog
 * ==========================================================================*/
const T = (id, name, desc, fn, placeholder) => ({ id, name, desc, kind: "transform", fn, placeholder });
const F = (id, name, desc, fields, run) => ({ id, name, desc, kind: "form", fields, run });
const N = (id, name, desc, fields, path) => ({ id, name, desc, kind: "net", fields, path });
const domainField = { key: "domain", label: "Domain", placeholder: "example.com" };
const urlField = { key: "url", label: "URL", placeholder: "https://example.com" };
const hostField = { key: "host", label: "Host", placeholder: "example.com" };

const CATEGORIES = [
  {
    id: "domain", name: "Domain Tools", icon: Globe, tools: [
      N("availability", "Check Website Availability", "Test whether a website responds and how fast.", [urlField], "/toolbox/availability"),
      N("ping", "Ping a Website / Host", "Send ICMP echo requests to a host.", [hostField], "/toolbox/ping"),
      N("resolve", "Find IP Address", "Resolve a domain to its IPv4/IPv6 addresses and PTR.", [hostField], "/toolbox/resolve"),
      N("geo", "Find Location of Domain", "IP → country / city / ISP geolocation.", [{ key: "target", label: "Domain or IP", placeholder: "example.com" }], "/toolbox/geo"),
      N("compare", "Compare Websites", "Compare status, latency and size of two URLs.", [{ key: "url1", label: "URL 1" }, { key: "url2", label: "URL 2" }], "/toolbox/compare"),
      N("web-objects", "Analyze Webpage Objects", "Enumerate sub-resources and total page weight.", [urlField], "/toolbox/web-objects"),
      N("ssl-cert", "Monitor SSL Certificate", "Show certificate issuer, SANs and expiry.", [hostField, { key: "port", label: "Port", type: "number", default: 443 }], "/toolbox/ssl-certificate"),
      N("tls", "TLS Checker", "Enumerate enabled TLS/SSL protocol versions.", [hostField, { key: "port", label: "Port", type: "number", default: 443 }], "/toolbox/tls"),
      N("blacklist", "Realtime Blacklist Check", "Check an IP/domain against major DNSBLs.", [{ key: "target", label: "Domain or IP", placeholder: "1.2.3.4" }], "/toolbox/blacklist"),
      N("brand-reputation", "Brand Reputation Check", "Check a host against URLhaus abuse feeds.", [{ key: "target", label: "Domain", placeholder: "example.com" }], "/toolbox/brand-reputation"),
      N("dkim", "DKIM Validator", "Verify a DKIM selector publishes a public key.", [domainField, { key: "selector", label: "Selector", default: "default" }], "/toolbox/dkim"),
      N("dmarc", "DMARC Analyzer", "Fetch and grade the DMARC policy.", [domainField], "/toolbox/dmarc"),
      N("email-validate", "Email Validator", "Syntax + MX + disposable/role detection.", [{ key: "email", label: "Email", placeholder: "user@example.com" }], "/toolbox/email-validate"),
      N("domain-expiry", "Domain Expiry Checker", "WHOIS expiry date and days remaining.", [domainField], "/toolbox/domain-expiry"),
      N("spf", "SPF Record Checker", "Fetch and assess the SPF record.", [domainField], "/toolbox/spf"),
      N("whois", "Whois Lookup", "Registry/registrar registration data.", [domainField], "/toolbox/whois"),
      N("eml", "EML Viewer", "Parse an .eml message (paste raw source).", [{ key: "text", label: "Raw EML", type: "textarea", placeholder: "Paste the raw .eml content…" }], "/toolbox/eml"),
      F("ics", "ICS Viewer", "Parse calendar events from ICS text.", [{ key: "text", label: "ICS content", type: "textarea" }], (v) => icsView(v.text)),
      N("tls-rpt", "TLS RPT Checker", "Look up the _smtp._tls TLS-RPT record.", [domainField], "/toolbox/tls-rpt"),
      N("mta-sts", "MTA-STS Lookup", "DNS record + hosted MTA-STS policy.", [domainField], "/toolbox/mta-sts"),
      N("bimi", "BIMI Checker", "Look up the default._bimi record.", [domainField], "/toolbox/bimi"),
      N("asn", "ASN Lookup", "Autonomous system + org for an IP/domain.", [{ key: "target", label: "Domain or IP" }], "/toolbox/asn"),
      N("email-headers", "Message Header Analyzer", "Trace hops and SPF/DKIM/DMARC verdicts.", [{ key: "text", label: "Raw headers", type: "textarea" }], "/toolbox/email-headers"),
      N("pgp-key", "PGP Key Generator", "Generate an OpenPGP key pair (needs pgpy).", [{ key: "url1", label: "Name" }, { key: "url2", label: "Email" }], "/toolbox/pgp-key"),
    ],
  },
  {
    id: "dns", name: "DNS Tools", icon: ServerCog, tools: [
      N("dns", "DNS Analysis of your Domain", "Full A/AAAA/MX/TXT/NS/SOA record report.", [domainField, { key: "type", label: "Type", type: "select", options: ["ALL", "A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA", "SRV"], default: "ALL" }], "/toolbox/dns"),
      N("dns-propagation", "DNS Propagation Checker", "Compare answers across 6 public resolvers / networks (Cloudflare, Google, OpenDNS, AdGuard, ControlD, NextDNS).", [domainField, { key: "type", label: "Type", type: "select", options: ["A", "AAAA", "MX", "TXT", "NS"], default: "A" }], "/toolbox/dns-propagation"),
      N("mx", "MX Lookup", "Mail exchanger records for a domain.", [domainField], "/toolbox/mx"),
      N("soa", "SOA Lookup", "Start of authority record.", [domainField], "/toolbox/soa"),
      N("reverse-dns", "Reverse DNS Lookup", "PTR record for an IP or host.", [hostField], "/toolbox/reverse-dns"),
      N("dns-traversal", "DNS Traversal", "Zone-by-zone NS delegation path.", [domainField], "/toolbox/dns-traversal"),
      N("ns-perf", "Name Server Performance", "List authoritative nameservers and reachability.", [domainField], "/toolbox/ns-perf"),
      N("ns", "Namespace Server Delegation", "NS records delegated for the domain.", [domainField], "/toolbox/ns"),
    ],
  },
  {
    id: "validation", name: "Validation Tools", icon: ShieldCheck, tools: [
      F("regex", "Regex Parser / Tester", "Test a regular expression against input.", [{ key: "pattern", label: "Regex" }, { key: "flags", label: "Flags", default: "g" }, { key: "text", label: "Test string", type: "textarea" }], (v) => { const m = [...v.text.matchAll(new RegExp(v.pattern, v.flags.includes("g") ? v.flags : v.flags + "g"))]; return m.length ? m.map((x, i) => `Match ${i + 1}: ${JSON.stringify(x[0])} @ ${x.index}${x.length > 1 ? " groups=" + JSON.stringify(x.slice(1)) : ""}`).join("\n") : "No matches"; }),
      F("jsonpath", "JSON Path Evaluator", "Evaluate a simple JSONPath against JSON.", [{ key: "json", label: "JSON", type: "textarea" }, { key: "path", label: "Path", default: "$.store.book[0].title" }], (v) => JSON.stringify(jsonPathEval(v.json, v.path), null, 2)),
      F("jsonpath-finder", "JSONPath Finder", "List every JSONPath within a document.", [{ key: "json", label: "JSON", type: "textarea" }], (v) => jsonPathFinder(v.json)),
      F("xpath", "XPath Evaluator", "Evaluate an XPath against XML.", [{ key: "xml", label: "XML", type: "textarea" }, { key: "expr", label: "XPath", default: "//title" }], (v) => xpathEval(v.xml, v.expr)),
      T("html-validator", "HTML Validator", "Basic HTML structure/closure checks.", validateHtml),
      T("yaml-validator", "Yaml Validator", "Validate YAML by parsing it.", validateYaml),
      T("js-validator", "JavaScript validator", "Check JS for syntax errors (no execution).", validateJs),
      N("redirect-checker", "Redirection Checker", "Follow the redirect chain and status codes.", [urlField], "/toolbox/redirect-checker"),
      N("link-checker", "Link Checker", "Find broken links on a page.", [urlField], "/toolbox/link-checker"),
    ],
  },
  {
    id: "general", name: "General Tools", icon: Calculator, tools: [
      F("sla", "SLA Uptime Calculator", "Downtime allowance from an uptime SLA.", [{ key: "pct", label: "Uptime %", default: "99.9" }], (v) => slaDowntime(v.pct)),
      F("bandwidth", "Website Bandwidth Calculator", "Monthly transfer from page size × views.", [{ key: "size", label: "Page size (KB)", default: "500" }, { key: "views", label: "Views / month", default: "100000" }], (v) => bandwidthCalc(v.size, v.views)),
      F("hosting-bandwidth", "Hosting Bandwidth Calculator", "Bandwidth for a data transfer budget.", [{ key: "size", label: "Avg object size (KB)", default: "200" }, { key: "req", label: "Requests / month", default: "1000000" }], (v) => bandwidthCalc(v.size, v.req)),
      F("download-time", "Download Time Calculator", "Time to transfer a file at a given speed.", [{ key: "size", label: "File size (MB)", default: "100" }, { key: "speed", label: "Speed (Mbps)", default: "100" }], (v) => downloadTime(v.size, v.speed)),
      F("data-unit", "Data Unit Converter", "Convert between B/KB/MB/GB/TB and bits.", [{ key: "val", label: "Value", default: "1" }, { key: "from", label: "From", type: "select", options: ["B", "KB", "MB", "GB", "TB", "Kb", "Mb", "Gb"], default: "MB" }, { key: "to", label: "To", type: "select", options: ["B", "KB", "MB", "GB", "TB", "Kb", "Mb", "Gb"], default: "GB" }], (v) => dataUnitConverter(v.val, v.from, v.to)),
      N("speed-test", "Internet Speed Test (server-side)", "Measure DNS/connect/TLS/TTFB and KB/s for a URL.", [urlField], "/toolbox/web-speed"),
      F("browser-fingerprint", "Browser Fingerprint Test", "Inspect the fingerprint your browser exposes.", [], () => browserFingerprint()),
      F("error-budget", "Error Budget Calculator", "Allowed downtime for an SLO over a period.", [{ key: "slo", label: "SLO %", default: "99.9" }, { key: "days", label: "Period (days)", default: "30" }], (v) => errorBudget(v.slo, v.days)),
    ],
  },
  {
    id: "status", name: "Status Tools", icon: Activity, tools: [
      N("downradar", "DownRadar / Availability", "Is the site up right now (from this host)?", [urlField], "/toolbox/availability"),
      N("web-speed-status", "Web Speed Report", "Load timing breakdown for a URL.", [urlField], "/toolbox/web-speed"),
    ],
  },
  {
    id: "sysadmin", name: "Sysadmin Tools", icon: Wrench, tools: [
      F("cron", "Cron Expression Generator", "Build a cron schedule expression.", [{ key: "min", label: "Minute", default: "0" }, { key: "hour", label: "Hour", default: "*" }, { key: "dom", label: "Day of month", default: "*" }, { key: "month", label: "Month", default: "*" }, { key: "dow", label: "Day of week", default: "*" }], (v) => `${cronExpr(v.min, v.hour, v.dom, v.month, v.dow)}\n\n(e.g. run at ${v.min} ${v.hour === "*" ? "every hour" : v.hour + ":00"})`),
      N("port", "Check Port Availability", "Test a TCP port on a host.", [hostField, { key: "port", label: "Port", type: "number", default: 443 }], "/toolbox/port"),
      N("traceroute", "Traceroute Generator", "Trace the network path to a host.", [hostField], "/toolbox/traceroute"),
      N("my-traceroute", "My Traceroute Generator", "Trace the path (same engine).", [hostField], "/toolbox/traceroute"),
      N("http2", "HTTP/2 Tester", "Check ALPN negotiation for HTTP/2.", [hostField, { key: "port", label: "Port", type: "number", default: 443 }], "/toolbox/http2"),
      N("poodle", "SSLv3 POODLE Check", "Test whether SSLv3 is still negotiable.", [hostField, { key: "port", label: "Port", type: "number", default: 443 }], "/toolbox/poodle"),
      T("ipv4-converter", "IPv4 Converter", "Convert IPv4 addresses to IPv4-mapped IPv6.", ipv4ToIpv6),
      T("ipv6-compress", "IPv6 Compression & Shortener", "Shorten IPv6 addresses per RFC 5952.", ipv6Compress),
      F("ipv4-subnet", "IPv4 Subnet Calculator", "Network/broadcast/range for IPv4 + prefix.", [{ key: "ip", label: "IPv4", default: "192.168.1.10" }, { key: "cidr", label: "Prefix", default: "24" }], (v) => subnetCalc(v.ip, v.cidr, false)),
      F("ipv6-subnet", "IPv6 Subnet Calculator", "Summarise an IPv6 prefix.", [{ key: "ip", label: "IPv6", default: "2001:db8::1" }, { key: "cidr", label: "Prefix", default: "64" }], (v) => subnetCalc(v.ip, v.cidr, true)),
      F("password-gen", "Random Password Generator", "Cryptographically random password.", [{ key: "len", label: "Length", type: "number", default: 20 }, { key: "upper", label: "Uppercase", type: "checkbox", default: true }, { key: "lower", label: "Lowercase", type: "checkbox", default: true }, { key: "digits", label: "Digits", type: "checkbox", default: true }, { key: "symbols", label: "Symbols", type: "checkbox", default: true }], (v) => genPassword(Number(v.len), v.upper, v.lower, v.digits, v.symbols)),
      N("heartbleed", "Heartbleed Check", "TLS handshake check (use nmap for full CVE scan).", [hostField, { key: "port", label: "Port", type: "number", default: 443 }], "/toolbox/heartbleed"),
      N("websocket", "WebSocket Availability", "Attempt a WebSocket upgrade handshake.", [{ key: "url", label: "WS/WSS URL", placeholder: "wss://example.com/socket" }], "/toolbox/websocket"),
      N("ghostcat", "Ghostcat Check", "Probe the AJP port 8009 for exposure.", [hostField], "/toolbox/ghostcat"),
      N("server-header", "Server Header / HTTP Headers", "Status, server banner and security headers.", [urlField], "/toolbox/http-headers"),
      N("hsts", "HSTS Tester", "Check the Strict-Transport-Security header.", [urlField], "/toolbox/http-headers"),
      N("xfo", "X-Frame-Options Tester", "Check X-Frame-Options / CSP frame-ancestors.", [urlField], "/toolbox/http-headers"),
      N("cookies", "Secure Cookie Tester", "Check Secure/HttpOnly/SameSite on cookies.", [urlField], "/toolbox/http-headers"),
      F("curl", "Curl Checker", "Paste a curl command — parsed (never shell-executed) and sent via the API tester.", [{ key: "cmd", label: "curl command", type: "textarea", placeholder: "curl -X POST https://httpbin.org/post -H 'Content-Type: application/json' -d '{\"a\":1}'" }], async (v) => { const r = parseCurl(v.cmd); if (!r.url) throw new Error("No URL found in the curl command"); const { data } = await api.post("/toolbox/rest-api", { method: r.method, url: r.url, headers: r.headers, body: r.body || undefined }); return JSON.stringify({ parsed_request: r, response: data }, null, 2); }),
    ],
  },
  {
    id: "formatter", name: "Formatter Tools", icon: Braces, tools: [
      T("json-formatter", "JSON Formatter", "Pretty-print JSON.", (s) => fmtJson(s, 2)),
      T("xml-formatter", "XML Formatter", "Pretty-print XML.", fmtXml),
      T("sql-formatter", "SQL Formatter", "Reformat SQL statements.", fmtSql),
      T("html-formatter", "HTML Formatter", "Indent HTML.", htmlBeautify),
      T("html-beautifier", "HTML Beautifier", "Beautify minified HTML.", htmlBeautify),
    ],
  },
  {
    id: "content", name: "Content Tools", icon: FileSearch, tools: [
      T("text-ratio", "Text Ratio", "Paste HTML → text-vs-code ratio.", textRatioClient),
      N("link-explorer-content", "Link Explorer", "Group a page's internal/external links.", [urlField], "/toolbox/link-explorer"),
      T("lynx-view", "Lynx View", "Render a webpage's text content.", lynxView),
      N("text-ratio-url", "Text Ratio (from URL)", "Fetch a page and compute its text ratio.", [urlField], "/toolbox/text-ratio"),
    ],
  },
  {
    id: "developer", name: "Developer Tools", icon: Code2, tools: [
      N("rest-api", "REST API Tester", "Send an HTTP request and view the response.", [{ key: "method", label: "Method", type: "select", options: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], default: "GET" }, { key: "url", label: "URL" }, { key: "headers", label: "Headers (JSON)", type: "json", placeholder: "{\"Accept\":\"application/json\"}" }, { key: "body", label: "Body", type: "textarea" }], "/toolbox/rest-api"),
      T("js-minifier", "JavaScript Minifier", "Compact JS (heuristic).", jsMinify),
      T("js-beautifier", "JavaScript Beautifier", "Re-indent JS (heuristic).", jsBeautify),
      T("css-minifier", "CSS Minifier", "Compact CSS.", cssMinify),
      T("css-beautifier", "CSS Beautifier", "Beautify CSS.", cssBeautify),
      T("json-minifier", "JSON Minifier", "Compact JSON.", minJson),
      T("json-beautifier", "JSON Beautifier", "Beautify JSON.", (s) => fmtJson(s, 2)),
      F("timestamp", "Timestamp Converter", "Unix epoch ↔ human date.", [{ key: "ts", label: "Epoch (s) or ISO date", default: String(Math.floor(Date.now() / 1000)) }], (v) => { const t = v.ts.trim(); if (/^\d+$/.test(t)) { const d = new Date(Number(t) * 1000); return `Epoch: ${t}\nUTC:   ${d.toUTCString()}\nLocal: ${d.toString()}\nISO:   ${d.toISOString()}`; } const d = new Date(t); if (isNaN(d)) throw new Error("Unrecognised value"); return `ISO:   ${d.toISOString()}\nEpoch: ${Math.floor(d.getTime() / 1000)}\nUTC:   ${d.toUTCString()}`; }),
      F("json-generator", "JSON Generator", "Generate JSON from a simple template (key: value lines).", [{ key: "tpl", label: "Template", type: "textarea", placeholder: "id: 1\nname: sample\nactive: true\ntags: [a, b]" }], (v) => { const o = {}; v.tpl.split(/\r?\n/).forEach((l) => { const m = l.match(/^([^:]+):\s*(.*)$/); if (!m) return; let val = m[2].trim(); if (/^-?\d+(\.\d+)?$/.test(val)) val = Number(val); else if (val === "true" || val === "false") val = val === "true"; else if (val.startsWith("[")) val = val.slice(1, -1).split(",").map((x) => x.trim()); o[m[1].trim()] = val; }); return JSON.stringify(o, null, 2); }),
      F("color-picker", "Color Code Picker", "Pick a colour / sample the average colour of an image.", [{ key: "color", label: "Colour", type: "text", default: "#ffcc00" }, { key: "img", label: "Image (optional)", type: "file" }], (v) => (v.img ? avgColorFromImage(v.img) : "Hex: " + v.color + "  (preview colour set)")),
      T("har-viewer", "HAR Viewer", "List requests from a HAR file (paste JSON).", harView),
      T("har-sanitizer", "HAR Sanitizer", "Strip cookies/auth from a HAR before sharing.", harSanitize),
      T("url-splitter", "URL Splitter", "Break a URL into components.", urlSplit),
      T("code-cleaner", "Code Cleaner", "Strip comments/extra whitespace from HTML.", codeCleaner),
      T("diff", "Diff Checker", "Line diff: paste OLD then a line with '---' then NEW.", (s) => { const [a, b] = s.split(/\n---\n/); return diffText(a || "", b || ""); }),
      T("url-encode", "URL Encoder/Decoder", "encodeURIComponent / decodeURIComponent.", (s) => `Encoded:\n${urlEnc(s)}\n\nDecoded:\n${(() => { try { return urlDec(s); } catch (e) { return "(not a valid encoded string)"; } })()}`),
      T("mime-type", "MIME Type Checker", "Guess the MIME type from a filename/extension.", (s) => { const ext = (s.trim().match(/\.([a-z0-9]+)$/i) || [])[1]?.toLowerCase(); const map = { html: "text/html", htm: "text/html", css: "text/css", js: "application/javascript", json: "application/json", xml: "application/xml", txt: "text/plain", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", svg: "image/svg+xml", pdf: "application/pdf", zip: "application/zip", gz: "application/gzip", mp4: "video/mp4", mp3: "audio/mpeg", csv: "text/csv", yaml: "application/yaml", yml: "application/yaml", doc: "application/msword", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" }; return ext ? `${s.trim()} → ${map[ext] || "application/octet-stream"}` : "Enter a filename with an extension"; }),
      T("html-encode", "HTML Encoder/Decoder", "Encode or decode HTML entities.", (s) => `Encoded:\n${htmlEnc(s)}\n\nDecoded:\n${htmlDec(s)}`),
      T("js-escape", "JavaScript String Escaper / Unescaper", "Escape/unescape JS string literals.", (s) => `Escaped:\n${jsEsc(s)}\n\nUnescaped:\n${(() => { try { return jsUnesc(s); } catch (e) { return "(invalid escape sequence)"; } })()}`),
      T("xml-escape", "XML String Escaper / Unescaper", "Escape/unescape XML entities.", (s) => `Escaped:\n${xmlEsc(s)}\n\nDecoded:\n${xmlUnesc(s)}`),
      T("base64-encode", "Base64 Encoder", "Text → Base64.", b64e),
      T("base64-decode", "Base64 Decoder", "Base64 → text.", b64d),
      T("jwt-decoder", "JWT Decoder", "Decode a JWT header + payload (no verification).", jwtDecode),
      T("svg-viewer", "SVG Viewer", "View SVG by inlining it as an image.", (s) => s),
    ],
  },
  {
    id: "threaddump", name: "Thread Dump Tools", icon: Layers, tools: [
      T("threaddump-analyzer", "Thread Dump Analyzer", "Detect deadlocks and thread state counts.", threadDumpAnalysis),
      T("thread-method", "Method Execution Summary", "Count stack frames per method.", threadMethodSummary),
      T("thread-stack", "Thread Stack Length", "Bucket threads by stack depth.", threadStackLength),
    ],
  },
  {
    id: "converter", name: "Converter Tools", icon: ArrowRightLeft, tools: [
      T("json-protobuf", "JSON to Protobuf", "Generate a proto3 message from JSON.", (s) => jsonToClass(s, "protobuf")),
      T("json-java", "JSON to JAVA", "Generate a Java class from JSON.", (s) => jsonToClass(s, "java")),
      T("json-csharp", "JSON to C#", "Generate a C# class from JSON.", (s) => jsonToClass(s, "csharp")),
      T("json-php", "JSON to PHP", "Generate a PHP class from JSON.", (s) => jsonToClass(s, "php")),
      T("json-xml", "JSON to XML", "Convert JSON to XML.", (s) => jsonToXml(JSON.parse(s))),
      T("json-yaml", "JSON to YAML", "Convert JSON to YAML.", jsonToYamlStr),
      T("xml-json", "XML to JSON", "Convert XML to JSON.", xmlToJson),
      T("xml-yaml", "XML to YAML", "Convert XML to YAML.", xmlToYaml),
      T("xml-xsd", "XML to XSD", "Infer a basic XSD from JSON-shaped data.", jsonToXsd),
      T("yaml-json", "YAML to JSON", "Convert YAML to JSON.", yamlToJson),
      T("csv-json", "CSV to JSON", "Convert CSV to a JSON array.", (s) => csvToJson(s)),
      T("csv-xml", "CSV to XML", "Convert CSV to XML.", (s) => csvToXml(s)),
      T("csv-yaml", "CSV to YAML", "Convert CSV to YAML.", (s) => csvToYaml(s)),
      T("csv-sql", "CSV to SQL", "Generate INSERT statements from CSV.", (s) => csvToSql(s)),
      T("sql-mongo", "SQL to MongoDB", "Convert a simple SELECT to a Mongo query.", sqlToMongo),
      T("ini-json", "INI to JSON", "Convert INI to JSON.", iniToJson),
      T("ini-xml", "INI to XML", "Convert INI to XML.", iniToXml),
      T("ini-yaml", "INI to YAML", "Convert INI to YAML.", iniToYaml),
      F("image-datauri", "Image to Data URI", "Encode an image file as a data URI.", [{ key: "img", label: "Image", type: "file" }], (v) => (v.img ? `Length: ${v.img.length} chars\n\n${v.img}` : "Choose an image")),
      T("datauri-image", "Data URI to Image", "Show a data URI (image) inline.", (s) => s.trim()),
      F("rgb-hex", "RGB to Hex", "Convert R,G,B to a hex colour.", [{ key: "r", label: "R", default: "255" }, { key: "g", label: "G", default: "204" }, { key: "b", label: "B", default: "0" }], (v) => { const h = (n) => Math.max(0, Math.min(255, Number(n))).toString(16).padStart(2, "0"); return `#${h(v.r)}${h(v.g)}${h(v.b)}`.toUpperCase(); }),
      F("hex-rgb", "Hex to RGB", "Convert a hex colour to R,G,B.", [{ key: "hex", label: "Hex", default: "#ffcc00" }], (v) => { const m = v.hex.trim().replace("#", ""); if (!/^[0-9a-f]{6}$/i.test(m)) throw new Error("Enter a 6-digit hex colour"); return `R: ${parseInt(m.slice(0, 2), 16)}, G: ${parseInt(m.slice(2, 4), 16)}, B: ${parseInt(m.slice(4, 6), 16)}`; }),
      T("idn", "IDN Converter", "Unicode domain ↔ punycode (IDN).", idnConvert),
    ],
  },
  {
    id: "cloud", name: "Cloud Tools", icon: Cloud, tools: [
      { id: "cloud-diagram", name: "Cloud Architecture Diagram", desc: "Describe AWS/Azure/GCP/K8s architecture in text (Name : layer, A -> B) → rendered SVG diagram.", kind: "custom", placeholder: "Internet : edge\nWAF : edge\nALB : network\nEC2 : compute\nRDS : data\nS3 : storage\nInternet -> WAF\nWAF -> ALB\nALB -> EC2\nEC2 -> RDS\nALB -> S3" },
      F("roi", "Cloud ROI Calculator", "Estimate savings from a cloud optimisation.", [{ key: "spend", label: "Monthly spend ($)", default: "10000" }, { key: "save", label: "Optimisation %", default: "25" }], (v) => `Monthly saving: $${(Number(v.spend) * Number(v.save) / 100).toFixed(2)}\nYearly saving:  $${(Number(v.spend) * Number(v.save) / 100 * 12).toFixed(2)}`),
    ],
  },
];

const ALL_TOOLS = CATEGORIES.flatMap((c) => c.tools.map((t) => ({ ...t, cat: c.name, catId: c.id })));

/* ============================================================================
 * Special renderers (custom)
 * ==========================================================================*/
function SvgTool({ tool }) {
  const [input, setInput] = useState("<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120'><circle cx='60' cy='60' r='50' fill='#ffcc00'/></svg>");
  const clean = input.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/on\w+\s*=/gi, "data-x=");
  const uri = "data:image/svg+xml;base64," + b64e(clean);
  return (
    <div className="space-y-3">
      <p className="text-xs text-zinc-500">{tool.desc}</p>
      <textarea value={input} onChange={(e) => setInput(e.target.value)} className={areaCls + " min-h-[120px]"} />
      <div className="border border-border bg-[#0a0a0a] p-4 flex items-center justify-center">
        <img src={uri} alt="svg preview" style={{ maxWidth: 260, maxHeight: 260 }} />
      </div>
    </div>
  );
}
function DataUriImageTool({ tool }) {
  const [input, setInput] = useState("");
  return (
    <div className="space-y-3">
      <p className="text-xs text-zinc-500">{tool.desc}</p>
      <textarea value={input} onChange={(e) => setInput(e.target.value)} className={areaCls + " min-h-[120px]"} placeholder="data:image/png;base64,…" />
      {input.trim().startsWith("data:image") && <div className="border border-border bg-[#0a0a0a] p-4 flex justify-center"><img src={input.trim()} alt="preview" style={{ maxWidth: 320, maxHeight: 320 }} /></div>}
    </div>
  );
}

function CloudDiagramTool({ tool }) {
  const [spec, setSpec] = useState(tool.placeholder || "");
  const svg = useMemo(() => { try { return cloudDiagram(spec); } catch (e) { return ""; } }, [spec]);
  const uri = "data:image/svg+xml;base64," + b64e(svg);
  return (
    <div className="space-y-3">
      <p className="text-xs text-zinc-500">{tool.desc}</p>
      <textarea value={spec} onChange={(e) => setSpec(e.target.value)} className={areaCls + " min-h-[180px]"} data-testid="cloud-diagram-spec" />
      <div className="flex gap-2">
        <button onClick={() => { navigator.clipboard.writeText(svg); toast.success("SVG copied"); }} className="px-4 py-2.5 border border-border text-zinc-300 hover:text-primary inline-flex items-center gap-2"><Copy className="w-4 h-4" /> Copy SVG</button>
        <a href={uri} download="cloud-architecture.svg" className="px-4 py-2.5 border border-border text-zinc-300 hover:text-primary inline-flex items-center gap-2">Download SVG</a>
      </div>
      {svg && <div className="border border-border bg-[#0a0a0a] p-3 overflow-auto" data-testid="cloud-diagram-preview"><img src={uri} alt="cloud architecture diagram" style={{ maxWidth: "100%" }} /></div>}
    </div>
  );
}

/* ============================================================================
 * Page
 * ==========================================================================*/
export default function AllTools() {
  const [active, setActive] = useState(CATEGORIES[0].id);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(null);

  const filtered = useMemo(() => {
    if (!query.trim()) return null;
    const q = query.toLowerCase();
    return ALL_TOOLS.filter((t) => t.name.toLowerCase().includes(q) || t.desc.toLowerCase().includes(q) || t.cat.toLowerCase().includes(q));
  }, [query]);

  const renderTool = (tool) => {
    if (tool.id === "svg-viewer") return <SvgTool tool={tool} />;
    if (tool.id === "datauri-image") return <DataUriImageTool tool={tool} />;
    if (tool.id === "cloud-diagram") return <CloudDiagramTool tool={tool} />;
    if (tool.kind === "net") return <NetTool tool={tool} />;
    if (tool.kind === "form") return <FormTool tool={tool} />;
    return <TransformTool tool={tool} />;
  };

  const ToolCard = ({ tool }) => (
    <button onClick={() => setOpen(tool)} data-testid={`tool-card-${tool.id}`}
      className="text-left border border-border bg-[#111] hover:border-primary/60 hover:bg-[#151515] transition-colors p-3 flex flex-col gap-1">
      <span className="text-sm font-medium text-zinc-100">{tool.name}</span>
      <span className="text-[11px] text-zinc-500 line-clamp-2">{tool.desc}</span>
      <span className="data-label mt-auto pt-2">{tool.kind === "net" ? "network" : "local"}</span>
    </button>
  );

  return (
    <div className="p-5 md:p-8" data-testid="all-tools-page">
      <div className="flex flex-wrap items-center gap-3 mb-1">
        <Wrench className="w-5 h-5 text-primary" />
        <h1 className="font-heading font-black text-2xl text-white">All Tools</h1>
        <span className="data-label">{ALL_TOOLS.length} utilities</span>
      </div>
      <p className="text-sm text-zinc-500 mb-5 max-w-3xl">
        One shared toolbox for domain/DNS, network, email-security, developer and converter tasks.
        Most converters &amp; formatters run <span className="text-zinc-300">locally in your browser</span>;
        network tools use the backend. Authorized use only.
      </p>

      <div className="relative mb-4 max-w-md">
        <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search all tools…" className={inputCls + " pl-9"} data-testid="all-tools-search" />
      </div>

      {filtered ? (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
          {filtered.map((t) => <ToolCard key={t.catId + t.id} tool={t} />)}
          {!filtered.length && <p className="text-sm text-zinc-500">No tools matched “{query}”.</p>}
        </div>
      ) : (
        <Tabs value={active} onValueChange={setActive}>
          <TabsList className="bg-[#111] border border-border flex-wrap h-auto justify-start p-1">
            {CATEGORIES.map((c) => (
              <TabsTrigger key={c.id} value={c.id} data-testid={`tool-cat-${c.id}`} className="gap-1.5 data-[state=active]:bg-primary data-[state=active]:text-black text-xs">
                <c.icon className="w-3.5 h-3.5" /> {c.name}
              </TabsTrigger>
            ))}
          </TabsList>
          {CATEGORIES.map((c) => (
            <TabsContent key={c.id} value={c.id} className="mt-4">
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                {c.tools.map((t) => <ToolCard key={t.id} tool={t} />)}
              </div>
            </TabsContent>
          ))}
        </Tabs>
      )}

      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        <DialogContent className="max-w-2xl bg-[#0e0e0e] border-border max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-white">
              <Wrench className="w-4 h-4 text-primary" /> {open?.name}
            </DialogTitle>
          </DialogHeader>
          <div data-testid={`tool-panel-${open?.id}`}>{open && renderTool(open)}</div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
