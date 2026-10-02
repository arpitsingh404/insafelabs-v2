import { createContext, useContext, useRef, useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { FilesetResolver, GestureRecognizer, FaceLandmarker, DrawingUtils } from "@mediapipe/tasks-vision";
import { toast } from "sonner";
import { Hand, Camera, CameraOff, Loader2, Maximize2, Minimize2, MousePointerClick, ScanFace, Gauge, Mic, MicOff, Zap, RotateCcw, ZoomIn, Minus, GripVertical } from "lucide-react";

const WASM = "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@1.0.1/wasm";
const GR_MODEL = "https://storage.googleapis.com/mediapipe-models/gesture_recognizer/gesture_recognizer/float16/1/gesture_recognizer.task";
const FL_MODEL = "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task";

export const GESTURE_LABEL = {
  None: "—", Closed_Fist: "✊ Fist", Open_Palm: "🖐 Open Palm", Pointing_Up: "☝ Pointing",
  Thumb_Down: "👎 Thumb Down", Thumb_Up: "👍 Thumb Up", Victory: "✌ Victory", ILoveYou: "🤟 ILoveYou",
};

const lerp = (a, b, t) => a + (b - a) * t;
const clamp01 = (v) => Math.min(1, Math.max(0, v));
// active-region remap: a central region (margin..1-margin) covers the FULL screen,
// so the hand reaches every edge WITHOUT leaving the camera frame (where tracking is lost).
const remapReach = (v, margin) => (margin <= 0 ? v : clamp01((v - margin) / (1 - 2 * margin)));

// fill a React-controlled input via the native value setter so onChange fires
function setNativeValue(el, value) {
  const proto = el.tagName === "TEXTAREA" ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
  setter.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
}
function fillAndRun(el, value, run) {
  if (!el) return false;
  el.focus();
  setNativeValue(el, value);
  if (run) setTimeout(() => { const f = el.closest("form"); if (f && f.requestSubmit) f.requestSubmit(); }, 250);
  return true;
}
// normalise spoken targets: "example dot com" -> "example.com", "a at b" -> "a@b"
function parseTarget(s) {
  return s.replace(/\s+dot\s+/g, ".").replace(/\s+at\s+/g, "@").replace(/\s+slash\s+/g, "/").replace(/\s+dash\s+/g, "-").replace(/\s+/g, "").replace(/[.,!?]+$/, "").trim();
}
function parseSpokenTarget(s) {
  const cleaned = (s || "").toLowerCase().replace(/^\s*(scan|target|lookup|check|run|open|hit)\s+/i, "");
  return parseTarget(cleaned);
}
const OSINT_INPUTS = ["osint-email-input", "osint-phone-input", "osint-image-input", "osint-username-input", "osint-imei-input"];

// module targets for gesture shortcuts + voice navigation
export const MODULES = [
  { to: "/app", label: "Command" },
  { to: "/app/scanner", label: "Attack Surface" },
  { to: "/app/osint", label: "OSINT" },
  { to: "/app/redteam", label: "Red Team Ops" },
  { to: "/app/ad-enum", label: "AD / LDAP" },
  { to: "/app/netmap", label: "Network Map" },
  { to: "/app/binre", label: "Reverse Eng" },
  { to: "/app/operation", label: "Operation Report" },
  { to: "/app/toolkit", label: "Hacker Toolkit" },
  { to: "/app/device", label: "USB Bridge" },
  { to: "/app/ai-pentest", label: "AI Pentest" },
  { to: "/app/gesture", label: "Gesture Control" },
  { to: "/app/guide", label: "How to Use" },
];

const VOICE_NAV = [
  { kw: ["command", "dashboard", "home"], to: "/app", label: "Command" },
  { kw: ["scan", "scanner", "attack surface"], to: "/app/scanner", label: "Attack Surface" },
  { kw: ["osint", "intelligence"], to: "/app/osint", label: "OSINT" },
  { kw: ["red team", "redteam"], to: "/app/redteam", label: "Red Team Ops" },
  { kw: ["active directory", "ldap"], to: "/app/ad-enum", label: "AD / LDAP" },
  { kw: ["network map", "network", "netmap"], to: "/app/netmap", label: "Network Map" },
  { kw: ["reverse", "binary"], to: "/app/binre", label: "Reverse Eng" },
  { kw: ["operation", "report", "dossier"], to: "/app/operation", label: "Operation Report" },
  { kw: ["toolkit", "tools"], to: "/app/toolkit", label: "Hacker Toolkit" },
  { kw: ["device", "usb", "bridge"], to: "/app/device", label: "USB Bridge" },
  { kw: ["ai pentest", "pentest"], to: "/app/ai-pentest", label: "AI Pentest" },
  { kw: ["gesture"], to: "/app/gesture", label: "Gesture Control" },
  { kw: ["guide", "help", "how to use"], to: "/app/guide", label: "How to Use" },
];

const Ctx = createContext(null);
export const useGesture = () => useContext(Ctx);

// gestures safe to map to an action (Pointing_Up excluded — it collides with cursor move)
export const MAP_GESTURES = [
  { key: "Closed_Fist", label: "✊ Fist" },
  { key: "Victory", label: "✌ Victory" },
  { key: "Open_Palm", label: "🖐 Open Palm" },
  { key: "ILoveYou", label: "🤟 ILoveYou" },
];
export const GESTURE_MACROS = [
  { id: "macro:bb_scan", label: "Bug Bounty — auto-scan target" },
  { id: "macro:surface_scan", label: "Attack Surface — scan target" },
  { id: "macro:netmap_scan", label: "Network Map — scan target" },
  { id: "macro:osint_lookup", label: "OSINT — lookup target" },
  { id: "macro:operation", label: "Operation Report — open" },
];
export const GESTURE_VOICE_MACROS = [
  { id: "voice:bb_scan", label: "🎤 Voice → Bug Bounty scan" },
  { id: "voice:surface_scan", label: "🎤 Voice → Attack Surface scan" },
  { id: "voice:netmap_scan", label: "🎤 Voice → Network scan" },
  { id: "voice:osint_lookup", label: "🎤 Voice → OSINT lookup" },
];

export function GestureProvider({ children }) {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const cursorRef = useRef(null);
  const grRef = useRef(null);
  const flRef = useRef(null);
  const rafRef = useRef(null);
  const runningRef = useRef(false);
  const posRef = useRef({ x: window.innerWidth / 2, y: window.innerHeight / 2 });
  const pinchDownRef = useRef(false);
  const lastTsRef = useRef(-1);
  const fpsRef = useRef({ t: performance.now(), n: 0, fps: 0 });
  const twoHandRef = useRef({ base: null, baseZoom: 1 });
  const zoomRef = useRef(1);
  const zoomWrapRef = useRef(null);
  const scrollAccelRef = useRef(0);

  const [phase, setPhase] = useState("idle"); // idle | loading | live | error
  const [err, setErr] = useState("");
  const [stream, setStream] = useState(null);
  const [expanded, setExpanded] = useState(false);
  const [faceOn, setFaceOn] = useState(true);
  const [controlOn, setControlOn] = useState(true);
  const [scrollOn, setScrollOn] = useState(() => localStorage.getItem("insafe_scrollOn") !== "0");
  const [zoomOn, setZoomOn] = useState(() => localStorage.getItem("insafe_zoomOn") !== "0");
  const [shortcutsOn, setShortcutsOn] = useState(() => localStorage.getItem("insafe_shortcutsOn") !== "0");
  const [sensitivity, setSensitivity] = useState(() => parseFloat(localStorage.getItem("insafe_sens")) || 0.35);
  const [scrollSpeed, setScrollSpeed] = useState(() => parseFloat(localStorage.getItem("insafe_scrollspd")) || 1);
  const [edgeReach, setEdgeReach] = useState(() => { const v = parseFloat(localStorage.getItem("insafe_edgereach")); return isNaN(v) ? 0.15 : v; });
  const [cameras, setCameras] = useState([]);
  const [cameraId, setCameraId] = useState(() => localStorage.getItem("insafe_cam") || "");
  const [hud, setHud] = useState({ gesture: "—", face: false, blink: false, head: "—", fps: 0, hand: false, pinch: false, clicks: 0, shortcut: "—", heard: "", zoom: 1 });

  const controlRef = useRef(true);
  const faceRef = useRef(true);
  const expandedRef = useRef(false);
  const scrollOnRef = useRef(scrollOn), zoomOnRef = useRef(zoomOn), shortcutsOnRef = useRef(shortcutsOn);
  const sensitivityRef = useRef(sensitivity), scrollSpeedRef = useRef(scrollSpeed), cameraIdRef = useRef(cameraId);
  const edgeReachRef = useRef(edgeReach);
  useEffect(() => { controlRef.current = controlOn; }, [controlOn]);
  useEffect(() => { faceRef.current = faceOn; }, [faceOn]);
  useEffect(() => { expandedRef.current = expanded; }, [expanded]);
  useEffect(() => { scrollOnRef.current = scrollOn; localStorage.setItem("insafe_scrollOn", scrollOn ? "1" : "0"); }, [scrollOn]);
  useEffect(() => { zoomOnRef.current = zoomOn; localStorage.setItem("insafe_zoomOn", zoomOn ? "1" : "0"); }, [zoomOn]);
  useEffect(() => { shortcutsOnRef.current = shortcutsOn; localStorage.setItem("insafe_shortcutsOn", shortcutsOn ? "1" : "0"); }, [shortcutsOn]);
  useEffect(() => { sensitivityRef.current = sensitivity; localStorage.setItem("insafe_sens", String(sensitivity)); }, [sensitivity]);
  useEffect(() => { scrollSpeedRef.current = scrollSpeed; localStorage.setItem("insafe_scrollspd", String(scrollSpeed)); }, [scrollSpeed]);
  useEffect(() => { edgeReachRef.current = edgeReach; localStorage.setItem("insafe_edgereach", String(edgeReach)); }, [edgeReach]);
  useEffect(() => { cameraIdRef.current = cameraId; localStorage.setItem("insafe_cam", cameraId || ""); }, [cameraId]);

  // ---- navigation + gesture shortcuts + voice ----
  const navigate = useNavigate();
  const navRef = useRef(navigate);
  useEffect(() => { navRef.current = navigate; }, [navigate]);

  const shortcutRef = useRef({ name: null, start: 0 });
  const navCooldownRef = useRef(0);

  const [gestureMap, setGestureMap] = useState(() => {
    try { const j = JSON.parse(localStorage.getItem("insafe_gmap")); if (j) return j; } catch { /* noop */ }
    const fist = localStorage.getItem("insafe_fist") || "/app";
    const vic = localStorage.getItem("insafe_victory") || "/app/scanner";
    return { Closed_Fist: `nav:${fist}`, Victory: `nav:${vic}`, Open_Palm: "none", ILoveYou: "none" };
  });
  const [macroTarget, setMacroTarget] = useState(() => localStorage.getItem("insafe_macrotgt") || "example.com");
  const [voiceCapture, setVoiceCapture] = useState(null);
  const captureRecRef = useRef(null);
  const gestureMapRef = useRef(gestureMap);
  const macroTargetRef = useRef(macroTarget);
  const runActionRef = useRef(null);
  useEffect(() => { gestureMapRef.current = gestureMap; localStorage.setItem("insafe_gmap", JSON.stringify(gestureMap)); }, [gestureMap]);
  useEffect(() => { macroTargetRef.current = macroTarget; localStorage.setItem("insafe_macrotgt", macroTarget); }, [macroTarget]);

  const setGestureMapEntry = useCallback((key, val) => {
    setGestureMap((m) => ({ ...m, [key]: val }));
  }, []);

  const runMacro = useCallback((id) => {
    const tgt = parseTarget(macroTargetRef.current || "");
    const nav = (p) => navRef.current && navRef.current(p);
    const q = (t) => document.querySelector(`[data-testid="${t}"]`);
    if (id === "bb_scan") {
      nav("/app/bugbounty");
      setTimeout(() => {
        const cb = q("bb-scope-checkbox"); if (cb && !cb.checked) cb.click();
        const ok = fillAndRun(q("bb-target-input"), tgt, false);
        setTimeout(() => q("bb-start") && q("bb-start").click(), 350);
        toast[ok ? "success" : "error"](ok ? `Macro: Bug Bounty scanning ${tgt}` : "Bug Bounty input not found");
      }, 900);
    } else if (id === "surface_scan") {
      nav("/app/scanner");
      setTimeout(() => {
        const ok = fillAndRun(q("scanner-target"), tgt, true);
        toast[ok ? "success" : "error"](ok ? `Macro: Attack Surface scanning ${tgt}` : "Scanner input not found");
      }, 850);
    } else if (id === "netmap_scan") {
      nav("/app/netmap");
      setTimeout(() => {
        const ok = fillAndRun(q("netmap-target"), tgt, true);
        toast[ok ? "success" : "error"](ok ? `Macro: Network scanning ${tgt}` : "Netmap input not found");
      }, 850);
    } else if (id === "osint_lookup") {
      nav("/app/osint");
      setTimeout(() => {
        let el = null;
        for (const idd of OSINT_INPUTS) { const e = document.querySelector(`[data-testid="${idd}"]`); if (e && e.offsetParent !== null) { el = e; break; } }
        const ok = fillAndRun(el, tgt, true);
        toast[ok ? "success" : "error"](ok ? `Macro: OSINT lookup ${tgt}` : "OSINT input not found");
      }, 850);
    } else if (id === "operation") {
      nav("/app/operation");
      setTimeout(() => { const b = q("op-generate"); if (b) b.click(); toast.success("Macro: Operation Report"); }, 850);
    }
  }, []);

  const armVoiceMacro = useCallback((macroId) => {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) { toast.error("Voice not supported in this browser"); return; }
    try { if (captureRecRef.current) captureRecRef.current.stop(); } catch { /* noop */ }
    const rec = new SR();
    rec.lang = "en-US"; rec.interimResults = false; rec.maxAlternatives = 1; rec.continuous = false;
    captureRecRef.current = rec;
    setVoiceCapture({ macroId });
    toast.message("🎤 Listening — say the target", { description: 'e.g. "example dot com" — the macro runs automatically' });
    rec.onresult = (e) => {
      const txt = (e.results[0][0].transcript || "").trim();
      const tgt = parseSpokenTarget(txt);
      if (tgt) {
        setMacroTarget(tgt); macroTargetRef.current = tgt;
        toast.success(`Heard "${txt}" → ${tgt}`);
        setTimeout(() => runMacro(macroId), 350);
      } else {
        toast.error(`Couldn't parse a target from "${txt}"`);
      }
    };
    rec.onerror = () => { toast.error("Voice capture failed — grant mic permission"); };
    rec.onend = () => { setVoiceCapture(null); };
    try { rec.start(); } catch { setVoiceCapture(null); }
  }, [runMacro]);

  const runAction = useCallback((actionId) => {
    if (!actionId || actionId === "none") return;
    if (actionId.startsWith("nav:")) {
      const to = actionId.slice(4);
      navRef.current && navRef.current(to);
      const lbl = (MODULES.find((m) => m.to === to) || {}).label || to;
      toast.success(`Gesture → ${lbl}`);
    } else if (actionId.startsWith("voice:")) {
      armVoiceMacro(actionId.slice(6));
    } else if (actionId.startsWith("macro:")) {
      runMacro(actionId.slice(6));
    }
  }, [runMacro, armVoiceMacro]);
  useEffect(() => { runActionRef.current = runAction; }, [runAction]);

  const [voiceOn, setVoiceOn] = useState(false);
  const voiceRef = useRef(false);
  const recogRef = useRef(null);

  const stopVoice = useCallback(() => {
    voiceRef.current = false;
    setVoiceOn(false);
    try { recogRef.current && recogRef.current.stop(); } catch { /* ignore */ }
  }, []);

  const applyZoom = useCallback((z) => {
    z = Math.max(0.5, Math.min(3, z));
    zoomRef.current = z;
    if (zoomWrapRef.current) zoomWrapRef.current.style.zoom = String(z);
    setHud((h) => ({ ...h, zoom: Math.round(z * 100) / 100 }));
  }, []);

  const zoomStep = useCallback((d) => { twoHandRef.current.base = null; applyZoom(zoomRef.current + d); }, [applyZoom]);

  const resetView = useCallback(() => {
    twoHandRef.current.base = null;
    applyZoom(1);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [applyZoom]);

  const handleVoice = useCallback((t) => {
    let m;
    if (/(stop|band).*(voice|listening|sun)/.test(t) || t.includes("stop listening")) { stopVoice(); toast.info("Voice OFF"); return; }
    // ---- dictation: start a whole scan / lookup hands-free ----
    if ((m = t.match(/^(?:scan|target|assess|check)\s+(.+)/))) {
      const tg = parseTarget(m[1]);
      navRef.current?.("/app/scanner");
      setTimeout(() => {
        const ok = fillAndRun(document.querySelector('[data-testid="scanner-target"]'), tg, true);
        toast[ok ? "success" : "error"](ok ? `Scanning ${tg}…` : "Scanner input not found");
      }, 750);
      return;
    }
    if ((m = t.match(/^(?:osint|lookup|investigate|recon)\s+(.+)/))) {
      const tg = parseTarget(m[1]);
      navRef.current?.("/app/osint");
      setTimeout(() => {
        let el = null;
        for (const id of OSINT_INPUTS) { const e = document.querySelector(`[data-testid="${id}"]`); if (e && e.offsetParent !== null) { el = e; break; } }
        const ok = fillAndRun(el, tg, true);
        toast[ok ? "success" : "error"](ok ? `OSINT lookup: ${tg}` : "OSINT input not found");
      }, 750);
      return;
    }
    if ((m = t.match(/^(?:type|dictate|enter|write|search)\s+(.+)/))) {
      const ae = document.activeElement;
      if (ae && (ae.tagName === "INPUT" || ae.tagName === "TEXTAREA")) { fillAndRun(ae, parseTarget(m[1]), false); toast.success("Dictated"); }
      else toast.error("First pinch-click on an input field");
      return;
    }
    if (/^(run|start scan|start|go|submit|enter)$/.test(t)) {
      const ae = document.activeElement;
      const f = ae && ae.closest && ae.closest("form");
      if (f && f.requestSubmit) { f.requestSubmit(); toast.success("Voice: run"); }
      else { document.querySelector('[data-testid="run-scanner"],[type="submit"]')?.click(); }
      return;
    }
    if (t.includes("clear")) { const ae = document.activeElement; if (ae && (ae.tagName === "INPUT" || ae.tagName === "TEXTAREA")) setNativeValue(ae, ""); return; }
    // ---- zoom / view ----
    if (t.includes("reset zoom") || t.includes("reset view") || t.includes("normal size")) { resetView(); return; }
    if (t.includes("zoom in") || t.includes("bigger")) { zoomStep(0.2); return; }
    if (t.includes("zoom out") || t.includes("smaller")) { zoomStep(-0.2); return; }
    // ---- scroll ----
    if (t.includes("scroll down") || t.includes("neeche")) return window.scrollBy({ top: 480, behavior: "smooth" });
    if (t.includes("scroll up") || t.includes("upar")) return window.scrollBy({ top: -480, behavior: "smooth" });
    if (t.includes("to top") || t.includes("go top")) return window.scrollTo({ top: 0, behavior: "smooth" });
    if (t.includes("bottom")) return window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" });
    // ---- click ----
    if (t.includes("click") || t.includes("tap") || t.includes("select")) {
      const el = document.elementFromPoint(posRef.current.x, posRef.current.y);
      if (el) { el.click(); toast.success("Voice: click"); }
      return;
    }
    // ---- navigation ----
    for (const n of VOICE_NAV) {
      if (n.kw.some((k) => t.includes(k))) { navRef.current?.(n.to); toast.success(`Voice → ${n.label}`); return; }
    }
  }, [stopVoice, resetView, zoomStep]);

  const startVoice = useCallback(() => {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) { toast.error("Voice commands sirf Chrome/Edge me chalte hain"); return; }
    try {
      const r = new SR();
      r.continuous = true; r.interimResults = false; r.lang = "en-US";
      r.onresult = (ev) => {
        const t = ev.results[ev.results.length - 1][0].transcript.toLowerCase().trim();
        setHud((h) => ({ ...h, heard: t }));
        handleVoice(t);
      };
      r.onerror = (e) => {
        if (e.error === "not-allowed" || e.error === "service-not-allowed") { toast.error("Mic permission do"); stopVoice(); }
      };
      r.onend = () => { if (voiceRef.current) { try { r.start(); } catch { /* already started */ } } };
      recogRef.current = r;
      voiceRef.current = true;
      setVoiceOn(true);
      r.start();
      toast.success("Voice ON — say 'scan example.com', 'open toolkit', 'zoom in', 'scroll down', 'stop listening'");
    } catch { toast.error("Voice start fail"); }
  }, [handleVoice, stopVoice]);

  const stop = useCallback(() => {
    runningRef.current = false;
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    const v = videoRef.current;
    if (v && v.srcObject) { v.srcObject.getTracks().forEach((t) => t.stop()); v.srcObject = null; }
    setStream(null);
    setPhase("idle");
  }, []);

  useEffect(() => () => stop(), [stop]);
  useEffect(() => () => stopVoice(), [stopVoice]);

  const acquire = useCallback((id) => {
    const video = id ? { deviceId: { exact: id }, width: 640, height: 480 } : { facingMode: "user", width: 640, height: 480 };
    return navigator.mediaDevices.getUserMedia({ video });
  }, []);

  const refreshCameras = useCallback(async () => {
    try {
      const devs = await navigator.mediaDevices.enumerateDevices();
      const cams = devs.filter((d) => d.kind === "videoinput").map((d, i) => ({ deviceId: d.deviceId, label: d.label || `Camera ${i + 1}` }));
      setCameras(cams);
      return cams;
    } catch { return []; }
  }, []);

  const switchCamera = useCallback(async (id) => {
    setCameraId(id);
    cameraIdRef.current = id;
    if (!runningRef.current) return;
    try {
      const v = videoRef.current;
      if (v && v.srcObject) v.srcObject.getTracks().forEach((t) => t.stop());
      const s = await acquire(id);
      v.srcObject = s; await v.play(); setStream(s);
      toast.success("Camera switched");
    } catch { toast.error("Could not switch to that camera"); }
  }, [acquire]);

  const loop = useCallback(() => {
    if (!runningRef.current) return;
    const v = videoRef.current, c = canvasRef.current;
    if (v && v.readyState >= 2) {
      const draw = expandedRef.current && c;
      let ctx = null;
      if (draw) {
        c.width = v.videoWidth || 640; c.height = v.videoHeight || 480;
        ctx = c.getContext("2d");
        ctx.save();
        ctx.clearRect(0, 0, c.width, c.height);
        ctx.translate(c.width, 0); ctx.scale(-1, 1);
        ctx.drawImage(v, 0, 0, c.width, c.height);
      }
      const du = draw ? new DrawingUtils(ctx) : null;

      let ts = performance.now();
      if (ts <= lastTsRef.current) ts = lastTsRef.current + 1;
      lastTsRef.current = ts;

      const next = { gesture: "—", face: false, blink: false, head: "—", hand: false, pinch: false };

      try {
        const g = grRef.current.recognizeForVideo(v, ts);
        const hands = g.landmarks || [];

        if (hands.length >= 2 && controlRef.current && zoomOnRef.current) {
          // ---- TWO-HAND ZOOM (pinch-to-zoom analog) ----
          next.hand = true;
          next.gesture = "🤲 Zoom";
          if (du) hands.forEach((lm) => du.drawConnectors(lm, GestureRecognizer.HAND_CONNECTIONS, { color: "#38BDF8", lineWidth: 3 }));
          const w0 = hands[0][0], w1 = hands[1][0];
          const dist = Math.hypot(w0.x - w1.x, w0.y - w1.y);
          const th = twoHandRef.current;
          if (th.base == null) { th.base = dist; th.baseZoom = zoomRef.current; }
          else {
            let z = Math.max(0.5, Math.min(3, th.baseZoom * (dist / th.base)));
            zoomRef.current = z;
            if (zoomWrapRef.current) zoomWrapRef.current.style.zoom = String(z);
            next.zoom = Math.round(z * 100) / 100;
          }
          shortcutRef.current.name = null;
          scrollAccelRef.current = 0;
        } else if (hands.length) {
          twoHandRef.current.base = null;
          const lm = hands[0];
          next.hand = true;
          if (du) {
            du.drawConnectors(lm, GestureRecognizer.HAND_CONNECTIONS, { color: "#FACC15", lineWidth: 3 });
            du.drawLandmarks(lm, { color: "#F97316", lineWidth: 1, radius: 4 });
          }
          const gest = g.gestures?.[0]?.[0]?.categoryName || "None";
          next.gesture = GESTURE_LABEL[gest] || gest;

          // gesture shortcut — hold a mapped gesture ~0.9s to run its action/macro
          const shName = ["Closed_Fist", "Victory", "Open_Palm", "ILoveYou"].includes(gest) ? gest : null;
          const scRef = shortcutRef.current;
          const nowMs = performance.now();
          if (shortcutsOnRef.current && shName && nowMs > navCooldownRef.current) {
            const action = gestureMapRef.current[shName];
            if (action && action !== "none") {
              if (scRef.name !== shName) { scRef.name = shName; scRef.start = nowMs; }
              else if (nowMs - scRef.start >= 900) {
                navCooldownRef.current = nowMs + 2500;
                scRef.name = null;
                next.shortcut = `${GESTURE_LABEL[shName] || shName} ▶`;
                runActionRef.current && runActionRef.current(action);
              }
            } else {
              scRef.name = null;
            }
          } else if (!shName) {
            scRef.name = null;
          }

          const idx = lm[8], thumb = lm[4];
          const pinchDist = Math.hypot(idx.x - thumb.x, idx.y - thumb.y);
          const isPinch = pinchDist < 0.06;
          next.pinch = isPinch;

          if (controlRef.current) {
            const tx = remapReach(1 - idx.x, edgeReachRef.current) * window.innerWidth;
            const ty = remapReach(idx.y, edgeReachRef.current) * window.innerHeight;
            posRef.current.x = lerp(posRef.current.x, tx, sensitivityRef.current);
            posRef.current.y = lerp(posRef.current.y, ty, sensitivityRef.current);
            const cur = cursorRef.current;
            if (cur) {
              cur.style.left = `${posRef.current.x}px`;
              cur.style.top = `${posRef.current.y}px`;
              cur.style.transform = `translate(-50%,-50%) scale(${isPinch ? 0.6 : 1})`;
              cur.style.borderColor = isPinch ? "#22C55E" : "#FACC15";
              cur.style.background = isPinch ? "rgba(34,197,94,0.35)" : "rgba(250,204,21,0.12)";
            }
            if (isPinch && !pinchDownRef.current) {
              pinchDownRef.current = true;
              const el = document.elementFromPoint(posRef.current.x, posRef.current.y);
              if (el && cur && !cur.contains(el)) {
                el.click();
                setHud((h) => ({ ...h, clicks: h.clicks + 1 }));
              }
            } else if (!isPinch) {
              pinchDownRef.current = false;
            }
            // accelerating scroll — hold longer = faster
            if (scrollOnRef.current && (gest === "Thumb_Up" || gest === "Thumb_Down")) {
              scrollAccelRef.current = Math.min(scrollAccelRef.current + 1, 40);
              const amt = (16 + scrollAccelRef.current * 2.5) * scrollSpeedRef.current;
              window.scrollBy({ top: gest === "Thumb_Up" ? -amt : amt });
            } else {
              scrollAccelRef.current = 0;
            }
          }
        } else {
          twoHandRef.current.base = null;
          scrollAccelRef.current = 0;
        }
      } catch { /* frame skip */ }

      if (faceRef.current) {
        try {
          const f = flRef.current.detectForVideo(v, ts + 1);
          if (f.faceLandmarks && f.faceLandmarks.length) {
            const fm = f.faceLandmarks[0];
            next.face = true;
            if (du) {
              du.drawConnectors(fm, FaceLandmarker.FACE_LANDMARKS_TESSELATION, { color: "rgba(56,189,248,0.18)", lineWidth: 1 });
              du.drawConnectors(fm, FaceLandmarker.FACE_LANDMARKS_FACE_OVAL, { color: "#38BDF8", lineWidth: 2 });
            }
            const cats = f.faceBlendshapes?.[0]?.categories || [];
            const bl = cats.find((x) => x.categoryName === "eyeBlinkLeft")?.score || 0;
            const br = cats.find((x) => x.categoryName === "eyeBlinkRight")?.score || 0;
            next.blink = bl > 0.5 && br > 0.5;
            const nose = fm[1], lc = fm[234], rc = fm[454];
            const off = nose.x - (lc.x + rc.x) / 2;
            next.head = off < -0.02 ? "→ Right" : off > 0.02 ? "← Left" : "center";
          }
        } catch { /* frame skip */ }
      }

      if (ctx) ctx.restore();

      if (!next.hand) shortcutRef.current.name = null;

      const fp = fpsRef.current; fp.n++;
      const now = performance.now();
      if (now - fp.t >= 500) { fp.fps = Math.round((fp.n * 1000) / (now - fp.t)); fp.n = 0; fp.t = now; }
      setHud((h) => ({ ...h, ...next, fps: fp.fps }));
    }
    rafRef.current = requestAnimationFrame(loop);
  }, []);

  const start = useCallback(async () => {
    setErr(""); setPhase("loading");
    try {
      const vision = await FilesetResolver.forVisionTasks(WASM);
      if (!grRef.current) {
        grRef.current = await GestureRecognizer.createFromOptions(vision, {
          baseOptions: { modelAssetPath: GR_MODEL, delegate: "GPU" },
          runningMode: "VIDEO", numHands: 2,
        });
      }
      if (!flRef.current) {
        flRef.current = await FaceLandmarker.createFromOptions(vision, {
          baseOptions: { modelAssetPath: FL_MODEL, delegate: "GPU" },
          runningMode: "VIDEO", numFaces: 1, outputFaceBlendshapes: true, outputFacialTransformationMatrixes: true,
        });
      }
      const s = await acquire(cameraIdRef.current);
      const v = videoRef.current;
      v.srcObject = s;
      await v.play();
      setStream(s);
      runningRef.current = true;
      setPhase("live");
      refreshCameras();
      toast.success("Gesture engine live — control the whole app with your hand");
      loop();
    } catch (e) {
      setErr(e?.message || String(e));
      setPhase("error");
      toast.error("Camera/model load failed — grant permission and open over https");
    }
  }, [loop, acquire, refreshCameras]);

  const value = {
    phase, err, stream, expanded, setExpanded, faceOn, setFaceOn, controlOn, setControlOn,
    scrollOn, setScrollOn, zoomOn, setZoomOn, shortcutsOn, setShortcutsOn,
    sensitivity, setSensitivity, scrollSpeed, setScrollSpeed,
    edgeReach, setEdgeReach,
    cameras, cameraId, switchCamera, refreshCameras,
    hud, start, stop, videoRef, canvasRef,
    voiceOn, startVoice, stopVoice,
    gestureMap, setGestureMapEntry, macroTarget, setMacroTarget, runAction, voiceCapture, armVoiceMacro,
    resetView, zoomStep,
  };

  return (
    <Ctx.Provider value={value}>
      <div ref={zoomWrapRef} style={{ transformOrigin: "0 0" }}>{children}</div>
      {/* persistent source video (offscreen) */}
      <video ref={videoRef} playsInline muted
        style={{ position: "fixed", width: 1, height: 1, opacity: 0, pointerEvents: "none", bottom: 0, right: 0 }} />
      {/* global gesture cursor */}
      <div ref={cursorRef} aria-hidden data-testid="gesture-cursor"
        style={{ position: "fixed", left: 0, top: 0, width: 46, height: 46, borderRadius: "50%", border: "2px solid #FACC15", background: "rgba(250,204,21,0.12)", boxShadow: "0 0 24px rgba(250,204,21,0.5)", pointerEvents: "none", zIndex: 99999, transform: "translate(-50%,-50%)", display: phase === "live" && controlOn ? "block" : "none", transition: "background 0.08s, border-color 0.08s" }} />
      <GestureWidget />
    </Ctx.Provider>
  );
}

function Dot({ on }) {
  return <span className="w-1.5 h-1.5 rounded-full" style={{ background: on ? "#22C55E" : "#3f3f46" }} />;
}

function GestureWidget() {
  const { phase, start, stop, hud, expanded, setExpanded, controlOn, canvasRef, voiceOn, startVoice, stopVoice, resetView } = useGesture();
  const live = phase === "live";
  const [min, setMin] = useState(true);
  const [pos, setPos] = useState(() => { try { return JSON.parse(localStorage.getItem("insafe_gwpos")) || null; } catch { return null; } });
  const wrapRef = useRef(null);
  const draggedRef = useRef(false);
  const latestPosRef = useRef(null);

  useEffect(() => {
    if (pos && (pos.x > window.innerWidth - 44 || pos.y > window.innerHeight - 44 || pos.x < 0 || pos.y < 0)) {
      setPos(null); try { localStorage.removeItem("insafe_gwpos"); } catch { /* noop */ }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const startDrag = (e) => {
    const el = wrapRef.current; if (!el) return;
    const rect = el.getBoundingClientRect();
    const offX = e.clientX - rect.left, offY = e.clientY - rect.top;
    draggedRef.current = false;
    const move = (ev) => {
      if (Math.abs(ev.clientX - e.clientX) > 3 || Math.abs(ev.clientY - e.clientY) > 3) draggedRef.current = true;
      const x = Math.min(window.innerWidth - rect.width, Math.max(0, ev.clientX - offX));
      const y = Math.min(window.innerHeight - rect.height, Math.max(0, ev.clientY - offY));
      const p = { x, y }; latestPosRef.current = p; setPos(p);
    };
    const up = () => {
      document.removeEventListener("pointermove", move);
      document.removeEventListener("pointerup", up);
      if (draggedRef.current && latestPosRef.current) { try { localStorage.setItem("insafe_gwpos", JSON.stringify(latestPosRef.current)); } catch { /* noop */ } }
      setTimeout(() => { draggedRef.current = false; }, 0);
    };
    document.addEventListener("pointermove", move);
    document.addEventListener("pointerup", up);
  };

  const posStyle = pos ? { left: pos.x, top: pos.y } : undefined;
  const posCls = "fixed z-[9998] select-none touch-none" + (pos ? "" : " bottom-20 md:bottom-6 right-4");

  // --- minimized: small draggable icon that stays out of the way ---
  if (min) {
    return (
      <div ref={wrapRef} data-testid="gesture-widget" className={posCls} style={posStyle}>
        <button data-testid="gesture-fab" onPointerDown={startDrag}
          onClick={() => { if (!draggedRef.current) setMin(false); }}
          title="Gesture control — click to open, drag to move"
          className="relative w-11 h-11 rounded-full border border-primary/40 bg-[#0a0a0a]/80 backdrop-blur-md flex items-center justify-center opacity-50 hover:opacity-100 transition-opacity shadow-[0_0_18px_rgba(250,204,21,0.15)] cursor-grab active:cursor-grabbing">
          <Hand className={`w-5 h-5 ${live ? "text-primary" : "text-zinc-400"}`} />
          {(live || voiceOn) && <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border border-black" style={{ background: live ? "#22C55E" : "#38BDF8" }} />}
        </button>
      </div>
    );
  }

  // --- open panel ---
  return (
    <div ref={wrapRef} data-testid="gesture-widget" className={posCls} style={{ ...posStyle, width: expanded ? 300 : 232 }}>
      <div className="border border-primary/40 bg-[#0a0a0a]/95 backdrop-blur-md shadow-[0_0_30px_rgba(250,204,21,0.15)]">
        {/* header (drag handle) */}
        <div className="flex items-center gap-1.5 px-2.5 h-10 border-b border-border cursor-grab active:cursor-grabbing" onPointerDown={startDrag} data-testid="gesture-widget-drag">
          <GripVertical className="w-3.5 h-3.5 text-zinc-600 shrink-0" />
          <Hand className={`w-4 h-4 ${live ? "text-primary" : "text-zinc-500"}`} />
          <span className="font-mono text-[11px] uppercase tracking-widest text-zinc-300">Gesture</span>
          <span className="flex items-center gap-1 ml-1">
            <Dot on={hud.hand} /><Dot on={hud.pinch} /><Dot on={voiceOn} />
          </span>
          <div className="ml-auto flex items-center gap-0.5" onPointerDown={(e) => e.stopPropagation()}>
            <button data-testid="gesture-widget-voice" onClick={voiceOn ? stopVoice : startVoice}
              className={`p-1 ${voiceOn ? "text-emerald-400" : "text-zinc-400 hover:text-primary"}`} title="Voice commands">
              {voiceOn ? <Mic className="w-3.5 h-3.5" /> : <MicOff className="w-3.5 h-3.5" />}
            </button>
            {live && (
              <button data-testid="gesture-widget-reset" onClick={resetView}
                className="text-zinc-400 hover:text-primary p-1" title="Reset zoom / scroll top">
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            )}
            {live && (
              <button data-testid="gesture-widget-expand" onClick={() => setExpanded((e) => !e)}
                className="text-zinc-400 hover:text-primary p-1" title={expanded ? "Hide preview" : "Show preview"}>
                {expanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
              </button>
            )}
            {live ? (
              <button data-testid="gesture-widget-toggle" onClick={stop}
                className="text-zinc-400 hover:text-severity-critical p-1" title="Stop camera">
                <CameraOff className="w-3.5 h-3.5" />
              </button>
            ) : (
              <button data-testid="gesture-widget-toggle" onClick={start} disabled={phase === "loading"}
                className="text-primary hover:text-yellow-400 p-1 disabled:opacity-50" title="Enable gesture control">
                {phase === "loading" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Camera className="w-3.5 h-3.5" />}
              </button>
            )}
            <button data-testid="gesture-widget-min" onClick={() => setMin(true)}
              className="text-zinc-400 hover:text-primary p-1" title="Minimize">
              <Minus className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* preview (only when expanded + live) */}
        <div style={{ display: expanded && live ? "block" : "none" }}>
          <div className="relative bg-black">
            <canvas ref={canvasRef} data-testid="gesture-widget-canvas" className="w-full block" style={{ maxHeight: 220, objectFit: "contain" }} />
          </div>
          <div className="grid grid-cols-2 gap-px bg-border text-[10px] font-mono">
            <div className="bg-[#0a0a0a] px-2 py-1.5"><span className="text-zinc-500">GEST </span><span className="text-white">{hud.gesture}</span></div>
            <div className="bg-[#0a0a0a] px-2 py-1.5"><span className="text-zinc-500">PINCH </span><span className={hud.pinch ? "text-emerald-400" : "text-zinc-400"}>{hud.pinch ? "CLICK" : "open"}</span></div>
            <div className="bg-[#0a0a0a] px-2 py-1.5"><span className="text-zinc-500">HEAD </span><span className="text-white">{hud.head}</span></div>
            <div className="bg-[#0a0a0a] px-2 py-1.5"><span className="text-zinc-500">FPS </span><span className="text-white">{hud.fps} · {hud.clicks}</span></div>
          </div>
          <div className="px-2 py-1.5 text-[10px] font-mono flex items-center gap-1.5 border-t border-border">
            <Zap className="w-3 h-3 text-primary" /><span className="text-zinc-400 truncate">{hud.shortcut}</span>
            <span className="ml-auto flex items-center gap-1 text-zinc-500"><ZoomIn className="w-3 h-3" />×{hud.zoom}</span>
          </div>
          {voiceOn && (
            <div className="px-2 py-1.5 text-[10px] font-mono flex items-center gap-1.5 border-t border-border">
              <Mic className="w-3 h-3 text-emerald-400" /><span className="text-zinc-400 truncate">{hud.heard || "listening…"}</span>
            </div>
          )}
        </div>

        {/* collapsed / idle hint */}
        {!expanded && (
          <div className="px-3 py-2 space-y-1">
            {live ? (
              <span className="flex items-center gap-2 text-[11px] text-zinc-400 font-mono">
                {controlOn ? <MousePointerClick className="w-3.5 h-3.5 text-primary" /> : <ScanFace className="w-3.5 h-3.5 text-primary" />}
                {hud.gesture} <Gauge className="w-3 h-3 text-zinc-600" /> {hud.fps}fps
              </span>
            ) : (
              <span className="block text-[11px] text-zinc-500 font-mono">
                {phase === "loading" ? "loading models…" : "hand control · tap 📷"}
              </span>
            )}
            {voiceOn && (
              <span className="flex items-center gap-1.5 text-[10px] text-emerald-400/80 font-mono">
                <Mic className="w-3 h-3" /> <span className="truncate">{hud.heard || "listening…"}</span>
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

