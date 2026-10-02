import { useEffect, useRef, useState } from "react";
import { safeHttpUrl } from "@/lib/safeUrl";
import { useGesture, MODULES, MAP_GESTURES, GESTURE_MACROS, GESTURE_VOICE_MACROS } from "@/context/GestureContext";
import { GestureConfigBuilder } from "@/components/GestureConfigBuilder";
import { toast } from "sonner";
import {
  Hand, ScanFace, Camera, CameraOff, MousePointer2, Loader2, Activity,
  Eye, Zap, Fingerprint, MousePointerClick, Gauge, Globe2, Mic, MicOff, ZoomIn, ZoomOut, RotateCcw,
  Video, RefreshCw, SlidersHorizontal, Wifi, MoveVertical,
  Play, Square, Circle, Download, HelpCircle, X, ChevronRight, CheckCircle2, Sparkles,
  Move, Monitor, Terminal, Maximize,
} from "lucide-react";

const TOUR_STEPS = [
  { key: "cursor", label: "Point your index finger to move the cursor", icon: MousePointer2, done: (h) => h.hand },
  { key: "pinch", label: "Pinch thumb + index to click", icon: MousePointerClick, done: (h) => h.pinch },
  { key: "scroll", label: "Thumb up / down to scroll", icon: MoveVertical, done: (h) => /Thumb/.test(h.gesture || "") },
  { key: "zoom", label: "Show both hands, move them apart to zoom", icon: ZoomIn, done: (h) => (h.gesture || "").includes("Zoom") },
  { key: "shortcut", label: "Hold a mapped gesture (e.g. ✊ Fist) to fire its action", icon: Zap, done: (h) => h.shortcut && h.shortcut !== "—" },
];

export default function GestureControl() {
  const {
    phase, err, start, stop, stream, hud, controlOn, setControlOn, faceOn, setFaceOn,
    scrollOn, setScrollOn, zoomOn, setZoomOn, shortcutsOn, setShortcutsOn,
    sensitivity, setSensitivity, scrollSpeed, setScrollSpeed,
    edgeReach, setEdgeReach,
    cameras, cameraId, switchCamera, refreshCameras,
    voiceOn, startVoice, stopVoice, gestureMap, setGestureMapEntry, macroTarget, setMacroTarget, runAction, voiceCapture,
    resetView, zoomStep,
  } = useGesture();
  const selfRef = useRef(null);
  const [webcamUrl, setWebcamUrl] = useState(() => localStorage.getItem("insafe_pubcam") || "");
  const [webcamLive, setWebcamLive] = useState(false);
  const capImgRef = useRef(null);
  const capCanvasRef = useRef(null);
  const recRef = useRef(null);
  const recChunksRef = useRef([]);
  const recTimerRef = useRef(null);
  const [recording, setRecording] = useState(false);

  // onboarding tour
  const [showTour, setShowTour] = useState(false);
  const [tourStep, setTourStep] = useState(0);
  useEffect(() => {
    if (phase === "live" && !localStorage.getItem("insafe_gtour")) { setTourStep(0); setShowTour(true); }
  }, [phase]);
  useEffect(() => {
    if (!showTour) return;
    const step = TOUR_STEPS[tourStep];
    if (step && step.done(hud)) {
      const t = setTimeout(() => setTourStep((s) => Math.min(s + 1, TOUR_STEPS.length)), 450);
      return () => clearTimeout(t);
    }
  }, [hud, showTour, tourStep]);
  const closeTour = () => { setShowTour(false); localStorage.setItem("insafe_gtour", "1"); };
  const startTour = () => { setTourStep(0); setShowTour(true); };

  useEffect(() => () => clearInterval(recTimerRef.current), []);

  const loadWebcam = () => {
    const safe = safeHttpUrl(webcamUrl);
    if (!safe) return toast.error("Enter a valid http(s) webcam stream URL");
    localStorage.setItem("insafe_pubcam", safe);
    setWebcamUrl(safe);
    setWebcamLive(true);
  };

  const snapshot = () => {
    const img = capImgRef.current, cv = capCanvasRef.current;
    if (!img || !img.naturalWidth || !cv) return toast.error("Capture needs a CORS-enabled feed");
    cv.width = img.naturalWidth; cv.height = img.naturalHeight;
    try {
      cv.getContext("2d").drawImage(img, 0, 0, cv.width, cv.height);
      cv.toBlob((b) => {
        if (!b) return toast.error("Snapshot failed");
        const u = URL.createObjectURL(b); const a = document.createElement("a");
        a.href = u; a.download = "insafelabs-webcam.png"; a.click(); URL.revokeObjectURL(u);
        toast.success("Snapshot saved");
      });
    } catch { toast.error("Snapshot blocked — feed isn't CORS-enabled"); }
  };

  const startRec = () => {
    const img = capImgRef.current, cv = capCanvasRef.current;
    if (!img || !img.naturalWidth || !cv) return toast.error("Recording needs a CORS-enabled feed");
    cv.width = img.naturalWidth; cv.height = img.naturalHeight;
    const ctx = cv.getContext("2d");
    try {
      recTimerRef.current = setInterval(() => { try { ctx.drawImage(img, 0, 0, cv.width, cv.height); } catch { /* taint */ } }, 80);
      const stream = cv.captureStream(12);
      const mr = new MediaRecorder(stream, { mimeType: "video/webm" });
      recChunksRef.current = [];
      mr.ondataavailable = (e) => { if (e.data.size) recChunksRef.current.push(e.data); };
      mr.onstop = () => {
        const blob = new Blob(recChunksRef.current, { type: "video/webm" });
        if (blob.size < 200) return toast.error("Clip empty — feed likely not CORS-enabled");
        const u = URL.createObjectURL(blob); const a = document.createElement("a");
        a.href = u; a.download = "insafelabs-webcam.webm"; a.click(); URL.revokeObjectURL(u);
        toast.success("Clip saved");
      };
      recRef.current = mr; mr.start(); setRecording(true);
      toast.success("Recording…");
    } catch { clearInterval(recTimerRef.current); toast.error("Recording not supported / blocked"); }
  };
  const stopRec = () => {
    setRecording(false);
    clearInterval(recTimerRef.current);
    try { if (recRef.current && recRef.current.state !== "inactive") recRef.current.stop(); } catch { /* noop */ }
  };

  useEffect(() => {
    const v = selfRef.current;
    if (!v) return;
    v.srcObject = stream || null;
    if (stream) v.play().catch(() => {});
  }, [stream]);

  const Stat = ({ icon: Icon, label, value, on }) => (
    <div className="flex items-center gap-2 border border-border bg-[#0a0a0a] px-3 py-2">
      <Icon className={`w-4 h-4 ${on ? "text-primary" : "text-zinc-600"}`} />
      <div className="min-w-0">
        <p className="data-label">{label}</p>
        <p className={`font-mono text-sm ${on ? "text-white" : "text-zinc-500"}`}>{value}</p>
      </div>
    </div>
  );

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="gesture-page">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 border border-border bg-[#121212] flex items-center justify-center shrink-0 glow-primary"><Hand className="w-6 h-6 text-primary" /></div>
        <div>
          <p className="data-label mb-1">/ Biometric · Global Gesture Deck</p>
          <h1 className="font-heading text-2xl md:text-3xl font-bold">Face & Hand Gesture Control</h1>
          <p className="text-sm text-zinc-500 mt-1">This engine is now <b className="text-primary">global + powerful</b> across the whole app — index finger moves the cursor, <b className="text-primary">pinch (👌) = click</b>, 👍/👎 = accelerating scroll, <b className="text-primary">🤲 two hands = zoom in/out</b>, ✊/✌ hold = jump to a module. With voice you can even say <b className="text-primary">"scan example.com"</b> to kick off a full scan. 100% on-device.</p>
        </div>
      </div>

      <div className="border border-primary/20 bg-primary/[0.04] p-3 flex items-center gap-2" data-testid="gesture-global-banner">
        <Globe2 className="w-4 h-4 text-primary shrink-0" />
        <p className="text-xs text-zinc-300 font-mono">
          Status: <b className={phase === "live" ? "text-emerald-400" : "text-zinc-500"}>{phase === "live" ? "GLOBAL CONTROL ACTIVE" : phase === "loading" ? "LOADING…" : "OFFLINE"}</b>
          {phase === "live" && " · keep this tab open, otherwise the camera stops"}
        </p>
        <button onClick={startTour} data-testid="gesture-tour-start"
          className="ml-auto text-[11px] font-mono uppercase border border-primary/40 text-primary px-2.5 py-1 hover:bg-primary/10 inline-flex items-center gap-1.5 shrink-0">
          <HelpCircle className="w-3.5 h-3.5" /> Guided Tour
        </button>
      </div>

      <div className="grid lg:grid-cols-[1fr_320px] gap-5">
        {/* Self-view stage */}
        <div className="border border-border bg-black relative overflow-hidden" data-testid="gesture-stage" style={{ minHeight: 360 }}>
          <video ref={selfRef} playsInline muted className="w-full block" style={{ transform: "scaleX(-1)", maxHeight: "70vh", objectFit: "contain", background: "#000" }} />

          {phase !== "live" && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 bg-[#0a0a0a]/90">
              {phase === "loading" ? (
                <><Loader2 className="w-8 h-8 text-primary animate-spin" /><p className="data-label">Loading vision models… (pehli baar 5-10s)</p></>
              ) : (
                <>
                  <ScanFace className="w-10 h-10 text-primary" />
                  <button onClick={start} data-testid="gesture-enable" className="bg-primary text-black font-semibold px-6 py-3 inline-flex items-center gap-2 hover:bg-yellow-500 transition-colors glow-primary">
                    <Camera className="w-4 h-4" /> Enable Gesture Control
                  </button>
                  {phase === "error" && <p className="text-severity-high text-xs font-mono max-w-sm text-center px-4">{err}</p>}
                  <p className="text-[11px] text-zinc-600">Click "Allow" for camera permission · https required</p>
                </>
              )}
            </div>
          )}

          {phase === "live" && (
            <button onClick={stop} data-testid="gesture-stop" className="absolute top-3 right-3 z-10 bg-black/70 border border-border text-zinc-300 hover:text-severity-critical px-3 py-1.5 text-xs font-mono inline-flex items-center gap-1.5">
              <CameraOff className="w-3.5 h-3.5" /> Stop
            </button>
          )}
        </div>

        {/* HUD */}
        <div className="space-y-3">
          <div className="border border-border bg-[#121212] p-4 space-y-2" data-testid="gesture-hud">
            <p className="data-label flex items-center gap-2 mb-1"><Activity className="w-3.5 h-3.5 text-primary" /> Live Telemetry</p>
            <Stat icon={Hand} label="Hand Gesture" value={hud.gesture} on={hud.hand} />
            <Stat icon={MousePointerClick} label="Pinch (click)" value={hud.pinch ? "ACTIVE" : "open"} on={hud.pinch} />
            <Stat icon={ScanFace} label="Face" value={hud.face ? "detected" : "none"} on={hud.face} />
            <Stat icon={Eye} label="Blink" value={hud.blink ? "blink!" : "eyes open"} on={hud.blink} />
            <Stat icon={Fingerprint} label="Head" value={hud.head} on={hud.face} />
            <Stat icon={Gauge} label="FPS · Clicks" value={`${hud.fps} · ${hud.clicks}`} on={phase === "live"} />
          </div>

          <div className="border border-border bg-[#121212] p-4 space-y-2.5" data-testid="gesture-options">
            <p className="data-label mb-1 flex items-center gap-2"><SlidersHorizontal className="w-3.5 h-3.5 text-primary" /> Controls &amp; Sensitivity</p>
            {[
              { on: controlOn, set: setControlOn, icon: MousePointer2, label: "Cursor + pinch-click", tid: "gesture-toggle-control" },
              { on: scrollOn, set: setScrollOn, icon: MoveVertical, label: "Scroll (thumb up / down)", tid: "gesture-toggle-scroll" },
              { on: zoomOn, set: setZoomOn, icon: ZoomIn, label: "Two-hand zoom", tid: "gesture-toggle-zoom" },
              { on: shortcutsOn, set: setShortcutsOn, icon: Zap, label: "Gesture shortcuts (fist / victory)", tid: "gesture-toggle-shortcuts" },
              { on: faceOn, set: setFaceOn, icon: ScanFace, label: "Face mesh tracking", tid: "gesture-toggle-face" },
            ].map((r) => (
              <label key={r.tid} className="flex items-center justify-between text-sm text-zinc-300 cursor-pointer">
                <span className="flex items-center gap-2"><r.icon className="w-4 h-4 text-primary" /> {r.label}</span>
                <input type="checkbox" checked={r.on} onChange={(e) => r.set(e.target.checked)} data-testid={r.tid} className="accent-primary w-4 h-4" />
              </label>
            ))}
            <div className="border-t border-border pt-2.5 space-y-2.5">
              <div>
                <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 mb-1"><span>Cursor sensitivity</span><span className="text-primary">{Math.round(sensitivity * 100)}%</span></div>
                <input type="range" min="0.15" max="0.6" step="0.05" value={sensitivity} onChange={(e) => setSensitivity(parseFloat(e.target.value))} data-testid="gesture-sensitivity" className="w-full accent-primary" />
              </div>
              <div>
                <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 mb-1"><span>Scroll speed</span><span className="text-primary">×{scrollSpeed.toFixed(1)}</span></div>
                <input type="range" min="0.5" max="3" step="0.5" value={scrollSpeed} onChange={(e) => setScrollSpeed(parseFloat(e.target.value))} data-testid="gesture-scrollspeed" className="w-full accent-primary" />
              </div>
              <div>
                <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 mb-1">
                  <span className="flex items-center gap-1.5"><Maximize className="w-3.5 h-3.5 text-primary" /> Edge reach</span>
                  <span className="text-primary">{Math.round(edgeReach * 100)}%</span>
                </div>
                <input type="range" min="0" max="0.3" step="0.05" value={edgeReach} onChange={(e) => setEdgeReach(parseFloat(e.target.value))} data-testid="gesture-edgereach" className="w-full accent-primary" />
                <p className="text-[10px] text-zinc-600 font-mono mt-1">Higher = a small hand move reaches screen corners, so your hand never has to leave the camera frame (where tracking is lost).</p>
              </div>
            </div>
          </div>

          {/* Camera source */}
          <div className="border border-border bg-[#121212] p-4 space-y-2" data-testid="gesture-camera-source">
            <p className="data-label flex items-center gap-2"><Video className="w-3.5 h-3.5 text-primary" /> Camera Source</p>
            <div className="flex items-center gap-2">
              <select value={cameraId} onChange={(e) => switchCamera(e.target.value)} data-testid="gesture-camera-select"
                className="bg-[#0a0a0a] border border-border text-xs text-white px-2 py-1.5 flex-1 min-w-0 outline-none focus:border-primary/50">
                <option value="">Default (front webcam)</option>
                {cameras.map((c) => <option key={c.deviceId} value={c.deviceId}>{c.label}</option>)}
              </select>
              <button onClick={refreshCameras} data-testid="gesture-camera-refresh" title="Detect cameras"
                className="border border-border p-2 text-zinc-400 hover:text-primary hover:border-primary/50"><RefreshCw className="w-3.5 h-3.5" /></button>
            </div>
            <p className="text-[10px] text-zinc-600 font-mono">Pick any connected webcam — built-in, USB or external. Enable control first so the browser reveals camera labels.</p>
          </div>

          <div className="border border-primary/20 bg-primary/[0.04] p-4">
            <p className="data-label text-primary mb-2 flex items-center gap-1.5"><Zap className="w-3.5 h-3.5" /> Gesture Legend</p>
            <ul className="text-[12px] text-zinc-400 space-y-1 font-mono">
              <li>☝ index finger → cursor move</li>
              <li>👌 pinch (thumb+index) → click/touch</li>
              <li>👍 thumb up → scroll up (accelerates)</li>
              <li>👎 thumb down → scroll down</li>
              <li>🤲 two hands apart/close → zoom in / out</li>
              <li>✊ fist (hold) → jump to module</li>
              <li>✌ victory (hold) → jump to module</li>
            </ul>
          </div>

          {/* Zoom / view controls */}
          <div className="border border-border bg-[#121212] p-4 space-y-2" data-testid="gesture-zoom">
            <p className="data-label flex items-center gap-2"><ZoomIn className="w-3.5 h-3.5 text-primary" /> Zoom &amp; View</p>
            <div className="flex items-center gap-2">
              <button onClick={() => zoomStep(-0.2)} data-testid="gesture-zoom-out" className="flex-1 border border-border py-2 text-zinc-300 hover:text-primary hover:border-primary/50 inline-flex items-center justify-center gap-1.5 text-sm"><ZoomOut className="w-4 h-4" /> Out</button>
              <span className="font-mono text-sm text-white tabular-nums w-14 text-center" data-testid="gesture-zoom-level">×{hud.zoom}</span>
              <button onClick={() => zoomStep(0.2)} data-testid="gesture-zoom-in" className="flex-1 border border-border py-2 text-zinc-300 hover:text-primary hover:border-primary/50 inline-flex items-center justify-center gap-1.5 text-sm"><ZoomIn className="w-4 h-4" /> In</button>
            </div>
            <button onClick={resetView} data-testid="gesture-reset-view" className="w-full border border-border py-2 text-zinc-300 hover:text-primary hover:border-primary/50 inline-flex items-center justify-center gap-1.5 text-sm"><RotateCcw className="w-4 h-4" /> Reset View</button>
          </div>

          {/* Hands-free extras: voice + gesture shortcuts */}
          <div className="border border-border bg-[#121212] p-4 space-y-3" data-testid="gesture-extras">
            <p className="data-label flex items-center gap-2"><Mic className="w-3.5 h-3.5 text-primary" /> Voice Commands</p>
            <button onClick={voiceOn ? stopVoice : startVoice} data-testid="gesture-voice-toggle"
              className={`w-full inline-flex items-center justify-center gap-2 py-2.5 text-sm font-semibold transition-colors ${
                voiceOn ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/40" : "bg-primary text-black hover:bg-yellow-500"}`}>
              {voiceOn ? <><MicOff className="w-4 h-4" /> Stop Listening</> : <><Mic className="w-4 h-4" /> Enable Voice</>}
            </button>
            {voiceOn && <p className="text-[11px] font-mono text-zinc-500">heard: <span className="text-emerald-400">{hud.heard || "…"}</span></p>}
            <p className="text-[11px] text-zinc-500 font-mono leading-relaxed">
              Try: "scan example.com", "osint user@site.com", "open toolkit", "type &lt;text&gt;", "run", "zoom in / out", "scroll down", "click", "stop listening"
            </p>

            <div className="border-t border-border pt-3 space-y-2" data-testid="gesture-mapping">
              <p className="data-label flex items-center gap-2"><Zap className="w-3.5 h-3.5 text-primary" /> Gesture Mapping &amp; Macros</p>
              <label className="flex items-center gap-2 text-[11px] text-zinc-400">
                <span className="font-mono shrink-0">Macro target</span>
                <input value={macroTarget} onChange={(e) => setMacroTarget(e.target.value)} data-testid="gesture-macro-target"
                  placeholder="example.com" className="bg-[#0a0a0a] border border-border text-xs text-white px-2 py-1.5 flex-1 min-w-0 outline-none focus:border-primary/50 font-mono" />
              </label>
              {voiceCapture && (
                <div className="flex items-center gap-2 border border-primary/40 bg-primary/10 px-2 py-1.5 text-[11px] text-primary font-mono animate-pulse" data-testid="gesture-voice-capture">
                  <Mic className="w-3.5 h-3.5" /> Listening — say the target…
                </div>
              )}
              {MAP_GESTURES.map((g) => (
                <div key={g.key} className="flex items-center gap-2">
                  <span className="font-mono text-sm text-zinc-300 w-20 shrink-0">{g.label}</span>
                  <select value={gestureMap[g.key] || "none"} onChange={(e) => setGestureMapEntry(g.key, e.target.value)} data-testid={`gesture-map-${g.key}`}
                    className="bg-[#0a0a0a] border border-border text-xs text-white px-2 py-1.5 flex-1 min-w-0 outline-none focus:border-primary/50">
                    <option value="none">(disabled)</option>
                    <optgroup label="Voice combo">
                      {GESTURE_VOICE_MACROS.map((v) => <option key={v.id} value={v.id}>{v.label}</option>)}
                    </optgroup>
                    <optgroup label="Macros">
                      {GESTURE_MACROS.map((mac) => <option key={mac.id} value={mac.id}>{mac.label}</option>)}
                    </optgroup>
                    <optgroup label="Open module">
                      {MODULES.map((m) => <option key={m.to} value={`nav:${m.to}`}>{m.label}</option>)}
                    </optgroup>
                  </select>
                  <button onClick={() => runAction(gestureMap[g.key])} disabled={!gestureMap[g.key] || gestureMap[g.key] === "none"} data-testid={`gesture-map-run-${g.key}`}
                    title="Run now" className="border border-border p-1.5 text-zinc-400 hover:text-primary hover:border-primary/50 disabled:opacity-40 shrink-0"><Play className="w-3.5 h-3.5" /></button>
                </div>
              ))}
              <p className="text-[11px] text-zinc-600 font-mono">Hold a gesture ~1s to fire its action. A 🎤 Voice option arms the mic so you can speak the target hands-free.</p>
            </div>
          </div>
        </div>
      </div>

      {/* Native PC (OS-level) control — downloadable Python script */}
      <div className="border border-primary/30 bg-primary/[0.04] p-5 space-y-4" data-testid="gesture-pc-control">
        <div className="flex items-start gap-3 flex-wrap">
          <div className="w-10 h-10 border border-primary/40 bg-[#121212] flex items-center justify-center shrink-0"><Monitor className="w-5 h-5 text-primary" /></div>
          <div className="min-w-0">
            <p className="data-label text-primary mb-1 flex items-center gap-2"><Terminal className="w-3.5 h-3.5" /> Control Your Whole PC (OS-level) · PRO</p>
            <p className="text-sm text-zinc-300 max-w-2xl">The in-browser deck can only control this web app. To control your <b className="text-primary">entire computer</b> (any app, the desktop, files, the terminal) with the same hand gestures, download and run this native script. It's <b className="text-primary">fully config-driven</b> — map any gesture to your own apps, hotkeys, text, media keys, screenshots and window controls via a simple JSON file.</p>
          </div>
          <div className="ml-auto flex flex-col gap-2 shrink-0">
            <a href={`${process.env.REACT_APP_BACKEND_URL}/api/offensive/gesture/local-script`}
              download="insafelabs_pc_control.py" data-testid="gesture-pc-download"
              className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center gap-2 hover:bg-yellow-500 transition-colors">
              <Download className="w-4 h-4" /> Download PC Control Script
            </a>
            <a href={`${process.env.REACT_APP_BACKEND_URL}/api/offensive/gesture/local-config`}
              download="insafelabs_gestures.json" data-testid="gesture-pc-config-download"
              className="border border-primary/40 text-primary px-4 py-2 inline-flex items-center justify-center gap-2 hover:bg-primary/10 transition-colors text-sm">
              <SlidersHorizontal className="w-4 h-4" /> Download Sample Config
            </a>
          </div>
        </div>

        <div className="grid md:grid-cols-2 gap-3">
          <div className="border border-border bg-[#0a0a0a] p-4 space-y-2">
            <p className="data-label flex items-center gap-2"><Terminal className="w-3.5 h-3.5 text-primary" /> Setup &amp; Run</p>
            <ol className="text-[12px] text-zinc-400 space-y-1.5 font-mono list-decimal list-inside">
              <li>Install Python 3.9–3.12 on your PC.</li>
              <li>Install deps:<br /><span className="text-primary select-all">pip install opencv-python mediapipe pyautogui numpy</span></li>
              <li>Run it:<br /><span className="text-primary select-all">python insafelabs_pc_control.py</span></li>
              <li>It auto-writes <span className="text-zinc-300">insafelabs_gestures.json</span> — edit it, then press <b className="text-primary">r</b> in the window to hot-reload.</li>
              <li>In-window keys: <span className="text-zinc-300">q quit · p pause · r reload · h help</span></li>
            </ol>
            <p className="text-[10px] text-zinc-600 font-mono">macOS: grant Terminal Accessibility + Camera. Linux: <span className="select-all">sudo apt install scrot python3-tk</span>. Flags: --camera 1 · --edge-reach 0.2 · --gestures</p>
          </div>
          <div className="border border-border bg-[#0a0a0a] p-4 space-y-1.5">
            <p className="data-label flex items-center gap-2"><Move className="w-3.5 h-3.5 text-primary" /> Default Map <span className="text-zinc-600 normal-case">(all re-bindable)</span></p>
            <ul className="text-[12px] text-zinc-400 space-y-1 font-mono">
              <li>☝ index → move real mouse · 👌 pinch → click · pinch-hold → drag</li>
              <li>👍 / 👎 → scroll (accelerates) · 🖐 palm → right click</li>
              <li>✊ fist → screenshot · ✌ victory → switch window</li>
              <li>3 fingers → Ctrl+C · 4 → play/pause · 🤙 call-me → launch app</li>
              <li>🤟 rock/pinky → volume · 🤞 L-shape → paste · 🕷 spiderman → pause</li>
            </ul>
            <p className="text-[10px] text-primary font-mono pt-1">Actions you can bind: click · hotkey · type text · launch app · media keys · screenshot · window min/max/close · scroll · pause.</p>
            <p className="text-[10px] text-severity-medium font-mono">Safety: slam the mouse to the TOP-LEFT corner to abort. Press <b>q</b> to quit.</p>
          </div>
        </div>
      </div>

      <GestureConfigBuilder />

      <div className="border border-border bg-[#121212] p-5 space-y-3" data-testid="gesture-pubcam">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="data-label flex items-center gap-2"><Wifi className="w-3.5 h-3.5 text-primary" /> Public Webcam Feed <span className="text-zinc-600 normal-case">(view-only)</span></p>
          {webcamLive && (
            <div className="ml-auto flex items-center gap-2">
              <button onClick={snapshot} data-testid="gesture-pubcam-snapshot"
                className="border border-border px-2.5 py-1 text-[11px] text-zinc-300 hover:text-primary hover:border-primary/50 inline-flex items-center gap-1.5"><Camera className="w-3.5 h-3.5" /> Snapshot</button>
              <button onClick={recording ? stopRec : startRec} data-testid="gesture-pubcam-record"
                className={`border px-2.5 py-1 text-[11px] inline-flex items-center gap-1.5 ${recording ? "border-severity-critical/50 text-severity-critical animate-pulse" : "border-border text-zinc-300 hover:text-primary hover:border-primary/50"}`}>
                {recording ? <><Square className="w-3.5 h-3.5" /> Stop</> : <><Circle className="w-3.5 h-3.5" /> Record</>}
              </button>
            </div>
          )}
        </div>
        <div className="flex flex-col sm:flex-row gap-2">
          <input value={webcamUrl} onChange={(e) => setWebcamUrl(e.target.value)} data-testid="gesture-pubcam-url"
            placeholder="http://<ip>/mjpg/video.mjpg  ·  http://<ip>/axis-cgi/mjpg/video.cgi"
            className="flex-1 bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-primary" />
          <button onClick={loadWebcam} data-testid="gesture-pubcam-load" className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500">
            <Video className="w-4 h-4" /> Load Feed
          </button>
          {webcamLive && <button onClick={() => { setWebcamLive(false); stopRec(); }} data-testid="gesture-pubcam-stop" className="border border-border px-4 py-2.5 text-sm text-zinc-300 hover:text-severity-critical">Stop</button>}
        </div>
        {webcamLive ? (
          <div className="border border-border bg-black relative" data-testid="gesture-pubcam-view">
            <img src={safeHttpUrl(webcamUrl)} alt="public webcam feed" className="w-full block" style={{ maxHeight: "60vh", objectFit: "contain" }}
              onError={() => toast.error("Feed failed to load — offline, blocked by CORS, or an RTSP URL (not browser-playable).")} />
            <img ref={capImgRef} src={safeHttpUrl(webcamUrl)} alt="" crossOrigin="anonymous" className="hidden" aria-hidden />
            <canvas ref={capCanvasRef} className="hidden" />
          </div>
        ) : (
          <p className="text-sm text-zinc-600">Paste a public MJPEG/HTTP camera stream (e.g. an authorized camera's <span className="font-mono text-zinc-400">/mjpg/video.mjpg</span>). Browsers can't play RTSP directly — for those, use the Network Mapper's RTSP URLs with VLC / ffplay.</p>
        )}
        <p className="text-[10px] text-zinc-600 font-mono">Authorized / public feeds only. Snapshot &amp; record require a CORS-enabled feed.</p>
      </div>

      {/* Onboarding tour overlay */}
      {showTour && (
        <div className="fixed inset-0 z-[9997] flex items-end sm:items-center justify-center p-4 bg-black/60 backdrop-blur-sm" data-testid="gesture-tour">
          <div className="w-full max-w-md border border-primary/40 bg-[#0a0a0a] shadow-[0_0_40px_rgba(250,204,21,0.2)]">
            <div className="flex items-center gap-2 px-4 h-11 border-b border-border">
              <ScanFace className="w-4 h-4 text-primary" />
              <span className="font-heading text-sm font-semibold">Gesture Tutorial</span>
              <span className="ml-auto data-label text-zinc-500">{Math.min(tourStep, TOUR_STEPS.length)}/{TOUR_STEPS.length}</span>
              <button onClick={closeTour} data-testid="gesture-tour-close" className="text-zinc-500 hover:text-white p-1"><X className="w-4 h-4" /></button>
            </div>
            <div className="p-5 space-y-4">
              {tourStep >= TOUR_STEPS.length ? (
                <div className="text-center space-y-3" data-testid="gesture-tour-done">
                  <Sparkles className="w-8 h-8 text-primary mx-auto" />
                  <p className="text-zinc-200">You're all set — every core gesture works. Control the whole app hands-free.</p>
                  <button onClick={closeTour} className="bg-primary text-black font-semibold px-5 py-2">Finish</button>
                </div>
              ) : (
                <>
                  {(() => { const S = TOUR_STEPS[tourStep]; const Icon = S.icon; return (
                    <div className="flex items-center gap-3 border border-primary/30 bg-primary/5 p-3">
                      <Icon className="w-6 h-6 text-primary shrink-0" />
                      <div>
                        <p className="text-sm text-white">{S.label}</p>
                        <p className="text-[11px] font-mono text-zinc-500">{phase === "live" ? (S.done(hud) ? "detected ✓" : "waiting for you to perform…") : "enable the camera to begin"}</p>
                      </div>
                    </div>
                  ); })()}
                  <div className="space-y-1">
                    {TOUR_STEPS.map((s, i) => (
                      <div key={s.key} className={`flex items-center gap-2 text-[12px] font-mono ${i < tourStep ? "text-emerald-400" : i === tourStep ? "text-zinc-200" : "text-zinc-600"}`}>
                        {i < tourStep ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Circle className="w-3.5 h-3.5" />} {s.label}
                      </div>
                    ))}
                  </div>
                  <div className="flex gap-2">
                    <button onClick={closeTour} data-testid="gesture-tour-skip" className="flex-1 border border-border py-2 text-sm text-zinc-400 hover:text-white">Skip</button>
                    <button onClick={() => setTourStep((s) => Math.min(s + 1, TOUR_STEPS.length))} data-testid="gesture-tour-next" className="flex-1 bg-primary text-black font-semibold py-2 text-sm inline-flex items-center justify-center gap-1">Next <ChevronRight className="w-4 h-4" /></button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Control playground — touch these with the gesture cursor + pinch */}
      <div className="border border-border bg-[#121212] p-5" data-testid="gesture-playground">
        <p className="data-label mb-3">Try it — touch these with your hand (pinch)</p>
        <Playground />
      </div>
    </div>
  );
}

function Playground() {
  const [count, setCount] = useState(0);
  const [lit, setLit] = useState(-1);
  const colors = ["#FACC15", "#F97316", "#38BDF8", "#22C55E", "#EF4444", "#A855F7"];
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4 flex-wrap">
        <button onClick={() => setCount((c) => c + 1)} data-testid="pg-counter" className="bg-primary text-black font-semibold px-5 py-3 hover:bg-yellow-500 transition-colors">Tap me +1</button>
        <span className="font-mono text-2xl text-white tabular-nums" data-testid="pg-count">{count}</span>
        <button onClick={() => setCount(0)} data-testid="pg-reset" className="border border-border px-4 py-3 text-sm text-zinc-300 hover:text-severity-medium hover:border-severity-medium/50 transition-colors">Reset</button>
      </div>
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
        {colors.map((c, i) => (
          <button key={i} onClick={() => setLit(i)} data-testid={`pg-tile-${i}`}
            className="h-20 border transition-all" style={{ borderColor: c + "66", background: lit === i ? c : c + "1a", boxShadow: lit === i ? `0 0 22px ${c}88` : "none" }} />
        ))}
      </div>
    </div>
  );
}
