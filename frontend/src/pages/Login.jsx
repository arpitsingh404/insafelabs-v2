import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import * as THREE from "three";
import { motion, AnimatePresence } from "framer-motion";
import { Lock, Terminal, Loader2, ShieldAlert, ArrowRight, Radio } from "lucide-react";
import { api, setToken, formatApiError } from "@/lib/api";

const NOISE = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")";

/* soft radial sprite for nebula points */
function nebulaTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d");
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, "rgba(255,255,255,0.9)");
  grad.addColorStop(0.35, "rgba(255,255,255,0.25)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 64, 64);
  const tex = new THREE.CanvasTexture(c);
  return tex;
}

const Corner = ({ pos }) => (
  <span className={`absolute ${pos} w-4 h-4 border-primary pointer-events-none`} style={{
    borderTopWidth: pos.includes("top") ? 2 : 0,
    borderBottomWidth: pos.includes("bottom") ? 2 : 0,
    borderLeftWidth: pos.includes("left") ? 2 : 0,
    borderRightWidth: pos.includes("right") ? 2 : 0,
  }} />
);

export default function Login() {
  const navigate = useNavigate();
  const mountRef = useRef(null);
  const engineRef = useRef({ speed: 4, target: 4, warp: false });
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [warping, setWarping] = useState(false);
  const [lockUntil, setLockUntil] = useState(0);
  const [lockLeft, setLockLeft] = useState(0);

  useEffect(() => {
    if (!lockUntil) { setLockLeft(0); return; }
    const tick = () => {
      const left = Math.max(0, Math.ceil((lockUntil - Date.now()) / 1000));
      setLockLeft(left);
      if (left <= 0) { setLockUntil(0); setError(""); }
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [lockUntil]);

  const locked = lockLeft > 0;
  const mmss = `${String(Math.floor(lockLeft / 60)).padStart(2, "0")}:${String(lockLeft % 60).padStart(2, "0")}`;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    let w = mount.clientWidth || window.innerWidth;
    let h = mount.clientHeight || window.innerHeight;

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x040404, 0.00055);
    const BASE_FOV = 78;
    const camera = new THREE.PerspectiveCamera(BASE_FOV, w / h, 1, 3600);
    camera.position.set(0, 0, 1);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(w, h);
    mount.appendChild(renderer.domElement);

    // ---- warp star STREAKS (LineSegments: short at rest, elongate on warp) ----
    const N = 1500;
    const stars = new Array(N);
    const linePos = new Float32Array(N * 6);
    const lineCol = new Float32Array(N * 6);
    const cWhite = new THREE.Color(0xffffff);
    const cGold = new THREE.Color(0xfacc15);
    const cGreen = new THREE.Color(0x22c55e);
    for (let i = 0; i < N; i++) {
      const x = (Math.random() - 0.5) * 1800;
      const y = (Math.random() - 0.5) * 1800;
      const z = -Math.random() * 3000;
      stars[i] = { x, y, z };
      const r = Math.random();
      const col = r < 0.13 ? cGold : r < 0.19 ? cGreen : cWhite;
      const o = i * 6;
      lineCol[o] = col.r; lineCol[o + 1] = col.g; lineCol[o + 2] = col.b;
      lineCol[o + 3] = col.r * 0.2; lineCol[o + 4] = col.g * 0.2; lineCol[o + 5] = col.b * 0.2;
    }
    const lineGeo = new THREE.BufferGeometry();
    lineGeo.setAttribute("position", new THREE.BufferAttribute(linePos, 3));
    lineGeo.setAttribute("color", new THREE.BufferAttribute(lineCol, 3));
    const lineMat = new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.92, blending: THREE.AdditiveBlending, depthWrite: false });
    const streaks = new THREE.LineSegments(lineGeo, lineMat);
    scene.add(streaks);

    // ---- nebula (soft additive point cloud, amber/emerald) ----
    const NEB = 260;
    const nebPos = new Float32Array(NEB * 3);
    const nebCol = new Float32Array(NEB * 3);
    for (let i = 0; i < NEB; i++) {
      nebPos[i * 3] = (Math.random() - 0.5) * 2600;
      nebPos[i * 3 + 1] = (Math.random() - 0.5) * 1600;
      nebPos[i * 3 + 2] = -300 - Math.random() * 2200;
      const col = Math.random() < 0.6 ? cGold : cGreen;
      nebCol[i * 3] = col.r; nebCol[i * 3 + 1] = col.g; nebCol[i * 3 + 2] = col.b;
    }
    const nebGeo = new THREE.BufferGeometry();
    nebGeo.setAttribute("position", new THREE.BufferAttribute(nebPos, 3));
    nebGeo.setAttribute("color", new THREE.BufferAttribute(nebCol, 3));
    const nebTex = nebulaTexture();
    const nebMat = new THREE.PointsMaterial({ size: 220, map: nebTex, vertexColors: true, transparent: true, opacity: 0.05, depthWrite: false, blending: THREE.AdditiveBlending });
    const nebula = new THREE.Points(nebGeo, nebMat);
    scene.add(nebula);

    // ---- holographic wireframe cyber globe ----
    const globe = new THREE.Mesh(
      new THREE.IcosahedronGeometry(150, 2),
      new THREE.MeshBasicMaterial({ color: 0xfacc15, wireframe: true, transparent: true, opacity: 0.16, blending: THREE.AdditiveBlending, depthWrite: false })
    );
    globe.position.set(0, 0, -1000);
    globe.rotation.x = 0.5;
    scene.add(globe);
    const grid = new THREE.Mesh(
      new THREE.SphereGeometry(118, 30, 18),
      new THREE.MeshBasicMaterial({ color: 0x22c55e, wireframe: true, transparent: true, opacity: 0.07, blending: THREE.AdditiveBlending, depthWrite: false })
    );
    grid.position.set(0, 0, -1000);
    scene.add(grid);

    // ---- mouse parallax ----
    let tmx = 0, tmy = 0, mx = 0, my = 0;
    const onMove = (e) => {
      tmx = (e.clientX / window.innerWidth - 0.5);
      tmy = (e.clientY / window.innerHeight - 0.5);
    };
    window.addEventListener("pointermove", onMove);

    const clock = new THREE.Clock();
    let raf;
    const animate = () => {
      const dt = Math.min(0.05, clock.getDelta());
      const f = dt * 60; // frame-rate normalization
      const e = engineRef.current;
      e.target = e.warp ? 320 : 4;
      e.speed += (e.target - e.speed) * 0.06 * f;
      const streakLen = Math.max(2.4, e.speed * 1.05);

      for (let i = 0; i < N; i++) {
        const d = stars[i];
        d.z += e.speed * f;
        if (d.z > 60) {
          d.x = (Math.random() - 0.5) * 1800;
          d.y = (Math.random() - 0.5) * 1800;
          d.z = -3000;
        }
        const o = i * 6;
        linePos[o] = d.x; linePos[o + 1] = d.y; linePos[o + 2] = d.z;
        linePos[o + 3] = d.x; linePos[o + 4] = d.y; linePos[o + 5] = d.z - streakLen;
      }
      lineGeo.attributes.position.needsUpdate = true;

      globe.rotation.y += 0.0016 * f; grid.rotation.y -= 0.0024 * f;
      nebula.rotation.z += 0.00015 * f;

      mx += (tmx - mx) * 0.045 * f; my += (tmy - my) * 0.045 * f;
      camera.position.x = mx * 42; camera.position.y = -my * 42;
      camera.lookAt(0, 0, -400);

      if (e.warp) {
        camera.fov += (122 - camera.fov) * 0.03 * f;
        camera.updateProjectionMatrix();
      }
      renderer.render(scene, camera);
      raf = requestAnimationFrame(animate);
    };
    animate();

    const onResize = () => {
      w = mount.clientWidth; h = mount.clientHeight;
      camera.aspect = w / h; camera.updateProjectionMatrix(); renderer.setSize(w, h);
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("pointermove", onMove);
      lineGeo.dispose(); lineMat.dispose();
      nebGeo.dispose(); nebMat.dispose(); nebTex.dispose();
      globe.geometry.dispose(); globe.material.dispose();
      grid.geometry.dispose(); grid.material.dispose();
      renderer.dispose();
      if (renderer.domElement.parentNode) renderer.domElement.parentNode.removeChild(renderer.domElement);
    };
  }, []);

  const submit = async (ev) => {
    ev.preventDefault();
    if (!password.trim() || loading || warping || locked) return;
    setLoading(true); setError("");
    try {
      const { data } = await api.post("/auth/login", { password });
      setToken(data.token);
      if (data.previous_login && (data.previous_login.at || data.previous_login.ip)) {
        localStorage.setItem("insafelabs_prev_login", JSON.stringify(data.previous_login));
      }
      setWarping(true);
      engineRef.current.warp = true;
      setTimeout(() => navigate("/app"), 1350);
    } catch (err) {
      setError(formatApiError(err.response?.data?.detail) || "Access denied");
      if (err.response?.status === 429) {
        const ra = parseInt(err.response?.headers?.["retry-after"] || "0", 10);
        if (ra > 0) setLockUntil(Date.now() + ra * 1000);
      }
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-[#040404] text-white overflow-hidden" data-testid="login-page">
      <div ref={mountRef} className="absolute inset-0" />

      {/* vignette + scanlines */}
      <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(circle at 50% 46%, transparent 28%, rgba(4,4,4,0.65) 78%, #040404 100%)" }} />
      <div className="absolute inset-0 pointer-events-none opacity-[0.5]" style={{ backgroundImage: "repeating-linear-gradient(transparent, transparent 2px, rgba(0,0,0,0.22) 2px, rgba(0,0,0,0.22) 4px)" }} />

      {/* slow targeting reticle behind card */}
      <motion.div
        className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none"
        animate={{ rotate: 360 }} transition={{ duration: 60, repeat: Infinity, ease: "linear" }}
        style={{ opacity: warping ? 0 : 0.12 }}
      >
        <svg width="620" height="620" viewBox="0 0 620 620" fill="none" stroke="#22C55E" strokeWidth="1">
          <circle cx="310" cy="310" r="300" strokeDasharray="4 10" />
          <circle cx="310" cy="310" r="220" strokeDasharray="2 14" />
          <line x1="310" y1="0" x2="310" y2="40" /><line x1="310" y1="580" x2="310" y2="620" />
          <line x1="0" y1="310" x2="40" y2="310" /><line x1="580" y1="310" x2="620" y2="310" />
        </svg>
      </motion.div>

      {/* corner HUD readouts */}
      <AnimatePresence>
        {!warping && (
          <motion.div exit={{ opacity: 0 }} className="absolute inset-0 pointer-events-none font-mono text-[10px] tracking-widest uppercase text-emerald-500/40">
            <span className="absolute top-5 left-6" data-testid="hud-tl">SYS.NODE // INSAFE-01</span>
            <span className="absolute top-5 right-6" data-testid="hud-tr">CRYPTO // AES-256-GCM</span>
            <span className="absolute bottom-5 left-6" data-testid="hud-bl">CHANNEL // <span className="text-primary/60">SECURE</span></span>
            <span className="absolute bottom-5 right-6" data-testid="hud-br">LINK ▮▮▮▮▮ <span className="animate-pulse">▮</span></span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* card */}
      <div className="relative z-10 min-h-full flex items-center justify-center px-5">
        <AnimatePresence>
          {!warping && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 22 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.8 }}
              transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
              className="w-full max-w-md"
            >
              <motion.div
                animate={error ? { x: [0, -11, 11, -8, 8, 0] } : { x: 0 }}
                transition={{ duration: 0.42 }}
                className="relative bg-[#0a0a0a]/45 backdrop-blur-2xl p-8 sm:p-10 border border-primary/20"
                style={{ boxShadow: "0 0 46px -10px rgba(250,204,21,0.16), inset 0 0 24px -12px rgba(250,204,21,0.12)" }}
              >
                {/* grain */}
                <div className="absolute inset-0 pointer-events-none" style={{ backgroundImage: NOISE, mixBlendMode: "overlay", opacity: 0.12 }} />
                {/* targeting corners */}
                <Corner pos="top-0 left-0" /><Corner pos="top-0 right-0" />
                <Corner pos="bottom-0 left-0" /><Corner pos="bottom-0 right-0" />

                <div className="relative">
                  <div className="flex items-center gap-2.5 mb-8">
                    <div className="w-9 h-9 bg-primary flex items-center justify-center glow-primary">
                      <Terminal className="w-5 h-5 text-black" strokeWidth={2.5} />
                    </div>
                    <div>
                      <p className="font-heading font-black text-lg tracking-tight leading-none">InsafeLabs</p>
                      <span className="data-label">Command Center</span>
                    </div>
                    <span className="ml-auto flex items-center gap-1.5 data-label !text-primary">
                      <Radio className="w-3 h-3 animate-pulse" /> secure channel
                    </span>
                  </div>

                  <h1 className="font-heading text-3xl sm:text-4xl font-black tracking-tighter uppercase">
                    Restricted<br /><span className="text-primary text-glow">Access</span>
                  </h1>
                  <p className="text-zinc-400 text-sm mt-3 leading-relaxed">
                    Authenticate to initialize the operator console.
                  </p>

                  <form onSubmit={submit} className="mt-8 space-y-4">
                    <div>
                      <label className="data-label flex items-center gap-1.5 mb-2">
                        <Lock className="w-3 h-3 text-primary" /> Access Code
                      </label>
                      <div className="flex items-center gap-2.5 bg-black/60 border-b-2 border-primary/50 focus-within:border-primary px-3 py-3.5 transition-colors">
                        <span className="font-mono text-emerald-400/80 text-sm select-none shrink-0">root@insafe:~#</span>
                        <input
                          type="password"
                          inputMode="numeric"
                          autoFocus
                          disabled={locked}
                          value={password}
                          onChange={(e) => { setPassword(e.target.value); if (error && !locked) setError(""); }}
                          data-testid="login-password-input"
                          placeholder="••••••"
                          className="flex-1 min-w-0 bg-transparent text-white font-mono tracking-[0.4em] text-lg focus:outline-none placeholder:text-zinc-700 placeholder:tracking-[0.3em] disabled:opacity-50"
                        />
                      </div>
                    </div>

                    <AnimatePresence>
                      {error && (
                        <motion.p
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          data-testid="login-error"
                          className="flex items-center gap-2 text-severity-high text-sm font-mono"
                        >
                          <ShieldAlert className="w-4 h-4 shrink-0" /> {error}
                        </motion.p>
                      )}
                    </AnimatePresence>

                    {locked && (
                      <p data-testid="login-lock-countdown" className="flex items-center justify-center gap-2 font-mono text-severity-high text-sm border border-severity-high/40 bg-severity-high/5 py-2">
                        <Lock className="w-4 h-4" /> LOCKED · {mmss} remaining
                      </p>
                    )}

                    <button
                      type="submit"
                      disabled={loading || warping || locked}
                      data-testid="login-submit-btn"
                      className="w-full bg-primary text-black font-mono font-bold uppercase tracking-widest px-6 py-3.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-400 active:translate-y-px transition-colors disabled:opacity-70 glow-primary"
                    >
                      {locked ? <><Lock className="w-4 h-4" /> Locked · {mmss}</>
                        : loading ? <><Loader2 className="w-4 h-4 animate-spin" /> Authorizing…</>
                        : <>Authorize <ArrowRight className="w-4 h-4" /></>}
                    </button>
                  </form>

                  <p className="font-mono text-[10px] text-zinc-600 mt-6 text-center tracking-widest uppercase">
                    Authorized personnel only · Activity is logged
                  </p>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* access-granted readout during the hyperspace jump */}
      <AnimatePresence>
        {warping && (
          <motion.div
            initial={{ opacity: 0, scale: 0.94 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.12, duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
            className="absolute inset-0 z-10 pointer-events-none flex flex-col items-center justify-center px-6 text-center"
            data-testid="login-access-granted"
          >
            <motion.p
              className="font-heading font-black text-4xl sm:text-6xl tracking-tighter text-primary text-glow"
              initial={{ letterSpacing: "0.3em", opacity: 0 }}
              animate={{ letterSpacing: "0.02em", opacity: 1 }}
              transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
            >
              ACCESS GRANTED
            </motion.p>
            <motion.p
              className="data-label mt-3"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.35, duration: 0.4 }}
            >
              initializing command center…
            </motion.p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* hyperspace jump flash */}
      <AnimatePresence>
        {warping && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 0, 1] }}
            transition={{ duration: 1.35, times: [0, 0.68, 1] }}
            className="absolute inset-0 z-20 pointer-events-none"
            style={{ background: "radial-gradient(circle at 50% 50%, #fff 0%, rgba(250,204,21,0.55) 42%, transparent 78%)" }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
