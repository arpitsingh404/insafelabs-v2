import { useEffect, useRef } from "react";
import * as THREE from "three";

// Office / Security-Operations-Room palette. Status drives the monitor + accent glow.
const OFFICE = {
  queued: { color: 0x3b82c4, screenEI: 0.18, accentEI: 0.3, typing: false, flicker: false, css: "#7fb0d8" },
  working: { color: 0x22d3ee, screenEI: 1.15, accentEI: 0.9, typing: true, flicker: false, css: "#22d3ee" },
  done: { color: 0x34d399, screenEI: 0.7, accentEI: 0.7, typing: false, flicker: false, css: "#34d399" },
  failed: { color: 0xf87171, screenEI: 0.9, accentEI: 0.8, typing: false, flicker: true, css: "#f87171" },
  stopped: { color: 0xf59e0b, screenEI: 0.4, accentEI: 0.45, typing: false, flicker: false, css: "#f59e0b" },
};

let _codeTex;
function codeTexture() {
  if (_codeTex) return _codeTex;
  const c = document.createElement("canvas"); c.width = 256; c.height = 256;
  const x = c.getContext("2d");
  x.fillStyle = "#000"; x.fillRect(0, 0, 256, 256);
  for (let i = 0; i < 20; i++) {
    const w = 24 + Math.random() * 190;
    x.fillStyle = `rgba(255,255,255,${0.3 + Math.random() * 0.65})`;
    x.fillRect(10, 8 + i * 12, w, 5);
  }
  const t = new THREE.CanvasTexture(c);
  t.wrapS = t.wrapT = THREE.RepeatWrapping;
  _codeTex = t; return t;
}

let _wallTex;
function wallTexture() {
  if (_wallTex) return _wallTex;
  const c = document.createElement("canvas"); c.width = 1024; c.height = 512;
  const x = c.getContext("2d");
  x.fillStyle = "#070a0f"; x.fillRect(0, 0, 1024, 512);
  x.strokeStyle = "rgba(34,211,238,0.10)"; x.lineWidth = 1;
  for (let i = 0; i <= 1024; i += 32) { x.beginPath(); x.moveTo(i, 0); x.lineTo(i, 512); x.stroke(); }
  for (let j = 0; j <= 512; j += 32) { x.beginPath(); x.moveTo(0, j); x.lineTo(1024, j); x.stroke(); }
  // dashboard panels
  x.strokeStyle = "rgba(34,211,238,0.35)";
  for (const [px, py, pw, ph] of [[60, 90, 260, 150], [360, 90, 300, 150], [700, 90, 260, 150], [60, 300, 400, 140], [520, 300, 440, 140]]) {
    x.strokeRect(px, py, pw, ph);
    x.fillStyle = "rgba(34,211,238,0.06)"; x.fillRect(px, py, pw, ph);
  }
  x.fillStyle = "rgba(245,193,7,0.9)"; x.font = "bold 40px 'Courier New', monospace";
  x.fillText("INSAFELABS // SECURITY OPERATIONS", 60, 55);
  x.fillStyle = "rgba(34,211,238,0.7)"; x.font = "20px 'Courier New', monospace";
  x.fillText("LIVE THREAT FEED", 80, 130); x.fillText("ASSET MAP", 380, 130); x.fillText("AGENT STATUS", 720, 130);
  const t = new THREE.CanvasTexture(c);
  _wallTex = t; return t;
}

function makeLabel(text, css) {
  const c = document.createElement("canvas"); c.width = 256; c.height = 64;
  const ctx = c.getContext("2d");
  ctx.font = "bold 20px 'Courier New', monospace";
  ctx.textAlign = "center"; ctx.textBaseline = "middle";
  ctx.shadowColor = css; ctx.shadowBlur = 10; ctx.fillStyle = css;
  ctx.fillText((text || "").toUpperCase().slice(0, 18), 128, 34);
  const tex = new THREE.CanvasTexture(c); tex.minFilter = THREE.LinearFilter;
  const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
  spr.scale.set(2.0, 0.5, 1);
  return spr;
}

// A seated worker (hoodie + helmet + headset) at a desk with a computer. Faces -Z (toward camera).
function buildWorker(name) {
  const group = new THREE.Group();
  const bodyMat = new THREE.MeshStandardMaterial({ color: 0x5a6272, roughness: 0.65, metalness: 0.15 });
  const hoodMat = new THREE.MeshStandardMaterial({ color: 0x323a49, roughness: 0.85 });
  const chairMat = new THREE.MeshStandardMaterial({ color: 0x2f2f38, roughness: 0.7, metalness: 0.25 });
  const deskMat = new THREE.MeshStandardMaterial({ color: 0x2b2b33, roughness: 0.85 });
  const legMat = new THREE.MeshStandardMaterial({ color: 0x17171b, roughness: 0.9 });
  const bezelMat = new THREE.MeshStandardMaterial({ color: 0x0a0a0d, roughness: 0.8 });
  const helmMat = new THREE.MeshStandardMaterial({ color: 0x3c4552, roughness: 0.45, metalness: 0.45 });
  const setMat = new THREE.MeshStandardMaterial({ color: 0x121418, roughness: 0.6, metalness: 0.3 });
  const accentMat = new THREE.MeshStandardMaterial({ color: 0x22d3ee, emissive: 0x22d3ee, emissiveIntensity: 0.9, roughness: 0.5 });
  const ledMat = new THREE.MeshStandardMaterial({ color: 0x22d3ee, emissive: 0x22d3ee, emissiveIntensity: 1.0 });
  const screenMat = new THREE.MeshStandardMaterial({ color: 0x05070a, emissive: 0x22d3ee, emissiveMap: codeTexture(), emissiveIntensity: 1.1, roughness: 1 });

  const box = (w, h, d, mat, x, y, z, parent = group) => {
    const m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), mat); m.position.set(x, y, z); parent.add(m); return m;
  };

  // chair
  box(0.06, 0.5, 0.06, chairMat, 0, 0.3, 0.22);
  const chairBase = new THREE.Mesh(new THREE.CylinderGeometry(0.36, 0.36, 0.06, 16), chairMat); chairBase.position.set(0, 0.05, 0.22); group.add(chairBase);
  box(0.52, 0.1, 0.52, chairMat, 0, 0.58, 0.18);
  box(0.54, 0.66, 0.1, chairMat, 0, 0.94, 0.44);

  // body (hoodie), seated facing -Z
  box(0.44, 0.28, 0.42, hoodMat, 0, 0.78, 0.16);
  box(0.56, 0.7, 0.36, hoodMat, 0, 1.22, 0.2);
  box(0.62, 0.18, 0.44, hoodMat, 0, 1.55, 0.22);
  box(0.24, 0.26, 0.04, accentMat, 0, 1.3, 0.02);
  box(0.36, 0.16, 0.5, hoodMat, 0, 0.72, -0.12);
  box(0.16, 0.55, 0.16, bodyMat, -0.12, 0.4, -0.34);
  box(0.16, 0.55, 0.16, bodyMat, 0.12, 0.4, -0.34);

  // head + face + helmet + headset
  const head = box(0.42, 0.42, 0.42, bodyMat, 0, 1.79, 0.16);
  box(0.36, 0.12, 0.05, accentMat, 0, 1.82, -0.05);
  box(0.48, 0.16, 0.48, helmMat, 0, 2.03, 0.16);
  box(0.5, 0.05, 0.14, helmMat, 0, 1.99, -0.07);
  const band = new THREE.Mesh(new THREE.TorusGeometry(0.27, 0.035, 6, 18, Math.PI), setMat);
  band.position.set(0, 1.82, 0.16); group.add(band);
  box(0.09, 0.2, 0.2, setMat, -0.25, 1.78, 0.16);
  box(0.09, 0.2, 0.2, setMat, 0.25, 1.78, 0.16);
  box(0.04, 0.04, 0.22, setMat, 0.22, 1.68, 0.02);

  // arms (elbow pivots -> typing)
  box(0.15, 0.42, 0.15, hoodMat, -0.34, 1.2, 0.18);
  box(0.15, 0.42, 0.15, hoodMat, 0.34, 1.2, 0.18);
  const mkArm = (sx) => {
    const g = new THREE.Group(); g.position.set(sx, 1.02, 0.14);
    const fore = new THREE.Mesh(new THREE.BoxGeometry(0.14, 0.14, 0.4), hoodMat); fore.position.set(0, 0, -0.22); g.add(fore);
    const hand = new THREE.Mesh(new THREE.BoxGeometry(0.18, 0.1, 0.17), bodyMat); hand.position.set(0, -0.02, -0.44); g.add(hand);
    g.rotation.x = -0.35; group.add(g); return g;
  };
  const armL = mkArm(-0.3);
  const armR = mkArm(0.3);

  // desk + keyboard + monitor
  box(1.2, 0.07, 0.64, deskMat, 0, 1.0, -0.42);
  box(0.06, 1.0, 0.5, legMat, -0.55, 0.5, -0.42);
  box(0.06, 1.0, 0.5, legMat, 0.55, 0.5, -0.42);
  const led = box(1.1, 0.03, 0.03, ledMat, 0, 1.04, -0.73);
  box(0.52, 0.04, 0.18, bezelMat, 0, 1.05, -0.5);
  box(0.08, 0.3, 0.08, legMat, 0, 1.2, -0.66);
  box(0.9, 0.58, 0.05, bezelMat, 0, 1.52, -0.68);
  box(0.8, 0.5, 0.055, screenMat, 0, 1.52, -0.685);

  // screen light that spills onto the agent's face
  const faceLight = new THREE.PointLight(0x22d3ee, 0.0, 3.2, 2.0);
  faceLight.position.set(0, 1.55, -0.4); group.add(faceLight);

  const hit = new THREE.Mesh(new THREE.BoxGeometry(1.3, 2.2, 1.7), new THREE.MeshBasicMaterial({ colorWrite: false, depthWrite: false, transparent: true, opacity: 0 }));
  hit.position.set(0, 1.0, -0.1); group.add(hit);

  const label = makeLabel(name, "#22d3ee"); label.position.set(0, 2.5, 0.1); group.add(label);

  return { group, head, armL, armR, accentMat, ledMat, screenMat, faceLight, label, name, hit, lastStatus: null, baseX: 0, baseY: 0 };
}

function applyStatus(char, status) {
  const p = OFFICE[status] || OFFICE.queued;
  char.accentMat.color.setHex(p.color); char.accentMat.emissive.setHex(p.color); char.accentMat.emissiveIntensity = p.accentEI;
  char.ledMat.color.setHex(p.color); char.ledMat.emissive.setHex(p.color); char.ledMat.emissiveIntensity = p.accentEI + 0.2;
  char.screenMat.emissive.setHex(p.color); char.screenMat.emissiveIntensity = p.screenEI;
  if (char.faceLight) char.faceLight.color.setHex(p.color);
  const old = char.label.material.map;
  char.label.material.map = makeLabel(char.name, p.css).material.map; char.label.material.needsUpdate = true;
  if (old) old.dispose();
}

function disposeGroup(g) {
  g.traverse((o) => {
    if (o.geometry) o.geometry.dispose();
    if (o.material) (Array.isArray(o.material) ? o.material : [o.material]).forEach((m) => { if (m.map) m.map.dispose(); if (m.emissiveMap && m.emissiveMap !== _codeTex) m.emissiveMap.dispose(); m.dispose(); });
  });
}

export function AgentArena({ agents = [], selected, onSelect }) {
  const mountRef = useRef(null);
  const agentsRef = useRef(agents); agentsRef.current = agents;
  const selRef = useRef(selected); selRef.current = selected;
  const onSelRef = useRef(onSelect); onSelRef.current = onSelect;
  const stateRef = useRef({});
  const idsKey = agents.map((a) => a.id).join(",");

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const width = mount.clientWidth || 800;
    const height = 360;
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x06080b);
    scene.fog = new THREE.Fog(0x06080b, 14, 34);
    const camera = new THREE.PerspectiveCamera(46, width / height, 0.1, 100);
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(width, height);
    mount.appendChild(renderer.domElement);

    // lighting for a dim ops room
    scene.add(new THREE.AmbientLight(0x3a4256, 1.55));
    const key = new THREE.DirectionalLight(0xffffff, 1.15); key.position.set(-4, 7, -5); scene.add(key);
    const rim = new THREE.DirectionalLight(0x22d3ee, 0.55); rim.position.set(3, 4, 6); scene.add(rim);
    const fill = new THREE.DirectionalLight(0x9fb4d8, 0.7); fill.position.set(0, 3, -9); scene.add(fill);

    // floor + grid
    const floor = new THREE.Mesh(new THREE.PlaneGeometry(80, 80), new THREE.MeshStandardMaterial({ color: 0x0a0a0e, roughness: 1 }));
    floor.rotation.x = -Math.PI / 2; scene.add(floor);
    const grid = new THREE.GridHelper(60, 60, 0x1b3a44, 0x11181e);
    grid.material.opacity = 0.5; grid.material.transparent = true; scene.add(grid);

    // big operations wall behind the desks
    const wall = new THREE.Mesh(new THREE.PlaneGeometry(14, 5.6), new THREE.MeshBasicMaterial({ map: wallTexture() }));
    wall.position.set(0, 2.6, 5.5); scene.add(wall);
    const wallFrame = new THREE.Mesh(new THREE.PlaneGeometry(14.4, 6), new THREE.MeshBasicMaterial({ color: 0x0c1218 }));
    wallFrame.position.set(0, 2.6, 5.6); scene.add(wallFrame);

    // room shell: side walls + ceiling + neon trim (front stays open toward the camera)
    const wallMat = new THREE.MeshStandardMaterial({ color: 0x0e1218, roughness: 1, side: THREE.FrontSide });
    const wallL = new THREE.Mesh(new THREE.PlaneGeometry(16, 6.5), wallMat); wallL.position.set(-8.5, 3, 1); wallL.rotation.y = Math.PI / 2; scene.add(wallL);
    const wallR = new THREE.Mesh(new THREE.PlaneGeometry(16, 6.5), wallMat); wallR.position.set(8.5, 3, 1); wallR.rotation.y = -Math.PI / 2; scene.add(wallR);
    const ceil = new THREE.Mesh(new THREE.PlaneGeometry(17.4, 16), new THREE.MeshStandardMaterial({ color: 0x0a0d12, roughness: 1, side: THREE.DoubleSide }));
    ceil.position.set(0, 6, 1); ceil.rotation.x = Math.PI / 2; scene.add(ceil);
    const trimMat = new THREE.MeshBasicMaterial({ color: 0x22d3ee });
    const trimL = new THREE.Mesh(new THREE.PlaneGeometry(16, 0.05), trimMat); trimL.position.set(-8.49, 1.5, 1); trimL.rotation.y = Math.PI / 2; scene.add(trimL);
    const trimR = new THREE.Mesh(new THREE.PlaneGeometry(16, 0.05), trimMat); trimR.position.set(8.49, 1.5, 1); trimR.rotation.y = -Math.PI / 2; scene.add(trimR);
    const panelMat = new THREE.MeshBasicMaterial({ color: 0xdfe8ff, side: THREE.DoubleSide });
    for (const px of [-4, 0, 4]) {
      const panel = new THREE.Mesh(new THREE.PlaneGeometry(2.4, 0.5), panelMat); panel.position.set(px, 5.97, 1); panel.rotation.x = Math.PI / 2; scene.add(panel);
    }
    const cl1 = new THREE.PointLight(0xbfd0ff, 0.5, 22); cl1.position.set(-3.5, 5.3, 0); scene.add(cl1);
    const cl2 = new THREE.PointLight(0xbfd0ff, 0.5, 22); cl2.position.set(3.5, 5.3, 0); scene.add(cl2);

    const rig = new THREE.Group(); scene.add(rig);
    const clock = new THREE.Clock();
    const ray = new THREE.Raycaster();
    const ndc = new THREE.Vector2();
    let raf;
    const st = stateRef.current;
    Object.assign(st, {
      scene, camera, renderer, rig, chars: {},
      theta: Math.PI, targetTheta: Math.PI, phi: 1.12, targetPhi: 1.12, radius: 11,
      target: new THREE.Vector3(0, 1.45, 0), dragging: false, lastX: 0, lastY: 0, moved: 0, reduce,
    });

    const animate = () => {
      raf = requestAnimationFrame(animate);
      const t = clock.getElapsedTime();
      st.theta += (st.targetTheta - st.theta) * 0.08;
      st.phi += (st.targetPhi - st.phi) * 0.12;
      const sway = st.dragging ? 0 : Math.sin(t * 0.14) * 0.12;
      const eff = st.theta + sway;
      const r = st.radius;
      camera.position.set(
        st.target.x + r * Math.sin(st.phi) * Math.sin(eff),
        st.target.y + r * Math.cos(st.phi),
        st.target.z + r * Math.sin(st.phi) * Math.cos(eff),
      );
      camera.lookAt(st.target);

      const list = agentsRef.current || [];
      const sel = selRef.current;
      Object.entries(st.chars).forEach(([id, char]) => {
        const ag = list.find((x) => x.id === id);
        const status = ag?.status || "queued";
        if (status !== char.lastStatus) { applyStatus(char, status); char.lastStatus = status; }
        const ph = char.phase;
        const p = OFFICE[status] || OFFICE.queued;

        if (p.typing && !st.reduce) {
          const type = Math.sin(t * 16 + ph);
          char.armL.rotation.x = -0.35 + type * 0.08;
          char.armR.rotation.x = -0.35 + Math.sin(t * 16 + ph + 1.6) * 0.08;
          char.head.rotation.x = Math.sin(t * 2 + ph) * 0.05;
          char.screenMat.emissiveMap.offset.y = (t * 0.35) % 1;    // scrolling code
          char.screenMat.emissiveIntensity = 0.95 + Math.abs(Math.sin(t * 9 + ph)) * 0.35;
        } else {
          char.armL.rotation.x += (-0.35 - char.armL.rotation.x) * 0.1;
          char.armR.rotation.x += (-0.35 - char.armR.rotation.x) * 0.1;
          char.head.rotation.x += (0 - char.head.rotation.x) * 0.1;
          if (p.flicker && !st.reduce) char.screenMat.emissiveIntensity = 0.5 + Math.abs(Math.sin(t * 20 + ph)) * 0.7;
        }

        // screen light spilling onto the face (bright when working)
        const li = status === "working" ? 1.7 : status === "queued" ? 0.3 : status === "failed" ? 1.1 : 0.8;
        char.faceLight.intensity = li * (status === "working" ? (0.8 + Math.abs(Math.sin(t * 8 + ph)) * 0.5) : 1);

        // selection emphasis
        const isSel = sel && sel === id;
        const target = isSel ? 1.08 : 1.0;
        char.group.scale.x += (target - char.group.scale.x) * 0.12;
        char.group.scale.y = char.group.scale.z = char.group.scale.x;
      });
      renderer.render(scene, camera);
    };
    animate();

    // interaction: drag-orbit + wheel-zoom + click-to-inspect
    const el = renderer.domElement;
    el.style.touchAction = "none"; el.style.cursor = "grab";
    const onDown = (e) => { st.dragging = true; st.moved = 0; st.lastX = e.clientX; st.lastY = e.clientY; el.style.cursor = "grabbing"; };
    const onMove = (e) => {
      if (!st.dragging) return;
      const dx = e.clientX - st.lastX, dy = e.clientY - st.lastY;
      st.lastX = e.clientX; st.lastY = e.clientY; st.moved += Math.abs(dx) + Math.abs(dy);
      st.targetTheta -= dx * 0.006;
      st.targetTheta = Math.min(Math.PI + 1.15, Math.max(Math.PI - 1.15, st.targetTheta));
      st.targetPhi = Math.min(1.45, Math.max(0.45, st.targetPhi - dy * 0.005));
    };
    const onUp = (e) => {
      const wasDrag = st.moved > 6;
      st.dragging = false; el.style.cursor = "grab";
      if (wasDrag) return;
      const rect = el.getBoundingClientRect();
      ndc.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      ndc.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      ray.setFromCamera(ndc, camera);
      const hits = ray.intersectObjects(Object.values(st.chars).map((c) => c.hit), false);
      if (hits.length) {
        let o = hits[0].object;
        while (o && !o.userData.agentId) o = o.parent;
        if (o?.userData.agentId) onSelRef.current?.(o.userData.agentId);
      } else onSelRef.current?.(null);
    };
    const onWheel = (e) => { e.preventDefault(); st.radius = Math.min(18, Math.max(6, st.radius + e.deltaY * 0.01)); };
    el.addEventListener("pointerdown", onDown);
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    el.addEventListener("wheel", onWheel, { passive: false });

    const onResize = () => { const w = mount.clientWidth || width; camera.aspect = w / height; camera.updateProjectionMatrix(); renderer.setSize(w, height); };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      el.removeEventListener("pointerdown", onDown);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      el.removeEventListener("wheel", onWheel);
      scene.traverse((o) => {
        if (o.geometry) o.geometry.dispose();
        if (o.material) (Array.isArray(o.material) ? o.material : [o.material]).forEach((m) => { if (m.map) m.map.dispose(); m.dispose(); });
      });
      renderer.dispose();
      if (renderer.domElement.parentNode === mount) mount.removeChild(renderer.domElement);
      stateRef.current = {};
    };
  }, []);

  useEffect(() => {
    const st = stateRef.current;
    if (!st.rig) return;
    Object.values(st.chars || {}).forEach((c) => { st.rig.remove(c.group); disposeGroup(c.group); });
    st.chars = {};
    const list = agentsRef.current || [];
    const n = list.length || 1;
    const step = 0.34;
    const Rarc = 3.4 + n * 0.32;
    list.forEach((a, i) => {
      const char = buildWorker(a.name || a.id);
      char.phase = i * 1.7;
      const ang = (i - (n - 1) / 2) * step;
      char.baseX = Math.sin(ang) * Rarc;
      char.baseZ = Math.cos(ang) * Rarc - Rarc;   // horseshoe: center at 0, ends curve toward camera
      char.baseY = 0;
      char.group.position.set(char.baseX, 0, char.baseZ);
      char.group.rotation.y = ang;                 // each desk faces the viewer / focal point
      char.group.userData.agentId = a.id;
      char.hit.userData.agentId = a.id;
      applyStatus(char, a.status || "queued");
      char.lastStatus = a.status || "queued";
      st.rig.add(char.group);
      st.chars[a.id] = char;
    });
    st.radius = Rarc + 5.5;
    st.target.set(0, 1.3, -0.3);
  }, [idsKey]);

  return (
    <div className="relative border border-cyan-500/20 bg-[#06080b] overflow-hidden" data-testid="agent-arena">
      <style>{`
        @keyframes holoScan { 0% { background-position: 0 0 } 100% { background-position: 0 120px } }
        .holo-scan { background: repeating-linear-gradient(to bottom, rgba(34,211,238,0.04) 0px, rgba(34,211,238,0.04) 1px, transparent 2px, transparent 4px); mix-blend-mode: screen; animation: holoScan 10s linear infinite; }
      `}</style>
      <div className="flex items-center justify-between px-4 py-2 border-b border-cyan-500/20">
        <span className="data-label flex items-center gap-2" style={{ color: "#22d3ee" }}>
          <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "#22d3ee" }} /> Operations Room · Live Agents
        </span>
        <span className="text-[10px] font-mono text-zinc-500 uppercase">{(agents || []).length} desks · drag to orbit</span>
      </div>
      <div className="relative">
        <div ref={mountRef} className="w-full" style={{ height: 360 }} data-testid="agent-arena-canvas" />
        <div className="holo-scan pointer-events-none absolute inset-0 opacity-50" />
        <div className="pointer-events-none absolute top-2 left-2 w-5 h-5 border-t border-l border-cyan-400/40" />
        <div className="pointer-events-none absolute top-2 right-2 w-5 h-5 border-t border-r border-cyan-400/40" />
        <div className="pointer-events-none absolute bottom-2 left-2 w-5 h-5 border-b border-l border-cyan-400/40" />
        <div className="pointer-events-none absolute bottom-2 right-2 w-5 h-5 border-b border-r border-cyan-400/40" />
        <span className="pointer-events-none absolute bottom-2.5 left-1/2 -translate-x-1/2 text-[9px] font-mono uppercase tracking-widest text-cyan-400/50">click a desk to inspect</span>
      </div>
    </div>
  );
}
