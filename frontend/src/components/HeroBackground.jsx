import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import * as THREE from "three";

function makeGlowTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d");
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.35, "rgba(255,255,255,0.45)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 64, 64);
  return new THREE.CanvasTexture(c);
}

const MODULE_NODES = [
  { label: "Attack Surface Scanner", to: "/app/scanner" },
  { label: "OSINT Investigator", to: "/app/osint" },
  { label: "AI Pentesting", to: "/app/ai-pentest" },
  { label: "Bug Bounty Engine", to: "/app/bugbounty" },
  { label: "Red Team Ops", to: "/app/redteam" },
  { label: "Hacker Toolkit", to: "/app/toolkit" },
  { label: "Network Mapper", to: "/app/netmap" },
  { label: "Command Dashboard", to: "/app" },
];

/* Interactive cyber command globe — rotating geodesic wireframe with glowing
   surface nodes, live attack arcs, drifting starfield, pointer parallax,
   DRAG-to-rotate and CLICKABLE module hotspots that open each module. */
export const HeroBackground = () => {
  const mountRef = useRef(null);
  const tipRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    let width = mount.clientWidth;
    let height = mount.clientHeight;

    const YELLOW = 0xfacc15;
    const BLUE = 0x3b82f6;
    const R = 13;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(55, width / height, 0.1, 1000);
    camera.position.z = 46;

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(width, height);
    mount.appendChild(renderer.domElement);
    const canvas = renderer.domElement;
    canvas.style.cursor = "grab";

    const glowTex = makeGlowTexture();

    const globe = new THREE.Group();
    globe.position.x = width < 1024 ? 0 : 13;
    scene.add(globe);

    const wire = new THREE.LineSegments(
      new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(R, 2)),
      new THREE.LineBasicMaterial({ color: BLUE, transparent: true, opacity: 0.1 })
    );
    globe.add(wire);

    // fibonacci surface nodes
    const DOTS = 320;
    const surf = [];
    const dpos = new Float32Array(DOTS * 3);
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < DOTS; i++) {
      const y = 1 - (i / (DOTS - 1)) * 2;
      const rad = Math.sqrt(1 - y * y);
      const th = golden * i;
      const v = new THREE.Vector3(Math.cos(th) * rad, y, Math.sin(th) * rad);
      surf.push(v);
      dpos[i * 3] = v.x * R;
      dpos[i * 3 + 1] = v.y * R;
      dpos[i * 3 + 2] = v.z * R;
    }
    const dotGeo = new THREE.BufferGeometry();
    dotGeo.setAttribute("position", new THREE.BufferAttribute(dpos, 3));
    globe.add(new THREE.Points(dotGeo, new THREE.PointsMaterial({
      color: YELLOW, size: 0.85, map: glowTex, transparent: true, opacity: 0.85, depthWrite: false, blending: THREE.AdditiveBlending,
    })));

    // --- clickable module hotspots ---
    const nodeMeshes = [];
    const nodeGeo = new THREE.SphereGeometry(0.62, 16, 16);
    MODULE_NODES.forEach((m, i) => {
      const dir = surf[Math.floor((i + 0.5) / MODULE_NODES.length * surf.length)].clone();
      const pos = dir.multiplyScalar(R + 0.4);
      const mesh = new THREE.Mesh(nodeGeo, new THREE.MeshBasicMaterial({ color: YELLOW }));
      mesh.position.copy(pos);
      mesh.userData = { ...m, base: 1 };
      const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color: YELLOW, transparent: true, opacity: 0.85, depthWrite: false, blending: THREE.AdditiveBlending }));
      halo.scale.set(3.4, 3.4, 1);
      mesh.add(halo);
      globe.add(mesh);
      nodeMeshes.push(mesh);
    });

    // --- live attack arcs ---
    const ARC_N = 16;
    const SEG = 50;
    const arcGroup = new THREE.Group();
    globe.add(arcGroup);
    const arcs = [];
    const headPos = new Float32Array(ARC_N * 3);
    const headGeo = new THREE.BufferGeometry();
    headGeo.setAttribute("position", new THREE.BufferAttribute(headPos, 3));
    globe.add(new THREE.Points(headGeo, new THREE.PointsMaterial({ color: 0xffffff, size: 1.7, map: glowTex, transparent: true, opacity: 0.95, depthWrite: false, blending: THREE.AdditiveBlending })));

    const makeArc = () => {
      const a = surf[(Math.random() * surf.length) | 0];
      let b = surf[(Math.random() * surf.length) | 0];
      let guard = 0;
      while (a.distanceTo(b) < 1.1 && guard++ < 6) b = surf[(Math.random() * surf.length) | 0];
      const mid = a.clone().add(b).multiplyScalar(0.5).normalize().multiplyScalar(R * (1.2 + a.distanceTo(b) * 0.28));
      const curve = new THREE.QuadraticBezierCurve3(a.clone().multiplyScalar(R), mid, b.clone().multiplyScalar(R));
      const geo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(SEG));
      const mat = new THREE.LineBasicMaterial({ color: YELLOW, transparent: true, opacity: 0, blending: THREE.AdditiveBlending });
      const line = new THREE.Line(geo, mat);
      arcGroup.add(line);
      return { curve, line, t: Math.random() * 0.4, speed: 0.004 + Math.random() * 0.006 };
    };
    for (let i = 0; i < ARC_N; i++) arcs.push(makeArc());

    // starfield
    const PN = 240;
    const ppos = new Float32Array(PN * 3);
    for (let i = 0; i < PN; i++) {
      ppos[i * 3] = (Math.random() - 0.5) * 130;
      ppos[i * 3 + 1] = (Math.random() - 0.5) * 85;
      ppos[i * 3 + 2] = (Math.random() - 0.5) * 90;
    }
    const starGeo = new THREE.BufferGeometry();
    starGeo.setAttribute("position", new THREE.BufferAttribute(ppos, 3));
    const stars = new THREE.Points(starGeo, new THREE.PointsMaterial({ color: BLUE, size: 0.45, transparent: true, opacity: 0.5 }));
    scene.add(stars);

    // --- interaction: parallax + drag rotate + raycast hover/click ---
    const raycaster = new THREE.Raycaster();
    raycaster.params.Points = { threshold: 0.6 };
    const ndc = new THREE.Vector2();
    const rot = { x: 0, y: 0 };
    let mx = 0, my = 0, tx = 0, ty = 0;
    let dragging = false, moved = 0, lastX = 0, lastY = 0;
    let hovered = null;

    const setHover = (mesh, clientX, clientY) => {
      const tip = tipRef.current;
      if (mesh) {
        hovered = mesh;
        canvas.style.cursor = "pointer";
        if (tip) {
          const r = canvas.getBoundingClientRect();
          tip.textContent = mesh.userData.label;
          tip.style.left = `${clientX - r.left + 14}px`;
          tip.style.top = `${clientY - r.top + 12}px`;
          tip.style.display = "block";
        }
      } else {
        hovered = null;
        canvas.style.cursor = dragging ? "grabbing" : "grab";
        if (tip) tip.style.display = "none";
      }
    };

    const onCanvasMove = (e) => {
      const r = canvas.getBoundingClientRect();
      tx = (e.clientX - r.left) / r.width - 0.5;
      ty = (e.clientY - r.top) / r.height - 0.5;
      if (dragging) return;
      ndc.x = ((e.clientX - r.left) / r.width) * 2 - 1;
      ndc.y = -((e.clientY - r.top) / r.height) * 2 + 1;
      raycaster.setFromCamera(ndc, camera);
      const hit = raycaster.intersectObjects(nodeMeshes, false)[0];
      setHover(hit ? hit.object : null, e.clientX, e.clientY);
    };
    const onDown = (e) => { dragging = true; moved = 0; lastX = e.clientX; lastY = e.clientY; canvas.style.cursor = "grabbing"; };
    const onWinMove = (e) => {
      if (!dragging) return;
      const dx = e.clientX - lastX, dy = e.clientY - lastY;
      moved += Math.abs(dx) + Math.abs(dy);
      rot.y += dx * 0.005;
      rot.x = Math.max(-0.6, Math.min(0.6, rot.x + dy * 0.005));
      lastX = e.clientX; lastY = e.clientY;
    };
    const onWinUp = () => {
      if (dragging && moved < 6 && hovered) navigate(hovered.userData.to);
      dragging = false;
      canvas.style.cursor = hovered ? "pointer" : "grab";
    };
    canvas.addEventListener("pointermove", onCanvasMove);
    canvas.addEventListener("pointerdown", onDown);
    window.addEventListener("pointermove", onWinMove);
    window.addEventListener("pointerup", onWinUp);

    let raf;
    const animate = () => {
      raf = requestAnimationFrame(animate);
      if (!dragging) rot.y += 0.0015;
      mx += (tx - mx) * 0.05;
      my += (ty - my) * 0.05;
      globe.rotation.y = rot.y + mx * 0.12;
      globe.rotation.x = rot.x + my * 0.22;
      stars.rotation.y += 0.0004;

      nodeMeshes.forEach((n) => {
        const target = n === hovered ? 1.7 : 1;
        n.scale.x += (target - n.scale.x) * 0.2;
        n.scale.y = n.scale.z = n.scale.x;
      });

      for (let i = 0; i < ARC_N; i++) {
        const arc = arcs[i];
        arc.t += arc.speed;
        const env = Math.sin(Math.min(arc.t, 1) * Math.PI);
        arc.line.material.opacity = Math.max(0, env) * 0.55;
        const p = arc.curve.getPointAt(Math.min(arc.t, 1));
        headPos[i * 3] = p.x; headPos[i * 3 + 1] = p.y; headPos[i * 3 + 2] = p.z;
        if (arc.t >= 1) {
          arcGroup.remove(arc.line);
          arc.line.geometry.dispose();
          arc.line.material.dispose();
          arcs[i] = makeArc();
        }
      }
      headGeo.attributes.position.needsUpdate = true;
      renderer.render(scene, camera);
    };
    animate();

    const onResize = () => {
      width = mount.clientWidth;
      height = mount.clientHeight;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
      globe.position.x = width < 1024 ? 0 : 13;
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      canvas.removeEventListener("pointermove", onCanvasMove);
      canvas.removeEventListener("pointerdown", onDown);
      window.removeEventListener("pointermove", onWinMove);
      window.removeEventListener("pointerup", onWinUp);
      scene.traverse((o) => {
        if (o.geometry) o.geometry.dispose();
        if (o.material) o.material.dispose();
      });
      glowTex.dispose();
      renderer.dispose();
      if (canvas.parentNode) canvas.parentNode.removeChild(canvas);
    };
  }, [navigate]);

  return (
    <div ref={mountRef} className="absolute inset-0 grid-fade" data-testid="hero-3d-bg">
      <div ref={tipRef} data-testid="hero-node-tip"
        className="pointer-events-none absolute z-20 hidden bg-black/85 border border-primary/40 text-primary text-[11px] font-mono uppercase tracking-wider px-2.5 py-1 backdrop-blur"
        style={{ display: "none" }} />
    </div>
  );
};
