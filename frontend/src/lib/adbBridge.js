// InsafeLabs Mobile Bridge — real WebUSB ADB via Tango (ya-webadb), lazy-loaded.
// Everything runs client-side in the browser (Chrome/Edge desktop). No backend.

let _mods = null;
async function load() {
  if (_mods) return _mods;
  const [core, usb, cred] = await Promise.all([
    import("@yume-chan/adb"),
    import("@yume-chan/adb-daemon-webusb"),
    import("@yume-chan/adb-credential-web"),
  ]);
  _mods = {
    Adb: core.Adb,
    AdbDaemonTransport: core.AdbDaemonTransport,
    AdbDaemonWebUsbDeviceManager: usb.AdbDaemonWebUsbDeviceManager,
    AdbWebCredentialStore: cred.default || cred.AdbWebCredentialStore,
  };
  return _mods;
}

const ADB_FILTERS = [{ classCode: 0xff, subclassCode: 0x42, protocol: 0x01 }];

export function isSupported() {
  return typeof navigator !== "undefined" && !!navigator.usb;
}

// Warm up the (heavy) Tango bundle ahead of the click so the user gesture isn't wasted.
export function preload() {
  try { load().catch(() => {}); } catch { /* ignore */ }
}

export function diagnostics() {
  const inIframe = (() => { try { return window.self !== window.top; } catch { return true; } })();
  return {
    supported: isSupported(),
    secureContext: typeof window !== "undefined" ? !!window.isSecureContext : false,
    inIframe,
  };
}

export async function authorizedCount() {
  try { return (await navigator.usb.getDevices()).length; } catch { return 0; }
}

function withTimeout(promise, ms, msg) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(msg)), ms)),
  ]);
}

// STEP 1 — must run synchronously inside the click handler (before any heavy await)
// so Chrome keeps the transient user-activation and actually shows the USB chooser.
export async function requestPermission() {
  if (!navigator.usb) throw new Error("WebUSB not supported — use desktop Chrome or Edge.");
  try {
    return await navigator.usb.requestDevice({ filters: ADB_FILTERS });
  } catch (e) {
    const name = e?.name || "";
    const msg = e?.message || "";
    if (name === "NotFoundError") return null; // chooser cancelled / empty
    if (name === "SecurityError" || /permissions policy|disallowed/i.test(msg)) {
      throw new Error("WebUSB blocked by the page. Open InsafeLabs in a real top-level browser tab, then retry.");
    }
    if (name === "NotAllowedError") {
      throw new Error("Browser blocked the USB prompt (user-gesture). Click Connect again.");
    }
    throw e;
  }
}

// STEP 2 — heavy work after permission is granted (Tango loads here, gesture no longer needed)
export async function connectSelected(selected) {
  const { Adb, AdbDaemonTransport, AdbDaemonWebUsbDeviceManager, AdbWebCredentialStore } = await load();
  const manager = AdbDaemonWebUsbDeviceManager.BROWSER;
  if (!manager) throw new Error("WebUSB not supported — use desktop Chrome or Edge.");

  const devices = await manager.getDevices();
  let device =
    devices.find((d) => d.raw?.serialNumber && selected?.serialNumber && d.raw.serialNumber === selected.serialNumber)
    || devices[devices.length - 1]
    || devices[0];
  if (!device) {
    throw new Error("Permission granted but no ADB interface found. Set USB mode to 'File transfer / MTP' with USB debugging ON, then retry.");
  }

  let connection;
  try {
    connection = await withTimeout(device.connect(), 15000, "Could not open the device (timed out).");
  } catch (e) {
    if (/claim|busy|access|InvalidState|Network|timed out/i.test(e?.message || "")) {
      throw new Error("Device busy — another ADB is holding it. Run 'adb kill-server' / close Android Studio, unplug-replug, then retry.");
    }
    throw e;
  }

  const credentialStore = new AdbWebCredentialStore("InsafeLabs Console");
  const transport = await withTimeout(
    AdbDaemonTransport.authenticate({ serial: device.serial, connection, credentialStore }),
    60000,
    "Timed out — tap 'Allow USB debugging' on the phone (tick 'Always allow from this computer'), then retry.",
  );
  const adb = new Adb(transport);
  return { adb, serial: device.serial, name: device.name };
}

// Convenience single-call (permission must still originate from a gesture; prefer the 2-step in UI).
export async function connectDevice() {
  const selected = await requestPermission();
  if (!selected) throw new Error("No device selected.");
  return connectSelected(selected);
}

// ---- stream helpers ----
async function collectBytes(stream) {
  const reader = stream.getReader();
  const chunks = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) chunks.push(value);
    }
  } finally {
    try { reader.releaseLock(); } catch { /* ignore */ }
  }
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

// Run a shell command and return trimmed stdout text. Handles Tango v2 + older APIs.
export async function shell(adb, cmd) {
  const sp = adb.subprocess;
  if (sp?.noneProtocol?.spawn) {
    const p = await sp.noneProtocol.spawn(cmd);
    return new TextDecoder().decode(await collectBytes(p.output)).trim();
  }
  if (sp?.spawnAndWait) {
    const r = await sp.spawnAndWait(cmd);
    return (typeof r === "string" ? r : (r.stdout ?? "")).toString().trim();
  }
  if (sp?.spawn) {
    const p = await sp.spawn(cmd);
    const stream = p.stdout || p.output;
    return new TextDecoder().decode(await collectBytes(stream)).trim();
  }
  throw new Error("This device/ADB build does not expose a shell interface.");
}

async function shellRaw(adb, cmd) {
  const sp = adb.subprocess;
  let stream;
  if (sp?.noneProtocol?.spawn) stream = (await sp.noneProtocol.spawn(cmd)).output;
  else if (sp?.spawn) { const p = await sp.spawn(cmd); stream = p.stdout || p.output; }
  else throw new Error("No subprocess interface.");
  return collectBytes(stream);
}

// ---- device info (auto) ----
export async function getInfo(adb) {
  const propsText = await shell(adb, "getprop");
  const map = {};
  propsText.split("\n").forEach((line) => {
    const m = line.match(/^\[([^\]]+)\]:\s*\[([^\]]*)\]/);
    if (m) map[m[1]] = m[2];
  });
  const battery = await shell(adb, "dumpsys battery").catch(() => "");
  const wm = await shell(adb, "wm size").catch(() => "");
  const df = await shell(adb, "df -h /data").catch(() => "");
  const uptime = await shell(adb, "cat /proc/uptime").catch(() => "");
  const level = (battery.match(/level:\s*(\d+)/) || [])[1];
  const plugged = (battery.match(/AC powered:\s*(true|false)/) || [])[1] === "true"
    || (battery.match(/USB powered:\s*(true|false)/) || [])[1] === "true";
  const dfLine = df.split("\n").find((l) => l.includes("/data")) || "";
  const dfCols = dfLine.trim().split(/\s+/);
  return {
    model: map["ro.product.model"] || "—",
    brand: map["ro.product.brand"] || map["ro.product.manufacturer"] || "—",
    manufacturer: map["ro.product.manufacturer"] || "—",
    device: map["ro.product.device"] || "—",
    androidVersion: map["ro.build.version.release"] || "—",
    sdk: map["ro.build.version.sdk"] || "—",
    serial: map["ro.serialno"] || map["ro.boot.serialno"] || "—",
    abi: map["ro.product.cpu.abi"] || "—",
    securityPatch: map["ro.build.version.security_patch"] || "—",
    buildId: map["ro.build.display.id"] || "—",
    battery: level ? `${level}%${plugged ? " ⚡" : ""}` : "—",
    screen: (wm.match(/Physical size:\s*(\S+)/) || [])[1] || "—",
    storage: dfCols.length >= 4 ? `${dfCols[2]} used / ${dfCols[1]}` : "—",
    uptime: uptime ? `${Math.floor(parseFloat(uptime.split(" ")[0]) / 3600)}h` : "—",
    bootloader: map["ro.boot.verifiedbootstate"] || map["ro.boot.flash.locked"] || "—",
  };
}

// ---- power controls (device will disconnect) ----
export async function power(adb, mode) {
  const race = (p) => Promise.race([p, new Promise((r) => setTimeout(r, 3000))]);
  try {
    if (adb.power) {
      if (mode === "recovery" && adb.power.recovery) return await race(adb.power.recovery());
      if (mode === "bootloader" && adb.power.bootloader) return await race(adb.power.bootloader());
      if (mode === "poweroff" && adb.power.powerOff) return await race(adb.power.powerOff());
      if (mode === "reboot") return await race(adb.power.reboot());
    }
  } catch { /* fall through to shell */ }
  if (mode === "poweroff") return race(shell(adb, "reboot -p"));
  if (mode === "reboot") return race(shell(adb, "reboot"));
  return race(shell(adb, `reboot ${mode}`));
}

// ---- screenshot ----
export async function screenshot(adb) {
  // Prefer `screencap -p` — captures the real composited screen (incl. hardware layers).
  try {
    const bytes = await shellRaw(adb, "screencap -p");
    if (bytes && bytes.length > 100 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e) {
      return URL.createObjectURL(new Blob([bytes], { type: "image/png" }));
    }
  } catch { /* fall back to framebuffer */ }
  if (typeof adb.framebuffer === "function") {
    const fb = await adb.framebuffer();
    const canvas = document.createElement("canvas");
    canvas.width = fb.width; canvas.height = fb.height;
    const ctx = canvas.getContext("2d");
    ctx.putImageData(new ImageData(new Uint8ClampedArray(fb.data), fb.width, fb.height), 0, 0);
    return canvas.toDataURL("image/png");
  }
  throw new Error("Screenshot not supported on this device.");
}

// ---- packages ----
// ADB args are string-concatenated into `sh -c`, so package names are validated
// against a strict charset and paths are single-quoted safely to prevent injection.
const PKG_RE = /^[A-Za-z0-9._]+$/;
const assertPkg = (p) => {
  if (!PKG_RE.test(p || "")) throw new Error(`Invalid package name: ${p}`);
  return p;
};
const shQuote = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

export async function listPackages(adb, thirdPartyOnly = true) {
  const out = await shell(adb, `pm list packages${thirdPartyOnly ? " -3" : ""}`);
  return out.split("\n").map((l) => l.replace("package:", "").trim()).filter(Boolean).sort();
}
export const uninstall = (adb, pkg) => shell(adb, `pm uninstall --user 0 ${assertPkg(pkg)}`);
export const clearData = (adb, pkg) => shell(adb, `pm clear ${assertPkg(pkg)}`);

// Pull an installed app's base.apk off the device (no root needed for world-readable base.apk).
export async function pullApk(adb, pkg) {
  const pathOut = await shell(adb, `pm path ${assertPkg(pkg)}`);
  const paths = pathOut.split("\n").map((l) => l.replace("package:", "").trim()).filter(Boolean);
  if (!paths.length) throw new Error("Could not resolve APK path (pm path returned nothing).");
  const apkPath = paths.find((p) => p.endsWith("base.apk")) || paths[0];
  const sync = await adb.sync();
  try {
    const stream = sync.read(apkPath);
    const bytes = await collectBytes(stream);
    if (!bytes || bytes.length < 100) throw new Error("APK read returned no data (this app may need root to pull).");
    return { bytes, apkPath };
  } finally {
    try { await sync.dispose?.(); } catch { /* ignore */ }
  }
}

// ---- file listing ----
export async function listDir(adb, path) {
  const out = await shell(adb, `ls -la ${shQuote(path)}`);
  return out.split("\n").filter((l) => l.trim() && !l.startsWith("total"));
}

// open the on-device factory-reset / privacy settings screen (user confirms on phone — safe)
export const openFactoryReset = (adb) =>
  shell(adb, "am start -a android.settings.PRIVACY_SETTINGS").catch(() =>
    shell(adb, "am start -n com.android.settings/.Settings"));

export async function disconnect(adb) {
  try { await adb.close(); } catch { /* ignore */ }
}
