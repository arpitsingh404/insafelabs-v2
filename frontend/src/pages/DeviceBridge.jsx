import { useState, useRef, useEffect } from "react";
import { toast } from "sonner";
import * as adbBridge from "@/lib/adbBridge";
import { ApkResult, analyzeApkFile } from "@/components/ApkAnalyzer";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  Usb, Smartphone, Power, RefreshCw, RotateCcw, Wrench, Camera, Trash2,
  Terminal as TerminalIcon, FolderOpen, Download, Loader2, ShieldAlert,
  Cpu, BatteryFull, HardDrive, MonitorSmartphone, Fingerprint, Eraser,
  Plug, PlugZap, Send, Search, ChevronRight, AlertTriangle, ExternalLink,
  FileArchive, Radar,
} from "lucide-react";

const TABS = [
  { key: "device", label: "Device", icon: Smartphone },
  { key: "apps", label: "Apps", icon: Cpu },
  { key: "shell", label: "Shell", icon: TerminalIcon },
  { key: "files", label: "Files", icon: FolderOpen },
];

const InfoCell = ({ icon: Icon, label, value }) => (
  <div className="border border-border bg-[#0a0a0a] px-3 py-2.5" data-testid={`dev-info-${label.toLowerCase().replace(/\s+/g, "-")}`}>
    <p className="data-label flex items-center gap-1.5">{Icon && <Icon className="w-3 h-3" />} {label}</p>
    <p className="font-mono text-sm text-white mt-1 truncate" title={value}>{value}</p>
  </div>
);

export default function DeviceBridge() {
  const supported = adbBridge.isSupported();
  const diag = adbBridge.diagnostics();
  const adbRef = useRef(null);
  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [device, setDevice] = useState(null);
  const [info, setInfo] = useState(null);
  const [busy, setBusy] = useState("");
  const [tab, setTab] = useState("device");

  const [packages, setPackages] = useState([]);
  const [pkgQuery, setPkgQuery] = useState("");
  const [thirdParty, setThirdParty] = useState(true);

  const [cmd, setCmd] = useState("");
  const [log, setLog] = useState([]);

  const [path, setPath] = useState("/sdcard");
  const [files, setFiles] = useState([]);

  const [shot, setShot] = useState(null);

  const [apkBusy, setApkBusy] = useState("");
  const [apkResult, setApkResult] = useState(null);
  const [apkName, setApkName] = useState("");
  const [apkDialog, setApkDialog] = useState(false);

  useEffect(() => { if (supported) adbBridge.preload(); }, [supported]);

  const analyzeInstalled = async (pkg) => {
    if (apkBusy) return;
    setApkBusy(pkg);
    try {
      toast(`Pulling ${pkg} from device…`);
      const { bytes } = await adbBridge.pullApk(adbRef.current, pkg);
      const file = new File([bytes], `${pkg}.apk`, { type: "application/vnd.android.package-archive" });
      toast(`Analyzing ${(bytes.length / 1048576).toFixed(1)} MB APK…`);
      const data = await analyzeApkFile(file);
      setApkResult(data); setApkName(pkg); setApkDialog(true);
      toast.success(`Analyzed ${pkg} — ${data.finding_count} findings`);
    } catch (e) {
      toast.error(`Analyze failed: ${e.message || e}`);
    } finally { setApkBusy(""); }
  };

  const run = async (label, fn) => {
    setBusy(label);
    try { return await fn(); }
    catch (e) { toast.error(`${label} failed: ${e.message || e}`); throw e; }
    finally { setBusy(""); }
  };

  const connect = async () => {
    setConnecting(true);
    try {
      // STEP 1: request permission synchronously in the gesture (shows the USB chooser)
      let selected;
      try {
        selected = await adbBridge.requestPermission();
      } catch (e) {
        toast.error(e.message || "USB prompt failed");
        return;
      }
      if (!selected) { toast("No device selected — pick your phone in the chooser."); return; }
      toast("Device selected — authorizing… tap 'Allow USB debugging' on your phone.");
      // STEP 2: heavy connect/auth (Tango) after permission
      const { adb, serial, name } = await adbBridge.connectSelected(selected);
      adbRef.current = adb;
      setDevice({ serial, name });
      setConnected(true);
      toast.success("Device connected — reading details…");
      const i = await adbBridge.getInfo(adb);
      setInfo(i);
      loadPackages(adb, thirdParty);
    } catch (e) {
      toast.error(e.message || "Connection failed. Ensure USB debugging is ON and tap Allow on the phone.");
    } finally {
      setConnecting(false);
    }
  };

  const disconnect = async () => {
    if (adbRef.current) await adbBridge.disconnect(adbRef.current);
    adbRef.current = null;
    setConnected(false); setInfo(null); setDevice(null); setPackages([]); setFiles([]); setShot(null); setLog([]);
    toast("Disconnected");
  };

  const refreshInfo = () => run("Refresh", async () => setInfo(await adbBridge.getInfo(adbRef.current)));

  const doPower = async (mode, human) => {
    if (!window.confirm(`Confirm: ${human}? The device will disconnect.`)) return;
    await run(human, () => adbBridge.power(adbRef.current, mode));
    toast.success(`${human} sent`);
    await disconnect();
  };

  const loadPackages = (adb, tp) => run("Load apps", async () => setPackages(await adbBridge.listPackages(adb || adbRef.current, tp)));

  const doScreenshot = () => run("Screenshot", async () => {
    const url = await adbBridge.screenshot(adbRef.current);
    setShot(url);
    toast.success("Screenshot captured");
  });

  const doShell = async (e) => {
    e?.preventDefault();
    if (!cmd.trim()) return;
    const c = cmd.trim();
    setCmd("");
    setLog((l) => [...l, { cmd: c, out: "…" }]);
    try {
      const out = await adbBridge.shell(adbRef.current, c);
      setLog((l) => l.map((x, i) => (i === l.length - 1 ? { cmd: c, out: out || "(no output)" } : x)));
    } catch (err) {
      setLog((l) => l.map((x, i) => (i === l.length - 1 ? { cmd: c, out: `error: ${err.message}` } : x)));
    }
  };

  const browse = (p) => run("List files", async () => { setPath(p); setFiles(await adbBridge.listDir(adbRef.current, p)); });

  const exportSnapshot = () => {
    const snap = { captured_at: new Date().toISOString(), device, info, packages };
    const blob = new Blob([JSON.stringify(snap, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `insafelabs-device-${(info?.model || "snapshot").replace(/\s+/g, "_")}.json`;
    a.click();
    toast.success("Device snapshot exported");
  };

  const filtered = packages.filter((p) => p.toLowerCase().includes(pkgQuery.toLowerCase()));

  return (
    <div className="p-5 md:p-8 space-y-6" data-testid="device-bridge">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="w-11 h-11 border border-primary/40 bg-primary/10 flex items-center justify-center">
          <Usb className="w-5 h-5 text-primary" />
        </div>
        <div className="min-w-0">
          <p className="data-label">Mobile Ops · USB Bridge</p>
          <h1 className="font-heading text-2xl font-bold text-white">Device Bridge</h1>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {connected ? (
            <>
              <span className="inline-flex items-center gap-1.5 data-label text-emerald-400"><PlugZap className="w-3.5 h-3.5" /> connected</span>
              <button onClick={disconnect} data-testid="dev-disconnect" className="border border-border px-3 py-2 text-xs font-mono uppercase tracking-wider text-zinc-300 hover:border-severity-high/50 hover:text-severity-high transition-colors inline-flex items-center gap-1.5"><Plug className="w-3.5 h-3.5" /> Disconnect</button>
            </>
          ) : (
            <button onClick={connect} disabled={!supported || connecting} data-testid="dev-connect"
              className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-50">
              {connecting ? <><Loader2 className="w-4 h-4 animate-spin" /> Requesting…</> : <><Usb className="w-4 h-4" /> Connect USB Device</>}
            </button>
          )}
        </div>
      </div>

      {/* Preview iframe blocks WebUSB — offer to open in a real tab */}
      {supported && diag.inIframe && !connected && (
        <div className="border border-primary/40 bg-primary/5 p-5 flex items-start gap-3" data-testid="dev-iframe-warning">
          <ExternalLink className="w-5 h-5 text-primary shrink-0 mt-0.5" />
          <div className="text-sm text-zinc-300 flex-1">
            <p className="font-semibold text-white">You're inside the preview frame — browsers block WebUSB here.</p>
            <p className="mt-1 text-zinc-400">Open InsafeLabs in a real top-level tab (Chrome/Edge desktop) to let the phone connect.</p>
            <button onClick={() => window.open(window.location.href, "_blank", "noopener")} data-testid="dev-open-tab"
              className="mt-3 bg-primary text-black font-semibold px-4 py-2 inline-flex items-center gap-2 hover:bg-yellow-500 transition-colors">
              <ExternalLink className="w-4 h-4" /> Open in new tab
            </button>
          </div>
        </div>
      )}

      {/* Unsupported browser */}
      {!supported && (
        <div className="border border-severity-high/40 bg-severity-high/5 p-5 flex items-start gap-3" data-testid="dev-unsupported">
          <ShieldAlert className="w-5 h-5 text-severity-high shrink-0 mt-0.5" />
          <div className="text-sm text-zinc-300">
            <p className="font-semibold text-white">WebUSB not available in this browser.</p>
            <p className="mt-1 text-zinc-400">Open InsafeLabs in <b className="text-white">desktop Chrome or Edge</b> to talk to a USB-connected Android device. Firefox/Safari/mobile browsers do not support WebUSB.</p>
          </div>
        </div>
      )}

      {/* Connect instructions */}
      {supported && !connected && (
        <div className="border border-border bg-[#0c0c0c] p-6" data-testid="dev-instructions">
          <p className="data-label mb-3">How to connect</p>
          <ol className="space-y-2 text-sm text-zinc-300 list-decimal list-inside">
            <li>On the Android phone: <b className="text-white">Settings → About phone → tap Build number 7×</b> to unlock Developer Options.</li>
            <li>Open <b className="text-white">Developer options → enable USB debugging</b>.</li>
            <li>Plug the phone into this computer via USB and hit <b className="text-primary">Connect USB Device</b> above.</li>
            <li>On the phone, tap <b className="text-white">Allow</b> for the "Allow USB debugging?" prompt.</li>
          </ol>
          <div className="mt-4 flex items-start gap-2 text-xs text-zinc-500">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-severity-medium" />
            <p>Everything runs locally in your browser over WebUSB — no data leaves your machine. Only your own / authorized devices. iPhones are not supported (Apple blocks ADB/WebUSB). Full factory-wipe & cloning need root and are not available on stock devices.</p>
          </div>

          <div className="mt-4 border-t border-border pt-4" data-testid="dev-troubleshoot">
            <p className="data-label mb-2 flex items-center gap-1.5 text-severity-medium"><AlertTriangle className="w-3.5 h-3.5" /> Phone not detected? (Windows "USB device not recognized")</p>
            <ul className="space-y-1.5 text-sm text-zinc-400 list-disc list-inside">
              <li>Use a proper <b className="text-white">data USB cable</b> — most bundled/cheap cables are <b className="text-white">charge-only</b> (no data lines). This is the #1 cause.</li>
              <li>Pull down the phone's USB notification → set USB mode to <b className="text-white">File transfer / MTP</b> (not "Charging only").</li>
              <li>Try a different USB port (prefer a <b className="text-white">rear USB 2.0</b> port) and avoid USB hubs.</li>
              <li>Confirm the phone shows up in Windows <b className="text-white">File Explorer / Device Manager</b> first — if Windows can't see it, the browser can't either.</li>
              <li>Install your phone's <b className="text-white">OEM USB driver</b> (Samsung/Xiaomi/etc.) or the Google USB driver, then replug.</li>
              <li>If ADB tools are installed, run <span className="font-mono text-primary">adb kill-server</span> and close Android Studio so the port is free.</li>
            </ul>
          </div>
        </div>
      )}

      {/* Connected workspace */}
      {connected && (
        <>
          {/* Action bar */}
          <div className="flex flex-wrap items-center gap-2">
            <button onClick={doScreenshot} disabled={!!busy} data-testid="dev-screenshot" className="btn-tool"><Camera className="w-3.5 h-3.5" /> Screenshot</button>
            <button onClick={refreshInfo} disabled={!!busy} data-testid="dev-refresh" className="btn-tool"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
            <button onClick={exportSnapshot} disabled={!!busy} data-testid="dev-export" className="btn-tool"><Download className="w-3.5 h-3.5" /> Export Snapshot</button>
            <span className="ml-auto data-label truncate max-w-[40%]">{device?.name || device?.serial}</span>
          </div>

          {/* Power controls */}
          <div className="border border-border bg-[#0c0c0c] p-4">
            <p className="data-label mb-3 flex items-center gap-1.5"><Power className="w-3.5 h-3.5 text-primary" /> Power & Recovery</p>
            <div className="flex flex-wrap gap-2">
              <button onClick={() => doPower("reboot", "Reboot")} data-testid="dev-reboot" className="btn-tool"><RotateCcw className="w-3.5 h-3.5" /> Reboot</button>
              <button onClick={() => doPower("recovery", "Reboot to Recovery")} data-testid="dev-recovery" className="btn-tool"><Wrench className="w-3.5 h-3.5" /> Recovery</button>
              <button onClick={() => doPower("bootloader", "Reboot to Bootloader")} data-testid="dev-bootloader" className="btn-tool"><Cpu className="w-3.5 h-3.5" /> Bootloader</button>
              <button onClick={() => doPower("poweroff", "Power Off")} data-testid="dev-poweroff" className="btn-tool !border-severity-high/40 !text-severity-high"><Power className="w-3.5 h-3.5" /> Power Off</button>
              <button onClick={() => run("Open reset", () => adbBridge.openFactoryReset(adbRef.current)).then(() => toast("Opened reset screen on device — confirm there"))} data-testid="dev-factory" className="btn-tool !border-severity-high/40 !text-severity-high"><Eraser className="w-3.5 h-3.5" /> Factory Reset (on device)</button>
            </div>
            <p className="text-[11px] text-zinc-600 mt-2">Factory reset opens the reset screen on the phone (you confirm there) — a full wipe cannot be forced on a stock device.</p>
          </div>

          {/* Tabs */}
          <div className="flex border border-border w-fit" data-testid="dev-tabs">
            {TABS.map(({ key, label, icon: Icon }) => (
              <button key={key} onClick={() => { setTab(key); if (key === "files" && !files.length) browse(path); }}
                data-testid={`dev-tab-${key}`}
                className={`inline-flex items-center gap-1.5 px-4 py-2 text-xs font-mono uppercase tracking-wider transition-colors ${tab === key ? "bg-primary text-black" : "text-zinc-400 hover:text-primary"}`}>
                <Icon className="w-3.5 h-3.5" /> {label}
              </button>
            ))}
          </div>

          {busy && <p className="data-label text-primary flex items-center gap-2"><Loader2 className="w-3.5 h-3.5 animate-spin" /> {busy}…</p>}

          {/* Device tab */}
          {tab === "device" && (
            <div className="grid gap-6 lg:grid-cols-3" data-testid="dev-panel-device">
              <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-3 gap-2">
                {info ? (
                  <>
                    <InfoCell icon={Smartphone} label="Model" value={info.model} />
                    <InfoCell icon={Fingerprint} label="Brand" value={info.brand} />
                    <InfoCell label="Manufacturer" value={info.manufacturer} />
                    <InfoCell label="Android" value={`${info.androidVersion} (SDK ${info.sdk})`} />
                    <InfoCell label="Serial" value={info.serial} />
                    <InfoCell icon={Cpu} label="ABI" value={info.abi} />
                    <InfoCell icon={BatteryFull} label="Battery" value={info.battery} />
                    <InfoCell icon={MonitorSmartphone} label="Screen" value={info.screen} />
                    <InfoCell icon={HardDrive} label="Storage" value={info.storage} />
                    <InfoCell label="Security Patch" value={info.securityPatch} />
                    <InfoCell label="Build" value={info.buildId} />
                    <InfoCell label="Uptime" value={info.uptime} />
                  </>
                ) : <p className="text-sm text-zinc-500 col-span-full">Reading device properties…</p>}
              </div>
              <div className="border border-border bg-[#0a0a0a] p-3">
                <p className="data-label mb-2">Live Screenshot</p>
                {shot ? (
                  <div className="space-y-2">
                    <img src={shot} alt="device screen" className="w-full border border-border max-h-96 object-contain bg-black" data-testid="dev-shot-img" />
                    <a href={shot} download="insafelabs-screen.png" className="btn-tool w-full justify-center"><Download className="w-3.5 h-3.5" /> Save PNG</a>
                  </div>
                ) : <button onClick={doScreenshot} className="btn-tool w-full justify-center"><Camera className="w-3.5 h-3.5" /> Capture screen</button>}
              </div>
            </div>
          )}

          {/* Apps tab */}
          {tab === "apps" && (
            <div className="border border-border bg-[#0c0c0c]" data-testid="dev-panel-apps">
              <div className="flex flex-wrap items-center gap-2 p-3 border-b border-border">
                <div className="relative flex-1 min-w-[180px]">
                  <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <input value={pkgQuery} onChange={(e) => setPkgQuery(e.target.value)} data-testid="dev-app-search" placeholder="filter packages…"
                    className="w-full bg-[#0a0a0a] border border-zinc-800 text-white pl-8 pr-3 py-2 text-sm font-mono focus:outline-none focus:border-primary" />
                </div>
                <button onClick={() => { const tp = !thirdParty; setThirdParty(tp); loadPackages(null, tp); }} data-testid="dev-app-toggle"
                  className="btn-tool">{thirdParty ? "3rd-party only" : "all packages"}</button>
                <span className="data-label">{filtered.length}</span>
              </div>
              <p className="px-4 py-2 text-[11px] text-zinc-500 border-b border-border/60 flex items-center gap-1.5"><Radar className="w-3 h-3 text-primary" /> Tap <b className="text-primary">analyze</b> to pull an app's APK straight off the phone into the Static APK Analyzer — no manual download/upload.</p>
              <div className="divide-y divide-border/60 max-h-[460px] overflow-y-auto">
                {filtered.length === 0 ? <p className="p-6 text-sm text-zinc-500 text-center">No packages.</p> :
                  filtered.map((pkg) => (
                    <div key={pkg} className="flex items-center gap-2 px-4 py-2.5" data-testid={`dev-app-${pkg}`}>
                      <span className="font-mono text-xs text-zinc-300 flex-1 truncate">{pkg}</span>
                      <button onClick={() => analyzeInstalled(pkg)} disabled={!!apkBusy}
                        data-testid={`dev-analyze-${pkg}`} className="text-[10px] font-mono uppercase border border-primary/40 px-2 py-1 text-primary hover:bg-primary/10 disabled:opacity-50 inline-flex items-center gap-1">
                        {apkBusy === pkg ? <Loader2 className="w-3 h-3 animate-spin" /> : <Radar className="w-3 h-3" />} analyze
                      </button>
                      <button onClick={async () => { if (window.confirm(`Clear all data for ${pkg}?`)) { await run("Clear data", () => adbBridge.clearData(adbRef.current, pkg)); toast.success(`Cleared ${pkg}`); } }}
                        data-testid={`dev-clear-${pkg}`} className="text-[10px] font-mono uppercase border border-border px-2 py-1 text-zinc-400 hover:text-severity-medium hover:border-severity-medium/50 inline-flex items-center gap-1"><Eraser className="w-3 h-3" /> clear</button>
                      <button onClick={async () => { if (window.confirm(`Uninstall ${pkg}?`)) { await run("Uninstall", () => adbBridge.uninstall(adbRef.current, pkg)); setPackages((ps) => ps.filter((p) => p !== pkg)); toast.success(`Uninstalled ${pkg}`); } }}
                        data-testid={`dev-uninstall-${pkg}`} className="text-[10px] font-mono uppercase border border-border px-2 py-1 text-zinc-400 hover:text-severity-critical hover:border-severity-critical/50 inline-flex items-center gap-1"><Trash2 className="w-3 h-3" /> remove</button>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Shell tab */}
          {tab === "shell" && (
            <div className="border border-border bg-[#0a0a0a]" data-testid="dev-panel-shell">
              <div className="p-4 h-[380px] overflow-y-auto font-mono text-xs space-y-3 terminal-scroll">
                {log.length === 0 && <p className="text-zinc-600">Run an adb shell command — e.g. <span className="text-primary">getprop ro.product.model</span>, <span className="text-primary">dumpsys battery</span>, <span className="text-primary">ip addr</span></p>}
                {log.map((l, i) => (
                  <div key={i}>
                    <p className="text-primary">$ {l.cmd}</p>
                    <pre className="text-zinc-300 whitespace-pre-wrap break-all">{l.out}</pre>
                  </div>
                ))}
              </div>
              <form onSubmit={doShell} className="flex gap-2 p-3 border-t border-border">
                <input value={cmd} onChange={(e) => setCmd(e.target.value)} data-testid="dev-shell-input" placeholder="adb shell command…"
                  className="flex-1 bg-[#0c0c0c] border border-zinc-800 text-white px-3 py-2 text-sm font-mono focus:outline-none focus:border-primary" />
                <button type="submit" data-testid="dev-shell-run" className="bg-primary text-black font-semibold px-4 inline-flex items-center gap-1.5 hover:bg-yellow-500"><Send className="w-4 h-4" /></button>
              </form>
            </div>
          )}

          {/* Files tab */}
          {tab === "files" && (
            <div className="border border-border bg-[#0c0c0c]" data-testid="dev-panel-files">
              <div className="flex items-center gap-2 p-3 border-b border-border">
                <input value={path} onChange={(e) => setPath(e.target.value)} onKeyDown={(e) => e.key === "Enter" && browse(path)} data-testid="dev-file-path"
                  className="flex-1 bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2 text-sm font-mono focus:outline-none focus:border-primary" />
                <button onClick={() => browse(path)} data-testid="dev-file-go" className="btn-tool"><ChevronRight className="w-3.5 h-3.5" /> Go</button>
                {["/sdcard", "/sdcard/Download", "/sdcard/DCIM", "/data/local/tmp"].map((q) => (
                  <button key={q} onClick={() => browse(q)} className="text-[10px] font-mono border border-border px-2 py-1 text-zinc-500 hover:text-primary hidden lg:inline">{q}</button>
                ))}
              </div>
              <div className="p-4 max-h-[420px] overflow-auto font-mono text-xs text-zinc-300 space-y-0.5">
                {files.length === 0 ? <p className="text-zinc-600">Empty or unreadable path.</p> :
                  files.map((f, i) => <div key={i} className="whitespace-pre hover:bg-white/[0.03] px-1">{f}</div>)}
              </div>
            </div>
          )}
        </>
      )}

      {/* Static APK analysis result (pulled from device) */}
      <Dialog open={apkDialog} onOpenChange={setApkDialog}>
        <DialogContent className="bg-[#0c0c0c] border-border max-w-4xl max-h-[88vh] overflow-y-auto" data-testid="dev-apk-dialog">
          <DialogHeader>
            <DialogTitle className="font-heading flex items-center gap-2"><FileArchive className="w-4 h-4 text-primary" /> Static Analysis · {apkName}</DialogTitle>
          </DialogHeader>
          {apkResult && <ApkResult res={apkResult} />}
        </DialogContent>
      </Dialog>
    </div>
  );
}
