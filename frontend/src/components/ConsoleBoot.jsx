import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Terminal, Cpu, ShieldCheck, Radio } from "lucide-react";

/**
 * ConsoleBoot — the initialization animation shown right after a successful
 * login (while the session is verified). Matches the login's hyperspace jump:
 * it opens with a bright amber flash that fades, then runs a reticle + boot log.
 */
const STEPS = [
  "boot: initializing secure enclave",
  "auth: verifying operator session",
  "intel: syncing threat intelligence",
  "mesh: arming utilities / modules",
  "crypto: handshake aes-256-gcm",
  "console: rendering command center",
];

export function ConsoleBoot() {
  const [pct, setPct] = useState(0);
  const [step, setStep] = useState(0);

  useEffect(() => {
    const start = Date.now();
    const DUR = 1450;
    const t = setInterval(() => {
      const p = Math.min(100, ((Date.now() - start) / DUR) * 100);
      setPct(p);
      setStep(Math.min(STEPS.length, Math.floor((p / 100) * STEPS.length) + 1));
      if (p >= 100) clearInterval(t);
    }, 40);
    return () => clearInterval(t);
  }, []);

  return (
    <motion.div
      key="boot"
      initial={{ opacity: 1 }}
      exit={{ opacity: 0, filter: "blur(8px)", scale: 1.03 }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className="fixed inset-0 z-[60] bg-[#040404] text-white overflow-hidden scanlines"
      data-testid="console-boot"
    >
      <div
        className="absolute inset-0 pointer-events-none opacity-60"
        style={{
          backgroundImage:
            "linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)",
          backgroundSize: "46px 46px",
        }}
      />
      <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(circle at 50% 45%, transparent 20%, rgba(4,4,4,0.72) 75%, #040404 100%)" }} />

      {/* entry flash — blends with the login hyperspace jump */}
      <motion.div
        className="absolute inset-0 pointer-events-none"
        initial={{ opacity: 0.9 }}
        animate={{ opacity: 0 }}
        transition={{ duration: 0.7, ease: "easeOut" }}
        style={{ background: "radial-gradient(circle at 50% 50%, #fff 0%, rgba(250,204,21,0.4) 40%, transparent 72%)" }}
      />

      {/* HUD corners */}
      <div className="absolute inset-0 pointer-events-none font-mono text-[10px] uppercase tracking-widest text-emerald-500/40">
        <span className="absolute top-5 left-6">SYS.NODE // INSAFE-01</span>
        <span className="absolute top-5 right-6 flex items-center gap-1.5">
          <Radio className="w-3 h-3 animate-pulse" /> initializing
        </span>
        <span className="absolute bottom-5 left-6">CHANNEL // <span className="text-primary/70">secure</span></span>
        <span className="absolute bottom-5 right-6">CONSOLE // v2.0</span>
      </div>

      {/* center stack */}
      <div className="relative z-10 min-h-full flex flex-col items-center justify-center px-6">
        <div className="relative w-[300px] h-[300px] flex items-center justify-center">
          <motion.svg
            width="300" height="300" viewBox="0 0 300 300" fill="none"
            stroke="#FACC15" strokeWidth="1" className="absolute inset-0"
            animate={{ rotate: 360 }} transition={{ duration: 14, repeat: Infinity, ease: "linear" }}
          >
            <circle cx="150" cy="150" r="140" strokeDasharray="3 9" opacity="0.5" />
            <circle cx="150" cy="150" r="104" strokeDasharray="2 12" opacity="0.4" />
            <line x1="150" y1="0" x2="150" y2="22" /><line x1="150" y1="278" x2="150" y2="300" />
            <line x1="0" y1="150" x2="22" y2="150" /><line x1="278" y1="150" x2="300" y2="150" />
          </motion.svg>

          <div className="absolute w-[210px] h-[210px] rounded-full radar-sweep overflow-hidden" />
          <motion.div
            className="absolute w-[176px] h-[176px] rounded-full border border-primary/20 border-dashed"
            animate={{ rotate: -360 }} transition={{ duration: 22, repeat: Infinity, ease: "linear" }}
          />

          <motion.div
            className="relative w-16 h-16 bg-primary flex items-center justify-center glow-primary"
            animate={{
              scale: [1, 1.08, 1],
              boxShadow: [
                "0 0 24px -6px rgba(250,204,21,0.5)",
                "0 0 42px -4px rgba(250,204,21,0.85)",
                "0 0 24px -6px rgba(250,204,21,0.5)",
              ],
            }}
            transition={{ duration: 1.6, repeat: Infinity, ease: "easeInOut" }}
          >
            <Terminal className="w-7 h-7 text-black" strokeWidth={2.5} />
          </motion.div>
        </div>

        <h1 className="font-heading font-black text-2xl tracking-tight mt-9 text-glow">InsafeLabs</h1>
        <p className="data-label !text-primary mt-1">command center · booting</p>

        <div className="w-full max-w-md mt-8">
          <div className="flex items-center justify-between text-[11px] font-mono text-zinc-500 mb-1.5">
            <span>initializing console</span>
            <span className="text-primary">{Math.round(pct)}%</span>
          </div>
          <div className="h-1 bg-white/5 overflow-hidden">
            <motion.div className="h-full bg-primary" style={{ width: `${pct}%` }} />
          </div>
        </div>

        <div className="w-full max-w-md mt-5 h-[158px] font-mono text-[11px] space-y-1.5" data-testid="console-boot-log">
          {STEPS.slice(0, step).map((s, i) => (
            <motion.div
              key={s}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3 }}
              className="flex items-center gap-2"
            >
              {i < step - 1
                ? <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                : <Cpu className="w-3.5 h-3.5 text-primary animate-pulse shrink-0" />}
              <span className={i < step - 1 ? "text-zinc-500" : "text-zinc-200"}>{s}</span>
            </motion.div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}
