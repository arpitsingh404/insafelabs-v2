import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { api, isAuthed, clearToken } from "@/lib/api";
import { ConsoleBoot } from "@/components/ConsoleBoot";

// Fail-closed guard: a token being *present* is not the same as being valid.
// We verify it against the server once before rendering the console shell.
// A short boot animation plays while verifying so the jump from the login
// screen flows straight into the console.
const MIN_BOOT_MS = 1500;

export function ProtectedRoute({ children }) {
  const [state, setState] = useState("checking"); // checking | ok | anon

  useEffect(() => {
    let active = true;
    const started = Date.now();
    const finish = (next) => {
      const wait = Math.max(0, MIN_BOOT_MS - (Date.now() - started));
      setTimeout(() => { if (active) setState(next); }, wait);
    };
    if (!isAuthed()) { finish("anon"); return () => { active = false; }; }
    api.get("/auth/me")
      .then(() => finish("ok"))
      .catch(() => { clearToken(); finish("anon"); });
    return () => { active = false; };
  }, []);

  return (
    <AnimatePresence mode="wait">
      {state === "checking" && <ConsoleBoot key="boot" />}
      {state === "ok" && (
        <motion.div
          key="app"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
        >
          {children}
        </motion.div>
      )}
      {state === "anon" && <Navigate key="anon" to="/login" replace />}
    </AnimatePresence>
  );
}
