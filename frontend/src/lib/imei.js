// Detect color-coded device status badges from an imei.info result object.
// Handles Blacklist (CLEAN/BLACKLISTED), SIM lock (UNLOCKED/SIM LOCKED) and FMI (FMI OFF/ON).
export function statusBadges(result) {
  if (!result || typeof result !== "object") return [];
  const S = (v) => String(v == null ? "" : v).toLowerCase().trim();
  const out = [];
  const push = (good, label) => out.push({ label, color: good ? "#22C55E" : "#EF4444" });

  if (result.device_is_clean !== undefined && result.device_is_clean !== null) {
    const clean = S(result.device_is_clean) === "true";
    push(clean, clean ? "CLEAN" : "BLACKLISTED");
  } else if (result.blacklist_status) {
    const bs = S(result.blacklist_status);
    const clean = bs.includes("clean") || bs === "no" || bs.startsWith("not");
    push(clean, clean ? "CLEAN" : "BLACKLISTED");
  }

  if (result.device_is_unlocked !== undefined && result.device_is_unlocked !== null) {
    const unlocked = S(result.device_is_unlocked) === "true";
    push(unlocked, unlocked ? "UNLOCKED" : "SIM LOCKED");
  } else if (result.sim_lock_status) {
    const ss = S(result.sim_lock_status);
    push(ss.includes("unlock"), ss.includes("unlock") ? "UNLOCKED" : "SIM LOCKED");
  }

  const fmi = result.icloud_lock ?? result.fmi ?? result.find_my_iphone ?? result.icloud_status;
  if (fmi != null && String(fmi) !== "") {
    const f = S(fmi);
    const off = f.includes("off") || f.includes("clean") || f.includes("disab") || f.includes("inactive");
    push(off, off ? "FMI OFF" : "FMI ON");
  }
  return out;
}
