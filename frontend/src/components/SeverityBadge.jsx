const STYLES = {
  critical: "text-severity-critical bg-severity-critical/10 border-severity-critical/30",
  high: "text-severity-high bg-severity-high/10 border-severity-high/30",
  medium: "text-severity-medium bg-severity-medium/10 border-severity-medium/30",
  low: "text-severity-low bg-severity-low/10 border-severity-low/30",
  info: "text-severity-info bg-severity-info/10 border-severity-info/30",
};

export const SeverityBadge = ({ severity, testId }) => {
  const s = (severity || "info").toLowerCase();
  return (
    <span
      data-testid={testId}
      className={`inline-flex items-center font-mono text-[10px] font-semibold uppercase tracking-[0.15em] px-2 py-0.5 border ${STYLES[s] || STYLES.info}`}
    >
      {s}
    </span>
  );
};

const STATUS_STYLES = {
  open: "text-severity-critical border-severity-critical/30 bg-severity-critical/5",
  new: "text-severity-high border-severity-high/30 bg-severity-high/5",
  triaged: "text-severity-medium border-severity-medium/30 bg-severity-medium/5",
  triaging: "text-severity-medium border-severity-medium/30 bg-severity-medium/5",
  in_progress: "text-severity-low border-severity-low/30 bg-severity-low/5",
  accepted: "text-severity-low border-severity-low/30 bg-severity-low/5",
  resolved: "text-emerald-400 border-emerald-500/30 bg-emerald-500/5",
  false_positive: "text-zinc-500 border-zinc-700 bg-zinc-800/30",
  duplicate: "text-zinc-500 border-zinc-700 bg-zinc-800/30",
  rejected: "text-zinc-500 border-zinc-700 bg-zinc-800/30",
};

export const StatusBadge = ({ status, testId }) => {
  const s = (status || "open").toLowerCase();
  return (
    <span
      data-testid={testId}
      className={`inline-flex items-center font-mono text-[10px] uppercase tracking-[0.12em] px-2 py-0.5 border ${STATUS_STYLES[s] || STATUS_STYLES.open}`}
    >
      {s.replace(/_/g, " ")}
    </span>
  );
};
