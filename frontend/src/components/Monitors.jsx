import { useEffect, useState, useCallback } from "react";
import { api, formatApiError } from "@/lib/api";
import { toast } from "sonner";
import { CalendarClock, Play, Trash2, Loader2, Radar, Bell } from "lucide-react";

const INTERVALS = ["5min", "hourly", "daily", "weekly"];
const inputCls = "bg-[#0a0a0a] border border-zinc-800 text-white px-3 py-2.5 text-sm focus:outline-none focus:border-primary transition-colors";

export function Monitors() {
  const [schedules, setSchedules] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [target, setTarget] = useState("");
  const [interval, setIntervalVal] = useState("daily");
  const [busy, setBusy] = useState(false);
  const [runningId, setRunningId] = useState(null);

  const load = useCallback(async () => {
    const [s, a] = await Promise.all([api.get("/scanner/schedules"), api.get("/scanner/alerts")]);
    setSchedules(s.data);
    setAlerts(a.data);
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async (e) => {
    e.preventDefault();
    if (!target.trim()) { toast.error("Enter a target"); return; }
    setBusy(true);
    try {
      await api.post("/scanner/schedules", { target: target.trim(), interval });
      toast.success("Monitor scheduled");
      setTarget("");
      load();
    } catch (err) {
      toast.error(formatApiError(err.response?.data?.detail) || "Failed");
    } finally {
      setBusy(false);
    }
  };

  const runNow = async (id) => {
    setRunningId(id);
    try {
      const { data } = await api.post(`/scanner/schedules/${id}/run`);
      toast.success(`Scan complete — ${data.finding_count} findings${data.new_findings.length ? `, ${data.new_findings.length} NEW` : ""}`);
      load();
    } catch (err) {
      toast.error(formatApiError(err.response?.data?.detail) || "Run failed");
    } finally {
      setRunningId(null);
    }
  };

  const remove = async (id) => {
    await api.delete(`/scanner/schedules/${id}`);
    toast.success("Monitor removed");
    load();
  };

  return (
    <div className="bg-[#121212] border border-border" data-testid="monitors-panel">
      <div className="flex items-center gap-2 px-6 py-4 border-b border-border">
        <CalendarClock className="w-4 h-4 text-primary" />
        <h3 className="font-heading text-lg font-semibold">Scheduled Monitors &amp; Alerts</h3>
        <span className="ml-auto inline-flex items-center gap-1.5 data-label"><Bell className="w-3.5 h-3.5" /> {alerts.length} alerts</span>
      </div>

      <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: create + schedules */}
        <div className="space-y-4">
          <form onSubmit={create} className="flex flex-col sm:flex-row gap-2" data-testid="monitor-form">
            <input className={`${inputCls} flex-1`} value={target} onChange={(e) => setTarget(e.target.value)} data-testid="monitor-target" placeholder="target.com" />
            <select className={inputCls} value={interval} onChange={(e) => setIntervalVal(e.target.value)} data-testid="monitor-interval">
              {INTERVALS.map((i) => <option key={i} value={i}>{i}</option>)}
            </select>
            <button type="submit" disabled={busy} data-testid="monitor-create" className="bg-primary text-black font-semibold px-4 py-2.5 inline-flex items-center justify-center gap-2 hover:bg-yellow-500 transition-colors disabled:opacity-60">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />} Add
            </button>
          </form>

          <div className="border border-border divide-y divide-border max-h-72 overflow-y-auto">
            {schedules.length === 0 ? (
              <p className="p-5 text-sm text-zinc-500 text-center">No monitors. Schedule recurring scans to auto-detect new exposures.</p>
            ) : schedules.map((s) => (
              <div key={s.id} className="p-4 flex items-center gap-3" data-testid={`schedule-${s.id}`}>
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-white truncate">{s.target}</p>
                  <p className="font-mono text-[10px] text-zinc-600">
                    every {s.interval} · {s.last_finding_count != null ? `${s.last_finding_count} findings` : "not run yet"}
                    {s.next_run ? ` · next ${s.next_run.slice(11, 16)}` : ""}
                  </p>
                </div>
                <button onClick={() => runNow(s.id)} disabled={runningId === s.id} data-testid={`schedule-run-${s.id}`} className="p-2 text-zinc-400 hover:text-primary disabled:opacity-50">
                  {runningId === s.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                </button>
                <button onClick={() => remove(s.id)} data-testid={`schedule-del-${s.id}`} className="p-2 text-zinc-500 hover:text-severity-critical">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Right: alerts */}
        <div className="border border-border divide-y divide-border max-h-[336px] overflow-y-auto" data-testid="monitor-alerts">
          {alerts.length === 0 ? (
            <p className="p-5 text-sm text-zinc-500 text-center">No new-exposure alerts. When a monitored target exposes something new, it appears here.</p>
          ) : alerts.map((a, i) => (
            <div key={i} className="p-4" data-testid={`monitor-alert-${i}`}>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-white truncate">{a.target}</span>
                <span className="ml-auto text-[10px] uppercase tracking-widest text-severity-high border border-severity-high/40 px-1.5 py-0.5">{a.count} new</span>
              </div>
              <p className="text-xs text-zinc-400 mt-1.5">{(a.new_findings || []).slice(0, 4).join(" · ")}</p>
              <p className="data-label mt-1">{a.created_at?.slice(0, 16).replace("T", " ")}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
