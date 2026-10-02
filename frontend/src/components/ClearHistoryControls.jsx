import { useState } from "react";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { Trash2, Download, Loader2 } from "lucide-react";
import {
  AlertDialog, AlertDialogTrigger, AlertDialogContent, AlertDialogHeader, AlertDialogTitle,
  AlertDialogDescription, AlertDialogFooter, AlertDialogCancel, AlertDialogAction,
} from "@/components/ui/alert-dialog";

// Download a full JSON backup of all history collections.
export async function downloadHistoryBackup() {
  const { data, headers } = await api.get("/dashboard/export-history", { responseType: "blob" });
  const name = (headers["content-disposition"] || "").match(/filename="?([^"]+)"?/)?.[1]
    || "insafelabs-history-backup.json";
  const url = window.URL.createObjectURL(new Blob([data], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  window.URL.revokeObjectURL(url);
}

export function ExportHistoryButton({ testId = "export-history-btn", className = "" }) {
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try { await downloadHistoryBackup(); toast.success("Backup downloaded"); }
    catch { toast.error("Could not export backup"); }
    finally { setBusy(false); }
  };
  return (
    <button onClick={run} disabled={busy} data-testid={testId} title="Download a JSON backup of all history"
      className={"inline-flex items-center gap-1.5 text-zinc-500 hover:text-primary transition-colors " + className}>
      {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />} export backup
    </button>
  );
}

// Small "clear" button that wipes a single module's history after confirm + optional backup.
export function ClearModuleButton({ module, label = "clear", onCleared, testId }) {
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const tid = testId || `clear-${module}-btn`;
  const clearIt = async () => {
    setBusy(true);
    try {
      const { data } = await api.post(`/dashboard/clear-history/${module}`);
      toast.success(`Cleared ${data.total_deleted} ${module} records`);
      setOpen(false);
      onCleared && onCleared();
    } catch { toast.error("Could not clear this module"); }
    finally { setBusy(false); }
  };
  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <button data-testid={tid} title={`Clear this module's history`}
          className="inline-flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider border border-zinc-800 px-2 py-1 text-zinc-500 hover:border-severity-critical/50 hover:text-severity-critical transition-colors">
          <Trash2 className="w-3 h-3" /> {label}
        </button>
      </AlertDialogTrigger>
      <AlertDialogContent className="bg-[#0a0a0a] border-border" data-testid={`${tid}-dialog`}>
        <AlertDialogHeader>
          <AlertDialogTitle className="font-heading flex items-center gap-2"><Trash2 className="w-4 h-4 text-severity-critical" /> Clear this module's history?</AlertDialogTitle>
          <AlertDialogDescription className="text-zinc-400">
            This permanently deletes all stored results for the <b className="text-zinc-200">{module}</b> module. This cannot be undone —
            download a backup first if you want to keep it.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="flex items-center gap-3 border border-border bg-[#121212] px-3 py-2">
          <ExportHistoryButton testId={`${tid}-export`} />
          <span className="text-[11px] text-zinc-600 font-mono">recommended before wiping</span>
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel data-testid={`${tid}-cancel`} className="border-border">Cancel</AlertDialogCancel>
          <AlertDialogAction data-testid={`${tid}-confirm`} disabled={busy} onClick={(e) => { e.preventDefault(); clearIt(); }}
            className="bg-severity-critical text-white hover:bg-red-600">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />} Clear {module}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
