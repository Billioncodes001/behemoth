"use client";

import * as React from "react";
import { Loader2Icon, SparklesIcon } from "lucide-react";
import { api } from "@/lib/api";

export function MaintenanceOverlay() {
  const [updating, setUpdating] = React.useState(false);
  const [phase, setPhase] = React.useState("Applying latest repository update and restarting services...");
  const [targetSha, setTargetSha] = React.useState("");
  const wasUpdatingRef = React.useRef(false);

  React.useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;

    async function poll() {
      try {
        const st = await api.maintenanceStatus();
        if (disposed) return;
        if (st.updating) {
          wasUpdatingRef.current = true;
          setUpdating(true);
          if (st.phase) setPhase(st.phase);
          if (st.target_sha) setTargetSha(st.target_sha);
          timer = setTimeout(poll, 2000);
          return;
        }
        if (wasUpdatingRef.current) {
          // Server finished updating and is back online — reload UI cleanly
          wasUpdatingRef.current = false;
          setUpdating(false);
          window.location.reload();
          return;
        }
        setUpdating(false);
        timer = setTimeout(poll, 15000);
      } catch {
        if (disposed) return;
        if (wasUpdatingRef.current) {
          // Expected brief disconnect while binary swaps and restarts
          setPhase("Restarting BEHEMOTH server with updated build — reconnecting...");
          timer = setTimeout(poll, 1500);
        } else {
          timer = setTimeout(poll, 15000);
        }
      }
    }

    timer = setTimeout(poll, 5000);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, []);

  if (!updating) return null;

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-background/85 backdrop-blur-md p-6">
      <div className="w-full max-w-md rounded-2xl border bg-card p-8 text-center shadow-2xl space-y-4">
        <div className="mx-auto flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary">
          <Loader2Icon className="size-7 animate-spin" />
        </div>
        <div className="space-y-1.5">
          <div className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-500">
            <SparklesIcon className="size-3.5" /> Live Repository Auto-Update
          </div>
          <h2 className="text-xl font-semibold tracking-tight">System Update in Progress</h2>
          <p className="text-sm text-muted-foreground leading-relaxed">{phase}</p>
          {targetSha && (
            <p className="font-mono text-xs text-muted-foreground pt-1">
              Target Commit: <span className="text-foreground">{targetSha}</span>
            </p>
          )}
        </div>
        <p className="text-xs text-muted-foreground pt-2">
          Please wait — this dashboard will automatically resume in a few seconds once the update takes effect.
        </p>
      </div>
    </div>
  );
}
