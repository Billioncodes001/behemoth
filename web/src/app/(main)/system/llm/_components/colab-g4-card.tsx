"use client";

import * as React from "react";
import {
  AlertTriangleIcon,
  CheckCircle2Icon,
  CloudIcon,
  ExternalLinkIcon,
  Loader2Icon,
  LogOutIcon,
  PlayIcon,
  RefreshCwIcon,
  SquareIcon,
  TerminalIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

type ColabStatus = Awaited<ReturnType<typeof api.colabG4Status>>;

export function ColabG4Card({ onProfileReady }: { onProfileReady: () => void }) {
  const [status, setStatus] = React.useState<ColabStatus | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState<string | null>(null);
  const [tier, setTier] = React.useState("3.05");
  const [ctxSize, setCtxSize] = React.useState("131072");
  const [autoActivate, setAutoActivate] = React.useState(true);
  const [authCode, setAuthCode] = React.useState("");
  const [showLogs, setShowLogs] = React.useState(false);
  const prevStateRef = React.useRef<string>("");

  const refresh = React.useCallback(
    async (probe = false) => {
      try {
        const next = await api.colabG4Status(probe);
        setStatus(next);
        if (prevStateRef.current === "starting" && next.state === "running") {
          toast.success("Colab G4 GLM-5.3-Flash is live and ready!");
          onProfileReady();
        }
        prevStateRef.current = next.state;
      } catch {
        /* ignore transient poll error */
      } finally {
        setLoading(false);
      }
    },
    [onProfileReady],
  );

  React.useEffect(() => {
    void refresh(true);
  }, [refresh]);

  // Poll live status every 3s while installing, starting, or authenticating.
  React.useEffect(() => {
    const active =
      status?.state === "installing" ||
      status?.state === "starting" ||
      status?.state === "stopping" ||
      status?.auth_in_progress;
    if (!active) return;
    const timer = window.setInterval(() => void refresh(false), 3000);
    return () => window.clearInterval(timer);
  }, [status?.state, status?.auth_in_progress, refresh]);

  async function handleGoogleSignIn() {
    if (busy) return;
    setBusy("auth_start");
    try {
      const res = await api.colabG4AuthStart();
      if (res.already_authenticated) {
        toast.success("Already signed in to Google Colab.");
        await refresh(true);
        return;
      }
      if (res.auth_url) {
        window.open(res.auth_url, "_blank", "noopener,noreferrer");
        toast.info("Google Sign-In opened in a new tab. Approve access, copy the code, and paste it below.");
      }
      await refresh(false);
    } catch (e) {
      toast.error((e as Error).message);
      await refresh(false);
    } finally {
      setBusy(null);
    }
  }

  async function handleCompleteAuth() {
    const trimmed = authCode.trim();
    if (!trimmed || busy) return;
    setBusy("auth_complete");
    try {
      await api.colabG4AuthComplete(trimmed);
      setAuthCode("");
      toast.success("Signed in to Google Colab!");
      await refresh(true);
    } catch (e) {
      toast.error((e as Error).message);
      await refresh(false);
    } finally {
      setBusy(null);
    }
  }

  async function handleLogout() {
    if (busy) return;
    setBusy("logout");
    try {
      await api.colabG4AuthLogout();
      setAuthCode("");
      toast.success("Signed out of Google Colab.");
      await refresh(false);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function handleStart() {
    if (busy) return;
    setBusy("start");
    setShowLogs(true);
    try {
      await api.colabG4Start({
        tier,
        ctx_size: Number(ctxSize),
        auto_activate: autoActivate,
      });
      toast.info("Launching Colab G4 GPU & GLM-5.3-Flash (cold start takes ~10-15 min)...");
      await refresh(false);
    } catch (e) {
      toast.error((e as Error).message);
      await refresh(false);
    } finally {
      setBusy(null);
    }
  }

  async function handleStop() {
    if (busy) return;
    setBusy("stop");
    try {
      await api.colabG4Stop();
      toast.success("Colab G4 VM & tunnel stopped (billing ended).");
      await refresh(true);
    } catch (e) {
      toast.error((e as Error).message);
      await refresh(false);
    } finally {
      setBusy(null);
    }
  }

  async function handleReconnect() {
    if (busy) return;
    setBusy("reconnect");
    try {
      await api.colabG4Reconnect();
      toast.success("SSH tunnel reconnected.");
      await refresh(false);
    } catch (e) {
      toast.error((e as Error).message);
      await refresh(false);
    } finally {
      setBusy(null);
    }
  }

  const stateBadge = (() => {
    if (!status) return { label: "Loading...", cls: "text-muted-foreground" };
    switch (status.state) {
      case "running":
        return {
          label: "Live · Serving",
          cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
        };
      case "starting":
      case "installing":
        return {
          label: status.state === "installing" ? "Installing..." : "Starting GPU...",
          cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
        };
      case "stopping":
        return {
          label: "Stopping...",
          cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
        };
      case "error":
        return {
          label: "Error",
          cls: "border-destructive/40 bg-destructive/10 text-destructive",
        };
      default:
        return { label: "Idle", cls: "text-muted-foreground" };
    }
  })();

  const isRunning = status?.state === "running" || Boolean(status?.tunnel_healthy);
  const isTransitioning =
    status?.state === "installing" || status?.state === "starting" || status?.state === "stopping";

  return (
    <Card className="border-primary/20">
      <CardHeader className="pb-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <CloudIcon className="size-5 text-primary" />
              <CardTitle className="text-base">
                One-Click Self-Hosted LLM · Google Colab G4 (GLM-5.3-Flash Uncensored)
              </CardTitle>
              <Badge variant="outline" className={cn("font-medium", stateBadge.cls)}>
                {isTransitioning && <Loader2Icon className="mr-1 size-3 animate-spin" />}
                {stateBadge.label}
              </Badge>
            </div>
            <CardDescription className="text-xs">
              Run abliterated <strong>GLM-5.3-Flash (321B-A18B)</strong> on a Google Colab G4 GPU (RTX PRO 6000 96 GB,
              up to 102 tok/s, 131K–262K context, ~10.05 CU/hr) with automatic SSH tunneling and zero-config LLM profile
              registration.
            </CardDescription>
          </div>
          <Button
            size="sm"
            variant="outline"
            disabled={loading || Boolean(busy)}
            onClick={() => void refresh(true)}
          >
            <RefreshCwIcon className={cn("mr-1.5 size-3.5", loading && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Google Account Sign-In & Subscription Eligibility */}
        <div className="rounded-lg border bg-muted/20 p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
              <span>Google Colab Account</span>
              {status?.authenticated ? (
                <Badge
                  variant="outline"
                  className="border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                >
                  <CheckCircle2Icon className="mr-1 size-3" />
                  {status.google_email || "Signed in"}
                </Badge>
              ) : (
                <Badge variant="outline" className="text-muted-foreground">
                  Not signed in
                </Badge>
              )}
              {status?.authenticated && !status.has_eligible_subscription && (
                <Badge
                  variant="outline"
                  className="border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                >
                  <AlertTriangleIcon className="mr-1 size-3" />
                  Subscription Required
                </Badge>
              )}
            </div>

            {status?.authenticated && (
              <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => void handleLogout()}>
                {busy === "logout" ? (
                  <Loader2Icon className="mr-1.5 size-3.5 animate-spin" />
                ) : (
                  <LogOutIcon className="mr-1.5 size-3.5" />
                )}
                Switch Account
              </Button>
            )}
          </div>

          {status?.authenticated ? (
            <div className="space-y-2">
              {status.subscription_note && (
                <div
                  className={cn(
                    "flex items-start gap-2 rounded-md border px-3 py-2 text-xs",
                    status.has_eligible_subscription
                      ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300"
                      : "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
                  )}
                >
                  {status.has_eligible_subscription ? (
                    <CheckCircle2Icon className="mt-0.5 size-3.5 shrink-0" />
                  ) : (
                    <AlertTriangleIcon className="mt-0.5 size-3.5 shrink-0" />
                  )}
                  <span>{status.subscription_note}</span>
                </div>
              )}
              {status.usage_summary && (
                <p className="rounded bg-background/80 px-2.5 py-1.5 font-mono text-[11px] text-muted-foreground">
                  {status.usage_summary}
                </p>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-muted-foreground">
                Sign in with a Google account that has an active <strong>Google AI Pro / Ultra</strong> or{" "}
                <strong>Colab Compute Units</strong> plan (~10.05 CU/hr).
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  size="sm"
                  disabled={Boolean(busy) || isTransitioning}
                  onClick={() => void handleGoogleSignIn()}
                >
                  {busy === "auth_start" ? (
                    <Loader2Icon className="mr-1.5 size-3.5 animate-spin" />
                  ) : (
                    <ExternalLinkIcon className="mr-1.5 size-3.5" />
                  )}
                  Sign in with Google
                </Button>
                {status?.auth_url && (
                  <Button size="sm" variant="outline" asChild>
                    <a href={status.auth_url} target="_blank" rel="noopener noreferrer">
                      Open Sign-In Link Again
                    </a>
                  </Button>
                )}
              </div>

              {(status?.auth_in_progress || status?.auth_url) && (
                <div className="space-y-2 rounded-md border border-primary/30 bg-background p-3">
                  <Label htmlFor="colab-oauth-code" className="text-xs font-medium">
                    Paste the Google authorization code from the sign-in tab:
                  </Label>
                  <div className="flex gap-2">
                    <Input
                      id="colab-oauth-code"
                      value={authCode}
                      onChange={(e) => setAuthCode(e.target.value)}
                      placeholder="4/0AeaYSHB..."
                      className="h-8 font-mono text-xs"
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          void handleCompleteAuth();
                        }
                      }}
                    />
                    <Button
                      size="sm"
                      className="h-8 shrink-0"
                      disabled={!authCode.trim() || busy === "auth_complete"}
                      onClick={() => void handleCompleteAuth()}
                    >
                      {busy === "auth_complete" && <Loader2Icon className="mr-1.5 size-3.5 animate-spin" />}
                      Complete Sign-In
                    </Button>
                  </div>
                </div>
              )}

              {status?.auth_error && <p className="text-xs text-destructive">{status.auth_error}</p>}
            </div>
          )}
        </div>

        {/* Launch & Manage Colab G4 GPU */}
        <div className="rounded-lg border bg-muted/20 p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-sm font-medium">Launch &amp; Manage Colab G4 GPU</span>
            {status?.endpoint_url && isRunning && (
              <code className="rounded bg-background px-2 py-0.5 font-mono text-xs text-emerald-600 dark:text-emerald-400">
                {status.endpoint_url} · {status.model_name}
              </code>
            )}
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label className="text-xs">Quantization Tier</Label>
              <Select value={tier} onValueChange={setTier} disabled={isTransitioning || isRunning}>
                <SelectTrigger className="h-9 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="2.51">2.51 bpw · Fastest (~102 tok/s · 10-12m start)</SelectItem>
                  <SelectItem value="3.05">3.05 bpw · Balanced (~95 tok/s · 12-13m start)</SelectItem>
                  <SelectItem value="4.05">4.05 bpw · Q4 Quality (~72 tok/s · 18-20m start)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Context Window</Label>
              <Select value={ctxSize} onValueChange={setCtxSize} disabled={isTransitioning || isRunning}>
                <SelectTrigger className="h-9 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="131072">131K Context (k8v4 KV · Fastest)</SelectItem>
                  <SelectItem value="262144">262K Context (Extended Long Context)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center justify-between rounded-md border bg-background/60 px-3 py-2">
              <div className="space-y-0.5">
                <Label htmlFor="colab-auto-activate" className="text-xs font-medium">
                  Auto-activate LLM profile
                </Label>
                <p className="text-[11px] text-muted-foreground">Set as default once live</p>
              </div>
              <Switch
                id="colab-auto-activate"
                checked={autoActivate}
                onCheckedChange={setAutoActivate}
                disabled={isTransitioning}
              />
            </div>
          </div>

          {status?.phase && status.phase !== "Idle" && (
            <div className="flex items-center gap-2 rounded-md border bg-background px-3 py-2 text-xs">
              {isTransitioning ? (
                <Loader2Icon className="size-3.5 shrink-0 animate-spin text-amber-500" />
              ) : status.state === "error" ? (
                <AlertTriangleIcon className="size-3.5 shrink-0 text-destructive" />
              ) : (
                <CheckCircle2Icon className="size-3.5 shrink-0 text-emerald-500" />
              )}
              <span className="font-medium">{status.phase}</span>
              {status.last_error && <span className="truncate text-destructive">— {status.last_error}</span>}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              disabled={
                !status?.authenticated ||
                !status?.has_eligible_subscription ||
                isTransitioning ||
                isRunning ||
                Boolean(busy)
              }
              onClick={() => void handleStart()}
            >
              {busy === "start" || status?.state === "starting" ? (
                <Loader2Icon className="mr-1.5 size-3.5 animate-spin" />
              ) : (
                <PlayIcon className="mr-1.5 size-3.5" />
              )}
              Start Colab G4 LLM
            </Button>

            <Button
              size="sm"
              variant="outline"
              disabled={!status?.authenticated || isTransitioning || Boolean(busy)}
              onClick={() => void handleReconnect()}
            >
              {busy === "reconnect" ? (
                <Loader2Icon className="mr-1.5 size-3.5 animate-spin" />
              ) : (
                <RefreshCwIcon className="mr-1.5 size-3.5" />
              )}
              Reconnect Tunnel
            </Button>

            <Button
              size="sm"
              variant="destructive"
              disabled={!status?.scripts_installed || Boolean(busy)}
              onClick={() => void handleStop()}
            >
              {busy === "stop" || status?.state === "stopping" ? (
                <Loader2Icon className="mr-1.5 size-3.5 animate-spin" />
              ) : (
                <SquareIcon className="mr-1.5 size-3.5" />
              )}
              Stop & End Billing (0.00 CU/hr)
            </Button>

            <Button
              size="sm"
              variant="ghost"
              className="ml-auto text-xs"
              onClick={() => setShowLogs((v) => !v)}
            >
              <TerminalIcon className="mr-1.5 size-3.5" />
              {showLogs ? "Hide Live Logs" : `Live Logs (${status?.logs?.length ?? 0})`}
            </Button>
          </div>

          {showLogs && (
            <div className="max-h-56 overflow-auto rounded-md border bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-200">
              {status?.logs && status.logs.length > 0 ? (
                status.logs.map((entry, idx) => (
                  <div
                    key={`${entry.timestamp}-${idx}`}
                    className={cn(
                      entry.level === "error" && "text-red-400",
                      entry.level === "warn" && "text-amber-400",
                      entry.level === "ok" && "text-emerald-400",
                    )}
                  >
                    <span className="mr-2 text-zinc-500">[{entry.timestamp}]</span>
                    {entry.message}
                  </div>
                ))
              ) : (
                <span className="text-zinc-500">No launcher logs yet.</span>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
