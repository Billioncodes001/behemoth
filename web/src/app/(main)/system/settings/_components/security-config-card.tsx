"use client";

import * as React from "react";
import { Shield, Plus, Trash2, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";

export function SecurityConfigCard() {
  const [enabled, setEnabled] = React.useState(true);
  const [uaRotation, setUaRotation] = React.useState(true);
  const [headerRandomize, setHeaderRandomize] = React.useState(true);
  const [tlsFingerprinting, setTlsFingerprinting] = React.useState(true);
  const [rateLimit, setRateLimit] = React.useState("120");
  const [blockedIPs, setBlockedIPs] = React.useState<string[]>([]);
  const [newIP, setNewIP] = React.useState("");
  const [tlsProfile, setTlsProfile] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  // Cloudflare Turnstile & Git Auto-Sync settings (single source of truth via /api/settings)
  const [turnstileEnabled, setTurnstileEnabled] = React.useState(true);
  const [turnstileSiteKey, setTurnstileSiteKey] = React.useState("");
  const [turnstileSecretKey, setTurnstileSecretKey] = React.useState("");
  const [turnstileSecretSet, setTurnstileSecretSet] = React.useState(false);
  const [turnstileVerified, setTurnstileVerified] = React.useState(false);
  const [savingTurnstile, setSavingTurnstile] = React.useState(false);
  const [gitAutoSync, setGitAutoSync] = React.useState(true);
  const [syncingGit, setSyncingGit] = React.useState(false);

  const load = React.useCallback(() => {
    api.security
      .getStealthConfig()
      .then((cfg: any) => {
        if (!cfg) return;
        setEnabled(cfg.enabled ?? true);
        setUaRotation(cfg.ua_rotation ?? true);
        setHeaderRandomize(cfg.header_randomize ?? true);
        setTlsFingerprinting(cfg.tls_fingerprinting ?? true);
        setRateLimit(String(cfg.rate_limit_per_min ?? cfg.rate_limit ?? 120));
      })
      .catch(() => {});
    api.security
      .listIOCs()
      .then((r) => setBlockedIPs(Array.isArray(r?.blocked_ips) ? r.blocked_ips : []))
      .catch(() => {});
    api.tls
      .current()
      .then((spec: any) => {
        if (spec?.name) setTlsProfile(spec.name);
      })
      .catch(() => {});
    api
      .settings()
      .then((s: any) => {
        if (!s) return;
        setTurnstileEnabled(s.turnstile_enabled ?? true);
        setTurnstileSiteKey(s.turnstile_site_key ?? "");
        setTurnstileSecretSet(Boolean(s.turnstile_secret_key_set));
        setTurnstileVerified(Boolean(s.turnstile_verified));
        setGitAutoSync(s.git_autosync_enabled ?? true);
      })
      .catch(() => {});
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  const saveStealth = async (patch?: Partial<{
    enabled: boolean;
    ua_rotation: boolean;
    header_randomize: boolean;
    tls_fingerprinting: boolean;
    rate_limit_per_min: number;
  }>) => {
    setSaving(true);
    try {
      const rl = patch?.rate_limit_per_min ?? (parseInt(rateLimit, 10) || 120);
      await api.security.updateStealthConfig({
        enabled: patch?.enabled ?? enabled,
        ua_rotation: patch?.ua_rotation ?? uaRotation,
        header_randomize: patch?.header_randomize ?? headerRandomize,
        tls_fingerprinting: patch?.tls_fingerprinting ?? tlsFingerprinting,
        rate_limit_per_min: rl,
        rate_limit: rl,
        request_jitter: 500000000,
        delay_between_requests: 500000000,
      } as any);
      toast.success("Stealth & Anti-Detection settings saved");
    } catch (e) {
      toast.error("Failed to save stealth config: " + e);
    } finally {
      setSaving(false);
    }
  };

  const addBlockedIP = async () => {
    const ip = newIP.trim();
    if (!ip) return;
    try {
      await api.security.addIOC(ip, "Blocked via Settings UI");
      setNewIP("");
      load();
      toast.success(`Blocked IP ${ip}`);
    } catch (e) {
      toast.error("Failed to block IP: " + e);
    }
  };

  const removeBlockedIP = async (ip: string) => {
    try {
      await api.security.removeIOC(ip);
      load();
      toast.success(`Unblocked IP ${ip}`);
    } catch (e) {
      toast.error("Failed to unblock IP: " + e);
    }
  };

  const saveTurnstileSettings = async (nextEnabled?: boolean, clearKeys?: boolean) => {
    setSavingTurnstile(true);
    try {
      const payload: Record<string, unknown> = {
        turnstile_enabled: nextEnabled ?? turnstileEnabled,
      };
      if (clearKeys) {
        payload.turnstile_site_key = "";
        payload.turnstile_secret_key = "";
      } else if (nextEnabled === undefined) {
        payload.turnstile_site_key = turnstileSiteKey.trim();
        if (turnstileSecretKey.trim() !== "") {
          payload.turnstile_secret_key = turnstileSecretKey.trim();
        }
      }
      const updated: any = await api.setSettings(payload as any);
      setTurnstileEnabled(updated.turnstile_enabled ?? (nextEnabled ?? turnstileEnabled));
      setTurnstileSiteKey(updated.turnstile_site_key ?? (clearKeys ? "" : turnstileSiteKey.trim()));
      setTurnstileSecretSet(Boolean(updated.turnstile_secret_key_set));
      setTurnstileVerified(Boolean(updated.turnstile_verified));
      setTurnstileSecretKey("");
      toast.success(
        updated.turnstile_verified
          ? "Cloudflare Turnstile keys verified — built-in decoy widget disabled"
          : "Cloudflare Turnstile settings saved",
      );
    } catch (e) {
      toast.error("Failed to save Turnstile settings: " + (e as Error).message);
    } finally {
      setSavingTurnstile(false);
    }
  };

  const toggleGitAutoSync = async (next: boolean) => {
    setGitAutoSync(next);
    try {
      await api.setSettings({ git_autosync_enabled: next } as any);
      toast.success(next ? "Automatic Git Live-Sync enabled" : "Automatic Git Live-Sync paused");
    } catch (e) {
      setGitAutoSync(!next);
      toast.error("Failed to update Git Auto-Sync: " + (e as Error).message);
    }
  };

  const triggerManualGitSync = async () => {
    setSyncingGit(true);
    try {
      await api.triggerGitSync();
      toast.success("Triggered repository update check against origin/main");
    } catch (e) {
      toast.error("Failed to trigger Git sync: " + (e as Error).message);
    } finally {
      setSyncingGit(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            <CardTitle className="text-base">Stealth, Anti-Detection &amp; IOC Protection</CardTitle>
          </div>
          {tlsProfile && (
            <Badge variant="outline" className="font-mono text-xs">
              TLS Profile: {tlsProfile}
            </Badge>
          )}
        </div>
        <CardDescription>
          Configure User-Agent rotation, HTTP header randomization, TLS fingerprint spoofing, and IOC IP blocking.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div>
              <Label className="text-sm font-medium">Stealth Mode</Label>
              <p className="text-xs text-muted-foreground">Master switch for anti-detection module</p>
            </div>
            <Switch
              checked={enabled}
              onCheckedChange={(v) => {
                setEnabled(v);
                void saveStealth({ enabled: v });
              }}
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div>
              <Label className="text-sm font-medium">User-Agent Rotation</Label>
              <p className="text-xs text-muted-foreground">Rotate realistic browser User-Agents</p>
            </div>
            <Switch
              checked={uaRotation}
              disabled={!enabled}
              onCheckedChange={(v) => {
                setUaRotation(v);
                void saveStealth({ ua_rotation: v });
              }}
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div>
              <Label className="text-sm font-medium">Header Randomization</Label>
              <p className="text-xs text-muted-foreground">Randomize Accept / Sec-CH-UA headers</p>
            </div>
            <Switch
              checked={headerRandomize}
              disabled={!enabled}
              onCheckedChange={(v) => {
                setHeaderRandomize(v);
                void saveStealth({ header_randomize: v });
              }}
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div>
              <Label className="text-sm font-medium">TLS Fingerprint Spoofing</Label>
              <p className="text-xs text-muted-foreground">Impersonate Chrome/Firefox/Safari JA3/JA4</p>
            </div>
            <Switch
              checked={tlsFingerprinting}
              disabled={!enabled}
              onCheckedChange={(v) => {
                setTlsFingerprinting(v);
                void saveStealth({ tls_fingerprinting: v });
              }}
            />
          </div>
        </div>

        <div className="flex flex-wrap items-end gap-3 rounded-lg border p-3">
          <div className="grid gap-1.5">
            <Label className="text-xs">External IP Rate Limit (requests/min)</Label>
            <Input
              type="number"
              min={10}
              className="w-40 font-mono text-sm"
              value={rateLimit}
              onChange={(e) => setRateLimit(e.target.value)}
            />
          </div>
          <Button size="sm" onClick={() => saveStealth()} disabled={saving}>
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <span>Save Rate Limit</span>}
          </Button>
        </div>

        <div className="space-y-2 rounded-lg border p-3">
          <Label className="text-sm font-medium">IOC IP Blocklist ({blockedIPs.length})</Label>
          <div className="flex gap-2">
            <Input
              placeholder="Enter IP to block (e.g. 203.0.113.50)"
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              className="font-mono text-sm"
            />
            <Button size="sm" variant="outline" onClick={addBlockedIP} disabled={!newIP.trim()}>
              <Plus className="mr-1 h-4 w-4" />
              <span>Block IP</span>
            </Button>
          </div>
          {blockedIPs.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-2">
              {blockedIPs.map((ip) => (
                <Badge key={ip} variant="secondary" className="gap-1.5 font-mono text-xs">
                  <span>{ip}</span>
                  <button
                    type="button"
                    onClick={() => removeBlockedIP(ip)}
                    className="text-muted-foreground hover:text-destructive"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
            </div>
          )}
        </div>

        {/* Cloudflare Turnstile Pre-Login Protection (Single Source of Truth) */}
        <div className="space-y-3 rounded-lg border p-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Label className="text-sm font-medium">Cloudflare Turnstile Pre-Login Gate</Label>
                <Badge variant={turnstileVerified ? "default" : "outline"} className="text-[10px]">
                  {turnstileVerified ? "Cloudflare Verified · Official Widget Only" : "Built-in Auto Gate Active"}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                Requires visitors to pass the Cloudflare Turnstile verification gate before accessing the login screen. Once both your Cloudflare Site Key and Secret Key are verified against Cloudflare <code>siteverify</code>, the built-in decoy widget is automatically removed so visitors see only the single official Cloudflare challenge.
              </p>
            </div>
            <Switch
              checked={turnstileEnabled}
              onCheckedChange={(v) => {
                setTurnstileEnabled(v);
                void saveTurnstileSettings(v);
              }}
            />
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Turnstile Site Key (optional)</Label>
              <Input
                placeholder="0x4AAAAAA... (blank = built-in auto gate)"
                value={turnstileSiteKey}
                disabled={!turnstileEnabled}
                onChange={(e) => setTurnstileSiteKey(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">
                Turnstile Secret Key (optional) {turnstileSecretSet ? "· Configured ✓" : ""}
              </Label>
              <Input
                type="password"
                placeholder={
                  turnstileSecretSet
                    ? "•••••••• (configured — leave blank to keep)"
                    : "0x4AAAAAA... (server-side siteverify secret)"
                }
                value={turnstileSecretKey}
                disabled={!turnstileEnabled}
                onChange={(e) => setTurnstileSecretKey(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={() => void saveTurnstileSettings()} disabled={savingTurnstile}>
              {savingTurnstile ? <Loader2 className="h-4 w-4 animate-spin" /> : "Verify & Save Turnstile Keys"}
            </Button>
            {(turnstileSecretSet || turnstileSiteKey) && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => void saveTurnstileSettings(undefined, true)}
                disabled={savingTurnstile}
              >
                Clear Secret Key
              </Button>
            )}
          </div>
        </div>

        {/* Automatic Git Repository Live-Sync */}
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3">
          <div className="space-y-0.5">
            <Label className="text-sm font-medium">Automatic Git Repository Live-Sync</Label>
            <p className="text-xs text-muted-foreground">
              Automatically polls <code>origin/main</code> (<code>Billioncodes001/myartex</code>) every 60s, displays a live maintenance notice when new commits are pushed, rebuilds, and restarts the server.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => void triggerManualGitSync()} disabled={syncingGit}>
              {syncingGit ? <Loader2 className="h-4 w-4 animate-spin" /> : "Check & Sync Now"}
            </Button>
            <Switch checked={gitAutoSync} onCheckedChange={(v) => void toggleGitAutoSync(v)} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
