"use client";

import * as React from "react";
import { ShieldCheck, Key, Loader2, RefreshCw, CheckCircle, XCircle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { CaptchaStatus } from "@/lib/types";

const CAPTCHA_MODES: {
  key: keyof CaptchaStatus["capabilities"];
  label: string;
  desc: string;
}[] = [
  { key: "image", label: "Image CAPTCHA", desc: "2Captcha ImageToText + local OCR" },
  { key: "turnstile", label: "Cloudflare Turnstile", desc: "Widgets & Challenge pages" },
  { key: "recaptcha_v2", label: "reCAPTCHA v2", desc: "Checkbox, Invisible & Enterprise" },
  { key: "recaptcha_v3", label: "reCAPTCHA v3", desc: "Score-based & pageAction" },
  { key: "hcaptcha", label: "hCaptcha", desc: "Standard & invisible widgets" },
];

export function CaptchaConfigCard() {
  const [status, setStatus] = React.useState<CaptchaStatus | null>(null);
  const [apiKey, setApiKey] = React.useState("");
  const [savedKey, setSavedKey] = React.useState("");
  const [balance, setBalance] = React.useState<number | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);

  const refresh = React.useCallback(() => {
    api.captcha
      .status()
      .then(setStatus)
      .catch(() => {});
  }, []);

  React.useEffect(() => {
    const cached = localStorage.getItem("behemoth_2captcha_key") || "";
    if (cached) {
      setApiKey(cached);
      setSavedKey(cached);
    }
    refresh();
  }, [refresh]);

  const saveConfig = async (): Promise<boolean> => {
    const val = apiKey.trim();
    if (!val) {
      toast.warning("Please enter your 2Captcha API key before saving.");
      return false;
    }
    if (/\s/.test(val)) {
      toast.warning("Invalid 2Captcha API key: remove spaces or line breaks.");
      return false;
    }
    setSaving(true);
    try {
      await api.captcha.saveConfig({ api_key: val });
      localStorage.setItem("behemoth_2captcha_key", val);
      setSavedKey(val);
      toast.success("2CAPTCHA API key saved — active immediately for all agents");
      refresh();
      return true;
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
      return false;
    } finally {
      setSaving(false);
    }
  };

  const testConfig = async () => {
    const typed = apiKey.trim();
    if (typed && (typed !== savedKey || !status?.configured)) {
      const ok = await saveConfig();
      if (!ok) return;
    }
    setTesting(true);
    try {
      const res = await api.captcha.test(typed ? { api_key: typed } : {});
      setBalance(res.balance);
      refresh();
      toast.success(`2CAPTCHA key verified (Account balance: $${res.balance.toFixed(4)})`);
    } catch (e) {
      toast.error("2CAPTCHA test failed: " + (e instanceof Error ? e.message : String(e)));
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            <CardTitle>2Captcha &amp; Automated CAPTCHA Solver</CardTitle>
          </div>
          <Button variant="outline" size="sm" onClick={refresh}>
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
        </div>
        <CardDescription>
          Solve Image CAPTCHAs, Cloudflare Turnstile, reCAPTCHA v2/v3, and hCaptcha automatically across all agents
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {status && (
          <div className="rounded-md bg-muted p-3">
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm font-medium">Supported CAPTCHA Engines</div>
              {balance !== null && (
                <span className="text-xs font-mono text-emerald-600 dark:text-emerald-400">
                  Balance: ${balance.toFixed(4)}
                </span>
              )}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
              {CAPTCHA_MODES.map(m => {
                const active = status.capabilities?.[m.key] ?? false;
                return (
                  <div
                    key={m.key}
                    className={
                      "flex flex-col gap-0.5 text-xs p-2 rounded-md border " +
                      (active
                        ? "bg-emerald-500/15 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/20 dark:text-emerald-300"
                        : "bg-muted text-muted-foreground border-border")
                    }
                  >
                    <div className="flex items-center gap-1.5 font-medium">
                      {active ? <CheckCircle className="h-3 w-3 shrink-0" /> : <XCircle className="h-3 w-3 shrink-0" />}
                      <span>{m.label}</span>
                    </div>
                    <span className="text-[11px] opacity-80">{m.desc}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        <div className="border rounded-lg p-4 space-y-3">
          <div className="flex items-start justify-between">
            <div>
              <Label className="text-sm font-medium">2Captcha API</Label>
              <p className="text-xs text-muted-foreground">
                Official 2Captcha v2 API (Image CAPTCHA, Cloudflare Turnstile, reCAPTCHA v2, reCAPTCHA v3, hCaptcha)
              </p>
            </div>
            {status?.configured && (
              <span className="text-xs text-green-600 flex items-center gap-1">
                <CheckCircle className="h-3 w-3" /> Active
              </span>
            )}
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Key className="h-3 w-3" />
              API Key
            </div>
            <div className="flex gap-2">
              <Input
                type="password"
                placeholder={
                  status?.configured
                    ? "Configured on server — enter new key to replace"
                    : "Enter 2Captcha API Key"
                }
                value={apiKey}
                onChange={ev => setApiKey(ev.target.value)}
                className="font-mono text-sm"
              />
              <Button size="sm" onClick={() => void saveConfig()} disabled={saving}>
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : "Save"}
              </Button>
              <Button variant="outline" size="sm" onClick={() => void testConfig()} disabled={testing || saving}>
                {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : "Test"}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Env: TWO_CAPTCHA_API_KEY / CAPTCHA_API_KEY (automatically injected into solve_captcha and live agent Bash environments)
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
