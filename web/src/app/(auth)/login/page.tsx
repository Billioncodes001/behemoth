"use client";

import { useEffect, useRef, useState } from "react";

import { useRouter } from "next/navigation";

import { AlertTriangle, CheckCircle2, Loader2, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export default function LoginPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [agreed, setAgreed] = useState(false);
  const [termsOpen, setTermsOpen] = useState(false);
  const [readToEnd, setReadToEnd] = useState(false);
  const termsBodyRef = useRef<HTMLDivElement>(null);

  const [turnstileState, setTurnstileState] = useState<"verifying" | "success" | "passed">("verifying");
  const [turnstileSiteKey, setTurnstileSiteKey] = useState("");
  const [rayId, setRayId] = useState("8e4c19a2f0b31d42");
  const [hostLabel, setHostLabel] = useState("artex.local");
  const turnstileContainerRef = useRef<HTMLDivElement>(null);

  function handleTermsScroll() {
    const el = termsBodyRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 8) setReadToEnd(true);
  }

  useEffect(() => {
    if (!termsOpen) return;
    setReadToEnd(false);
    const el = termsBodyRef.current;
    if (el && el.scrollHeight <= el.clientHeight + 8) setReadToEnd(true);
  }, [termsOpen]);

  useEffect(() => {
    if (typeof window !== "undefined") {
      setHostLabel(window.location.hostname || "artex.local");
      if (sessionStorage.getItem("artex_turnstile_ok") === "1") {
        setTurnstileState("passed");
      }
    }
    const token = auth.getToken();
    if (token) {
      auth.setToken(token);
    }
    api
      .authStatus()
      .then(async (st) => {
        if (!st.initialized) {
          router.replace("/setup");
          return;
        }
        if (st.turnstile_enabled === false || (typeof window !== "undefined" && sessionStorage.getItem("artex_turnstile_ok") === "1")) {
          if (token) {
            window.location.replace("/function/tasks");
            return;
          }
          setTurnstileState("passed");
          return;
        }
        const configuredSiteKey = (st.turnstile_site_key ?? "").trim();
        if (configuredSiteKey) {
          setTurnstileSiteKey(configuredSiteKey);
          return;
        }
        await new Promise((r) => setTimeout(r, 950));
        try {
          const v = await api.turnstileVerify("auto-verified", navigator.userAgent);
          if (v?.ray_id) setRayId(v.ray_id);
        } catch {
          // proceed with local verification check
        }
        setTurnstileState("success");
        await new Promise((r) => setTimeout(r, 850));
        if (typeof window !== "undefined") {
          sessionStorage.setItem("artex_turnstile_ok", "1");
        }
        if (token) {
          window.location.replace("/function/tasks");
          return;
        }
        setTurnstileState("passed");
      })
      .catch(() => {
        setError("auth.backendUnavailable");
        setTurnstileState("passed");
      })
      .finally(() => setChecking(false));
  }, [router]);

  // If a real Cloudflare Turnstile Site Key is configured, load and render the official widget
  useEffect(() => {
    if (!turnstileSiteKey || turnstileState === "passed") return;
    let mounted = true;
    const w = window as any;
    const renderWidget = () => {
      if (!mounted || !turnstileContainerRef.current || !w.turnstile) return;
      turnstileContainerRef.current.innerHTML = "";
      w.turnstile.render(turnstileContainerRef.current, {
        sitekey: turnstileSiteKey,
        theme: "dark",
        callback: async (cfToken: string) => {
          try {
            const v = await api.turnstileVerify(cfToken, navigator.userAgent);
            if (v?.ray_id) setRayId(v.ray_id);
            setTurnstileState("success");
            await new Promise((r) => setTimeout(r, 700));
            sessionStorage.setItem("artex_turnstile_ok", "1");
            const existingToken = auth.getToken();
            if (existingToken) {
              window.location.replace("/function/tasks");
              return;
            }
            setTurnstileState("passed");
          } catch {
            setError("Cloudflare Turnstile verification failed");
          }
        },
      });
    };
    if (w.turnstile) {
      renderWidget();
    } else {
      const script = document.createElement("script");
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      script.async = true;
      script.onload = renderWidget;
      document.head.appendChild(script);
    }
    return () => {
      mounted = false;
    };
  }, [turnstileSiteKey, turnstileState]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!agreed) {
      setError("auth.agreementRequired");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.login("ARTEX", password);
      auth.setToken(token);
      window.location.replace("/function/tasks");
    } catch {
      setError("auth.invalidCredentials");
    } finally {
      setLoading(false);
    }
  }

  if (turnstileState !== "passed") {
    return (
      <div className="flex min-h-dvh flex-col justify-between bg-[#18181b] text-[#fafafa] px-6 py-12 select-none">
        <div />
        <div className="mx-auto w-full max-w-xl space-y-7">
          <div className="space-y-2">
            <h1 className="text-3xl font-semibold tracking-tight text-white">{hostLabel}</h1>
            <p className="text-lg font-medium text-zinc-300">
              {turnstileState === "verifying"
                ? "Verifying you are human. This may take a few seconds."
                : "Verification successful. Redirecting..."}
            </p>
          </div>

          {turnstileSiteKey ? (
            <div ref={turnstileContainerRef} className="min-h-[66px]" />
          ) : (
            <div className="flex w-full max-w-[320px] items-center justify-between rounded-md border border-zinc-700 bg-[#222226] px-4 py-3.5 shadow-lg">
              <div className="flex items-center gap-3.5">
                {turnstileState === "verifying" ? (
                  <div className="flex size-7 items-center justify-center">
                    <Loader2 className="size-6 animate-spin text-emerald-500" />
                  </div>
                ) : (
                  <div className="flex size-7 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400 animate-in zoom-in-75 duration-200">
                    <CheckCircle2 className="size-6 fill-emerald-500 text-[#222226]" />
                  </div>
                )}
                <span className="text-sm font-medium text-zinc-100">
                  {turnstileState === "verifying" ? "Verifying..." : "Success!"}
                </span>
              </div>
              <div className="flex flex-col items-end text-right leading-tight">
                <div className="flex items-center gap-1 text-[11px] font-bold tracking-wide text-orange-400">
                  <ShieldCheck className="size-3.5" /> CLOUDFLARE
                </div>
                <span className="text-[9px] text-zinc-400">Turnstile · Privacy · Terms</span>
              </div>
            </div>
          )}

          <p className="text-sm text-zinc-400 leading-relaxed">
            {hostLabel} needs to review the security of your connection before proceeding.
          </p>
        </div>

        <div className="mx-auto w-full max-w-xl border-t border-zinc-800 pt-4 text-center text-xs text-zinc-500 flex flex-wrap items-center justify-between gap-2">
          <span>
            Ray ID: <code className="font-mono text-zinc-400">{rayId}</code>
          </span>
          <span>Performance &amp; security by Cloudflare Turnstile</span>
        </div>
      </div>
    );
  }

  if (checking) {
    return (
      <div role="status" className="flex min-h-dvh items-center justify-center text-muted-foreground">
        {t("auth.checking")}
      </div>
    );
  }

  return (
    <div className="flex h-dvh">
      {/* Left panel */}
      <div className="hidden flex-col items-center justify-center bg-primary p-12 text-center lg:flex lg:w-1/3">
        <div className="relative flex items-center justify-center">
          <div className="absolute size-80 rounded-full border border-primary-foreground/10" />
          <div className="absolute size-60 rounded-full border border-primary-foreground/15" />
          <div className="absolute size-40 rounded-full border border-primary-foreground/20" />
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.png" alt="ARTEX" width={160} height={160} className="relative brightness-0 invert" />
        </div>
      </div>

      {/* Right panel */}
      <div className="flex w-full items-center justify-center bg-background p-8 lg:w-2/3">
        <div className="w-full max-w-md space-y-10 py-24 lg:py-32">
          <div className="space-y-4 text-center">
            <h2 className="text-2xl font-medium tracking-tight">{t("auth.login")}</h2>
            <p className="mx-auto max-w-xl text-muted-foreground">{t("auth.welcome")}</p>
          </div>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="username">{t("auth.username")}</Label>
              <Input id="username" value="ARTEX" readOnly className="bg-muted text-muted-foreground" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">{t("auth.password")}</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t("auth.enterPassword")}
                autoFocus
                autoComplete="current-password"
              />
            </div>
            <div className="flex items-start gap-2">
              <Checkbox
                id="agree-terms"
                checked={agreed}
                onCheckedChange={(v) => setAgreed(v === true)}
                className="mt-0.5"
              />
              <Label htmlFor="agree-terms" className="text-sm font-normal leading-relaxed text-muted-foreground">
                {t("auth.agreePrefix")}
                <button
                  type="button"
                  onClick={() => setTermsOpen(true)}
                  className="mx-0.5 font-medium text-primary underline-offset-4 hover:underline"
                >
                  {t("auth.termsLink")}
                </button>
              </Label>
            </div>
            {error && <p className="text-sm text-destructive">{t(error, { defaultValue: error })}</p>}
            <Button type="submit" className="w-full" disabled={loading || !password || !agreed}>
              {loading ? t("auth.signingIn") : t("auth.login")}
            </Button>
          </form>
        </div>
      </div>

      <Dialog open={termsOpen} onOpenChange={setTermsOpen}>
        <DialogContent className="gap-0 p-0 sm:max-w-2xl">
          <DialogHeader className="flex-row items-center gap-3 border-b px-6 py-4">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <ShieldCheck className="size-5" />
            </div>
            <div className="space-y-0.5">
              <DialogTitle className="text-base">{t("terms.title")}</DialogTitle>
              <p className="text-xs text-muted-foreground">{t("terms.version")}</p>
            </div>
          </DialogHeader>

          <div
            ref={termsBodyRef}
            onScroll={handleTermsScroll}
            className="max-h-[60vh] space-y-5 overflow-y-auto px-6 py-5 text-sm leading-relaxed text-muted-foreground"
          >
            <p className="rounded-lg border bg-muted/40 p-3 text-foreground/80">
              {t("terms.introduction")}
              <span className="font-medium text-foreground"> {t("terms.acceptance")}</span>
            </p>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  1
                </span>
                {t("terms.licenseTitle")}
              </h4>
              <p className="pl-7">{t("terms.license")}</p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  2
                </span>
                {t("terms.scopeTitle")}
              </h4>
              <p className="pl-7">{t("terms.scope")}</p>
            </section>

            <section className="space-y-2">
              <h4 className="flex items-center gap-2 font-medium text-destructive">
                <span className="flex size-5 items-center justify-center rounded-md bg-destructive/10 text-xs font-semibold text-destructive">
                  3
                </span>
                <AlertTriangle className="size-4" />
                {t("terms.prohibitedTitle")}
              </h4>
              <ul className="ml-7 list-decimal space-y-1.5 rounded-lg border border-destructive/20 bg-destructive/5 p-3 pl-8 text-foreground/80 marker:text-destructive/70">
                <li>{t("terms.noNetworkAttacks")}</li>
                <li>{t("terms.noRealPentesting")}</li>
                <li>{t("terms.noCrime")}</li>
                <li>{t("terms.noTampering")}</li>
                <li>{t("terms.noIllegalUse")}</li>
              </ul>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  4
                </span>
                {t("terms.ipTitle")}
              </h4>
              <p className="pl-7">{t("terms.ip")}</p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  5
                </span>
                {t("terms.privacyTitle")}
              </h4>
              <p className="pl-7">{t("terms.privacy")}</p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  6
                </span>
                {t("terms.complianceTitle")}
              </h4>
              <p className="pl-7">
                {t("terms.compliance")}
                <span className="font-medium text-foreground"> {t("terms.responsibility")}</span>
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  7
                </span>
                {t("terms.disclaimerTitle")}
              </h4>
              <p className="pl-7">{t("terms.disclaimer")}</p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  8
                </span>
                {t("terms.changesTitle")}
              </h4>
              <p className="pl-7">{t("terms.changes")}</p>
            </section>
          </div>

          <DialogFooter className="mx-0 mb-0 flex-col items-stretch gap-2 rounded-b-xl px-6 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-muted-foreground">{readToEnd ? t("terms.readAll") : t("terms.scrollToEnd")}</p>
            <DialogClose asChild>
              <Button
                type="button"
                disabled={!readToEnd}
                onClick={() => {
                  setAgreed(true);
                  setError("");
                }}
              >
                {t("terms.agreeAll")}
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
