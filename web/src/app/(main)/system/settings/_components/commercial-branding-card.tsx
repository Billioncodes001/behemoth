"use client";

import * as React from "react";
import { Award, Building2, CheckCircle2, Copy, KeyRound, Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";

export function CommercialBrandingCard() {
  const [licensed, setLicensed] = React.useState(false);
  const [requireLicense, setRequireLicense] = React.useState(false);
  const [maskedKey, setMaskedKey] = React.useState("");
  const [licenseError, setLicenseError] = React.useState("");
  const [claims, setClaims] = React.useState<{
    customer: string;
    tier: string;
    max_workers: number;
    issued_at: string;
    expires_at: string;
  } | null>(null);
  const [licenseInput, setLicenseInput] = React.useState("");
  const [savingLicense, setSavingLicense] = React.useState(false);

  const [brandName, setBrandName] = React.useState("ARTEX");
  const [brandTagline, setBrandTagline] = React.useState(
    "Autonomous AI Security & Penetration Testing Platform",
  );
  const [companyFooter, setCompanyFooter] = React.useState(
    "Prepared by ARTEX Autonomous Security Operations",
  );
  const [reportClassification, setReportClassification] = React.useState(
    "CONFIDENTIAL — AUTHORIZED SECURITY ASSESSMENT",
  );
  const [supportUrl, setSupportUrl] = React.useState("");
  const [savingBranding, setSavingBranding] = React.useState(false);

  const applyStatus = React.useCallback((st: any) => {
    if (!st) return;
    setLicensed(Boolean(st.licensed));
    setRequireLicense(Boolean(st.require_license));
    setMaskedKey(st.masked_key || "");
    setLicenseError(st.license_error || "");
    setClaims(st.claims || null);
    if (st.branding) {
      setBrandName(st.branding.brand_name || "ARTEX");
      setBrandTagline(st.branding.brand_tagline || "");
      setCompanyFooter(st.branding.company_footer || "");
      setReportClassification(st.branding.report_classification || "");
      setSupportUrl(st.branding.support_url || "");
    }
  }, []);

  React.useEffect(() => {
    api.commercial
      .getStatus()
      .then(applyStatus)
      .catch(() => {});
  }, [applyStatus]);

  const handleActivateLicense = async (clear = false) => {
    const key = clear ? "" : licenseInput.trim();
    if (!clear && !key) {
      toast.warning("Paste an ARTEX-LIC-... license key first.");
      return;
    }
    setSavingLicense(true);
    try {
      const st = await api.commercial.activateLicense(key);
      applyStatus(st);
      setLicenseInput("");
      toast.success(
        clear
          ? "Commercial license cleared"
          : `Activated ${st?.claims?.tier || "Commercial"} license for ${st?.claims?.customer || "customer"}`,
      );
    } catch (e: any) {
      toast.error(e?.message || "Failed to verify license key");
    } finally {
      setSavingLicense(false);
    }
  };

  const handleSaveBranding = async () => {
    setSavingBranding(true);
    try {
      const st = await api.commercial.updateBranding({
        brand_name: brandName.trim() || "ARTEX",
        brand_tagline: brandTagline.trim(),
        company_footer: companyFooter.trim(),
        report_classification: reportClassification.trim(),
        support_url: supportUrl.trim(),
      });
      applyStatus(st);
      toast.success("White-label branding & report deliverable headers saved");
    } catch (e: any) {
      toast.error("Failed to save branding: " + (e?.message || String(e)));
    } finally {
      setSavingBranding(false);
    }
  };

  const cliSnippet = `./artex --generate-license --license-customer "Acme Corp" --license-tier Enterprise --license-days 365`;

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Award className="h-4 w-4" />
            <CardTitle className="text-base">Commercial Licensing &amp; White-Label Branding</CardTitle>
          </div>
          {licensed && claims ? (
            <Badge variant="default" className="gap-1 text-xs">
              <CheckCircle2 className="h-3 w-3" />
              {claims.tier} · {claims.customer}
            </Badge>
          ) : (
            <Badge variant={requireLicense ? "destructive" : "secondary"} className="text-xs">
              {requireLicense ? "License Required" : "Vendor / Self-Hosted Edition"}
            </Badge>
          )}
        </div>
        <CardDescription>
          Manage commercial customer license keys and customize white-label product branding on sign-in pages and exported Executive PDF/HTML client deliverables.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {/* Commercial License Section */}
        <div className="space-y-3 rounded-lg border p-3.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-sm font-medium">
              <KeyRound className="h-4 w-4 text-muted-foreground" />
              <span>Customer License Key</span>
            </div>
            {maskedKey && (
              <code className="rounded bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
                {maskedKey}
              </code>
            )}
          </div>

          {licensed && claims ? (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
              <span className="inline-flex items-center gap-1 font-medium">
                <ShieldCheck className="h-3.5 w-3.5" /> Licensed to {claims.customer}
              </span>
              <span>Tier: <strong>{claims.tier}</strong></span>
              <span>Max Workers: <strong>{claims.max_workers}</strong></span>
              <span>Expires: <strong>{new Date(claims.expires_at).toLocaleDateString()}</strong></span>
            </div>
          ) : licenseError ? (
            <p className="text-xs text-destructive">{licenseError}</p>
          ) : null}

          <div className="flex flex-wrap gap-2">
            <Input
              placeholder="ARTEX-LIC-eyJjdXN0b21lciI6..."
              value={licenseInput}
              onChange={(e) => setLicenseInput(e.target.value)}
              className="min-w-[240px] flex-1 font-mono text-xs"
            />
            <Button size="sm" onClick={() => void handleActivateLicense(false)} disabled={savingLicense}>
              {savingLicense ? <Loader2 className="h-4 w-4 animate-spin" /> : "Activate Key"}
            </Button>
            {maskedKey && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => void handleActivateLicense(true)}
                disabled={savingLicense}
              >
                Clear
              </Button>
            )}
          </div>

          <div className="flex items-center justify-between gap-2 rounded bg-muted/40 px-2.5 py-1.5 text-[11px] text-muted-foreground">
            <span className="truncate font-mono" title={cliSnippet}>
              Vendor CLI: {cliSnippet}
            </span>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-6 px-2 text-xs"
              onClick={() => {
                navigator.clipboard.writeText(cliSnippet);
                toast.success("Copied vendor license generator CLI command");
              }}
            >
              <Copy className="h-3 w-3" />
            </Button>
          </div>
        </div>

        {/* White-Label Branding Section */}
        <div className="space-y-3 rounded-lg border p-3.5">
          <div className="flex items-center gap-1.5 text-sm font-medium">
            <Building2 className="h-4 w-4 text-muted-foreground" />
            <span>White-Label &amp; Client Report Branding</span>
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Brand / Product Name</Label>
              <Input
                value={brandName}
                onChange={(e) => setBrandName(e.target.value)}
                placeholder="ARTEX"
                className="text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Header Tagline</Label>
              <Input
                value={brandTagline}
                onChange={(e) => setBrandTagline(e.target.value)}
                placeholder="Autonomous AI Security & Penetration Testing Platform"
                className="text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Report Footer / Consultancy Credit</Label>
              <Input
                value={companyFooter}
                onChange={(e) => setCompanyFooter(e.target.value)}
                placeholder="Prepared by Acme Offensive Security"
                className="text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Deliverable Classification Banner</Label>
              <Input
                value={reportClassification}
                onChange={(e) => setReportClassification(e.target.value)}
                placeholder="CONFIDENTIAL — AUTHORIZED SECURITY ASSESSMENT"
                className="text-sm"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <Button size="sm" onClick={() => void handleSaveBranding()} disabled={savingBranding}>
              {savingBranding ? <Loader2 className="h-4 w-4 animate-spin" /> : "Save Branding"}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
