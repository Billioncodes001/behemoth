"use client";

import React from "react";
import { toast } from "sonner";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api } from "@/lib/api";
import type { ProxyV2Entry, ProxyV2Stats, ProxyV2SwitchLog, ProxyV2Config } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  RefreshCw, Upload, Trash2, Play, CheckCircle2, XCircle,
  Loader2, Globe, Activity, Zap, Settings, MapPin, Clock, FileUp, ShieldCheck, ShieldAlert,
  Sparkles, Terminal, Square, ExternalLink, Radar,
} from "lucide-react";

type ProxyStatus = "healthy" | "unhealthy" | "untested" | "unknown" | "in_use" | "disabled";

export default function ProxyPoolPage() {
  const { t } = useLiveTranslation();
  const [proxies, setProxies] = React.useState<ProxyV2Entry[]>([]);
  const [stats, setStats] = React.useState<ProxyV2Stats>({
    total: 0, healthy: 0, unhealthy: 0, unknown: 0, disabled: 0,
    avg_latency_ms: 0, total_requests: 0, success_rate: 0,
  });
  const [logs, setLogs] = React.useState<ProxyV2SwitchLog[]>([]);
  const [config, setConfig] = React.useState<ProxyV2Config | null>(null);
  const [importOpen, setImportOpen] = React.useState(false);
  const [importText, setImportText] = React.useState("");
  const [selectedFiles, setSelectedFiles] = React.useState<File[]>([]);
  const [defaultType, setDefaultType] = React.useState<string>("http");
  const [autoTestOnImport, setAutoTestOnImport] = React.useState(true);
  const [replaceExisting, setReplaceExisting] = React.useState(false);
  const [dragOver, setDragOver] = React.useState(false);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);
  const quickFileInputRef = React.useRef<HTMLInputElement | null>(null);

  const [testing, setTesting] = React.useState<string | null>(null);
  const [testingAll, setTestingAll] = React.useState(false);
  const [importing, setImporting] = React.useState(false);
  const [savingConfig, setSavingConfig] = React.useState(false);
  const [loading, setLoading] = React.useState(true);

  const [poolEnabled, setPoolEnabled] = React.useState(false);
  const [rotationStrategy, setRotationStrategy] = React.useState<string>("round_robin");
  const [rotationInterval, setRotationInterval] = React.useState("30");
  const [autoRotateOnFailure, setAutoRotateOnFailure] = React.useState(true);
  const [healthInterval, setHealthInterval] = React.useState("30");
  const [maxFailures, setMaxFailures] = React.useState("3");
  const [cooldown, setCooldown] = React.useState("60");
  const [sessionSticky, setSessionSticky] = React.useState(true);
  const [torStatus, setTorStatus] = React.useState<{
    installed: boolean;
    daemon_running: boolean;
    mode?: "exclusive" | "hybrid";
    enabled_in_pool: boolean;
    exclusive_active?: boolean;
    hybrid_pool_active?: boolean;
    suspended_pool_count?: number;
    circuits_total: number;
    circuits_healthy: number;
    exit_ips?: string[];
  } | null>(null);
  const [torCircuits, setTorCircuits] = React.useState<string>("5");
  const [torMode, setTorMode] = React.useState<"exclusive" | "hybrid">("exclusive");
  const [torBusy, setTorBusy] = React.useState(false);

  const [scraper, setScraper] = React.useState<Awaited<ReturnType<typeof api.proxyV2.getScraperStatus>> | null>(null);
  const [scraperEnabled, setScraperEnabled] = React.useState(false);
  const [scraperAIEnabled, setScraperAIEnabled] = React.useState(true);
  const [scraperAutoEnablePool, setScraperAutoEnablePool] = React.useState(true);
  const [scraperInterval, setScraperInterval] = React.useState("30");
  const [scraperMaxProxies, setScraperMaxProxies] = React.useState("25");
  const [scraperMaxLatency, setScraperMaxLatency] = React.useState("4500");
  const [scraperProtoMode, setScraperProtoMode] = React.useState<"both" | "socks5" | "http">("http");
  const [scraperCountryMode, setScraperCountryMode] = React.useState<"us_preferred" | "us_only" | "all">("us_preferred");
  const [webshareApiKey, setWebshareApiKey] = React.useState("");
  const [webshareKeySaved, setWebshareKeySaved] = React.useState(false);
  const [scraperBusy, setScraperBusy] = React.useState(false);
  const scraperConfigHydratedRef = React.useRef(false);
  const logEndRef = React.useRef<HTMLDivElement | null>(null);


  const fetchData = React.useCallback(async () => {
    try {
      const [proxyList, poolStats, switchLogs, poolConfig, torSnap, scraperSnap] = await Promise.all([
        api.proxyV2.listProxies().catch(() => []),
        api.proxyV2.getStats().catch(() => null),
        api.proxyV2.getLogs().catch(() => []),
        api.proxyV2.getConfig().catch(() => null),
        api.proxyV2.getTorStatus().catch(() => null),
        api.proxyV2.getScraperStatus().catch(() => null),
      ]);
      setProxies(Array.isArray(proxyList) ? proxyList : []);
      if (torSnap) {
        setTorStatus(torSnap);
        if (torSnap.mode === "exclusive" || torSnap.mode === "hybrid") {
          setTorMode(torSnap.mode);
        }
      }
      if (scraperSnap) {
        setScraper(scraperSnap);
        setWebshareKeySaved(Boolean(scraperSnap.config?.webshare_key_saved));
        if (!scraperConfigHydratedRef.current && scraperSnap.config) {
          scraperConfigHydratedRef.current = true;
          setScraperEnabled(Boolean(scraperSnap.config.enabled));
          setScraperAIEnabled(scraperSnap.config.ai_agent_enabled !== false);
          setScraperAutoEnablePool(scraperSnap.config.auto_enable_pool !== false);
          setScraperInterval(String(scraperSnap.config.interval_minutes ?? 30));
          setScraperMaxProxies(String(scraperSnap.config.max_proxies ?? 25));
          setScraperMaxLatency(String(scraperSnap.config.max_latency_ms ?? 4500));
          const protos = scraperSnap.config.protocols || ["http"];
          if (protos.includes("socks5") && protos.includes("http")) setScraperProtoMode("both");
          else if (protos.includes("socks5")) setScraperProtoMode("socks5");
          else setScraperProtoMode("http");
          const cm = scraperSnap.config.country_mode;
          if (cm === "us_only" || cm === "all" || cm === "us_preferred") {
            setScraperCountryMode(cm);
          }
        }
      }
      if (poolStats) {
        setStats({
          total: poolStats.total ?? 0,
          healthy: poolStats.healthy ?? 0,
          unhealthy: poolStats.unhealthy ?? 0,
          unknown: (poolStats as any).untested ?? poolStats.unknown ?? 0,
          disabled: poolStats.disabled ?? 0,
          active_proxy_id: poolStats.active_proxy_id,
          avg_latency_ms: poolStats.avg_latency_ms ?? 0,
          total_requests: poolStats.total_requests ?? 0,
          success_rate: poolStats.success_rate ?? 0,
        });
      }
      setLogs(Array.isArray(switchLogs) ? switchLogs : []);
      if (poolConfig) {
        setConfig(poolConfig);
        setPoolEnabled(Boolean(poolConfig.enabled));
        const mode = (poolConfig as any).rotation_mode || poolConfig.rotation_strategy || "round_robin";
        setRotationStrategy(mode);
        setRotationInterval(String(poolConfig.rotation_interval_seconds ?? 30));
        setAutoRotateOnFailure(poolConfig.auto_rotate_on_failure !== false);
        setHealthInterval(String(poolConfig.health_check_interval_seconds ?? 30));
        setMaxFailures(String(poolConfig.max_consecutive_failures ?? 3));
        setCooldown(String(poolConfig.cooldown_seconds ?? 60));
        setSessionSticky(Boolean(poolConfig.session_sticky));
      }
    } catch {
      // Ignore transient fetch errors so Next.js dev overlay does not pop up
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => { fetchData(); }, [fetchData]);

  // Auto-poll live scraping log & pool state while Online Scraper or AI Harvester is running
  React.useEffect(() => {
    if (!scraper?.running && !scraper?.ai_running) return;
    const tmr = setInterval(() => {
      void fetchData();
    }, 1800);
    return () => clearInterval(tmr);
  }, [scraper?.running, scraper?.ai_running, fetchData]);

  const handleFilesChosen = (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    const arr = Array.from(fileList);
    setSelectedFiles((prev) => [...prev, ...arr]);
  };

  const handleQuickFileUpload = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    const files = Array.from(fileList);
    setImporting(true);
    try {
      const r = await api.proxyV2.uploadProxiesFiles(files, {
        default_type: defaultType,
        auto_test: true,
        replace_existing: false,
      });
      const summaryParts = [`Imported ${r.imported} proxies`];
      if (r.skipped) summaryParts.push(`${r.skipped} duplicates skipped`);
      if (typeof r.tested === "number" && r.tested > 0) {
        summaryParts.push(`tested ${r.tested} (${r.healthy ?? 0} healthy, ${r.failed ?? 0} failed)`);
      }
      if (r.errors?.length) {
        toast.warning(`${summaryParts.join(" · ")} (${r.errors.length} parse errors)`);
      } else {
        toast.success(summaryParts.join(" · "));
      }
      await fetchData();
    } catch (e: any) {
      toast.error("File upload failed: " + (e?.message || String(e)));
    } finally {
      setImporting(false);
      if (quickFileInputRef.current) quickFileInputRef.current.value = "";
    }
  };

  const handleImport = async () => {
    if (!importText.trim() && selectedFiles.length === 0) {
      toast.warning("Paste proxy lines or upload a proxy file (.txt, .csv, .json) first.");
      return;
    }
    setImporting(true);
    try {
      const r =
        selectedFiles.length > 0
          ? await api.proxyV2.uploadProxiesFiles(selectedFiles, {
              data: importText.trim() || undefined,
              default_type: defaultType,
              auto_test: autoTestOnImport,
              replace_existing: replaceExisting,
            })
          : await api.proxyV2.importProxies({
              data: importText,
              default_type: defaultType,
              auto_test: autoTestOnImport,
              replace_existing: replaceExisting,
            });
      const summaryParts = [`Imported ${r.imported} proxies`];
      if (r.skipped) summaryParts.push(`${r.skipped} duplicates skipped`);
      if (typeof r.tested === "number" && r.tested > 0) {
        summaryParts.push(`tested ${r.tested} (${r.healthy ?? 0} healthy, ${r.failed ?? 0} failed)`);
      }
      if (r.errors?.length) {
        toast.warning(`${summaryParts.join(" · ")} (${r.errors.length} parse errors)`);
      } else {
        toast.success(summaryParts.join(" · "));
      }
      setImportText("");
      setSelectedFiles([]);
      setImportOpen(false);
      await fetchData();
    } catch (e: any) {
      toast.error("Import failed: " + (e?.message || String(e)));
    } finally {
      setImporting(false);
    }
  };

  const handleTestOne = async (id: string) => {
    setTesting(id);
    try {
      const res = await api.proxyV2.proxyAction(id, "test");
      if (res?.success === false) {
        toast.error(`Proxy check failed: ${res.error || "unreachable"}`);
      } else {
        toast.success(`Proxy healthy${res?.response_ip ? ` · Exit IP ${res.response_ip}` : ""}${res?.latency_ms ? ` (${res.latency_ms}ms)` : ""}`);
      }
      await fetchData();
    } catch (e: any) {
      toast.error("Proxy test failed: " + (e?.message || String(e)));
    } finally {
      setTesting(null);
    }
  };

  const handleTestAll = async () => {
    if (proxies.length === 0) {
      toast.warning("No proxies in the pool to test. Import proxies first.");
      return;
    }
    setTestingAll(true);
    try {
      const res = await api.proxyV2.testAll();
      const s = res?.summary;
      if (s) {
        toast.success(`Tested ${s.total} proxies: ${s.passed} healthy, ${s.failed} failed`);
      } else {
        toast.success("Completed health check for all proxies");
      }
      await fetchData();
    } catch (e: any) {
      toast.error("Test all failed: " + (e?.message || String(e)));
    } finally {
      setTestingAll(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.proxyV2.deleteProxy(id);
      toast.success("Proxy deleted");
      await fetchData();
    } catch (e: any) {
      toast.error("Delete failed: " + (e?.message || String(e)));
    }
  };

  const handleActivate = async (id: string) => {
    try {
      await api.proxyV2.proxyAction(id, "activate");
      toast.success("Proxy selected and now in use");
      await fetchData();
    } catch (e: any) {
      toast.error("Activate failed: " + (e?.message || String(e)));
    }
  };

  const handleStopUsing = async (id: string) => {
    try {
      await api.proxyV2.proxyAction(id, "deactivate");
      toast.success("Stopped using proxy — no proxy is currently in use");
      await fetchData();
    } catch (e: any) {
      toast.error("Stop using failed: " + (e?.message || String(e)));
    }
  };

  const handleToggle = async (id: string, currentlyDisabled: boolean) => {
    try {
      await api.proxyV2.proxyAction(id, "toggle");
      toast.success(currentlyDisabled ? "Proxy enabled in pool" : "Proxy disabled");
      await fetchData();
    } catch (e: any) {
      toast.error("Toggle failed: " + (e?.message || String(e)));
    }
  };

  const handleClearFailed = async () => {
    if (proxies.length === 0) {
      toast.warning("No proxies in the pool.");
      return;
    }
    try {
      const r = await api.proxyV2.clearFailed();
      toast.success(`${r.cleared ?? 0} failed proxies removed`);
      await fetchData();
    } catch (e: any) {
      toast.error("Clear failed: " + (e?.message || String(e)));
    }
  };

  const handleClearAll = async () => {
    if (proxies.length === 0) {
      toast.warning("No proxies in the pool.");
      return;
    }
    try {
      const r = await api.proxyV2.clearAll();
      toast.success(`Cleared all ${r.cleared ?? 0} proxies`);
      await fetchData();
    } catch (e: any) {
      toast.error("Clear all failed: " + (e?.message || String(e)));
    }
  };

  const persistPoolConfig = async (nextEnabled: boolean, showToast = true) => {
    const rotSec = Math.max(5, parseInt(rotationInterval) || 30);
    const hlthSec = Math.max(10, parseInt(healthInterval) || 30);
    const maxF = Math.max(1, parseInt(maxFailures) || 3);
    const coolSec = Math.max(10, parseInt(cooldown) || 60);
    setSavingConfig(true);
    try {
      await api.proxyV2.updateConfig({
        enabled: nextEnabled,
        rotation_strategy: rotationStrategy as any,
        rotation_interval_seconds: rotSec,
        auto_rotate_on_failure: autoRotateOnFailure,
        health_check_interval_seconds: hlthSec,
        max_consecutive_failures: maxF,
        cooldown_seconds: coolSec,
        session_sticky: sessionSticky,
      });
      setPoolEnabled(nextEnabled);
      setConfig((prev) => (prev ? { ...prev, enabled: nextEnabled } : ({ enabled: nextEnabled } as ProxyV2Config)));
      if (showToast) {
        toast.success("Proxy pool configuration saved");
      }
      await fetchData();
    } catch (e: any) {
      toast.error("Save failed: " + (e?.message || String(e)));
    } finally {
      setSavingConfig(false);
    }
  };

  const handleTogglePoolEnabled = async (checked: boolean) => {
    const wasExclusiveTor = Boolean(torStatus?.exclusive_active);
    setPoolEnabled(checked);
    await persistPoolConfig(checked, false);
    toast.success(
      checked
        ? wasExclusiveTor
          ? "Proxy Pool enabled — Exclusive Tor automatically shut down"
          : "Proxy Pool enabled — outbound target & scanner traffic now routes through the pool"
        : "Proxy Pool disabled — target traffic connects directly (unless a static Global Proxy is set)",
    );
  };

  const handleSaveConfig = async () => {
    await persistPoolConfig(poolEnabled, true);
  };

  const handleForceRotate = async () => {
    if (proxies.length === 0) {
      toast.warning("No proxies in the pool to rotate. Import proxies first.");
      return;
    }
    try {
      await api.proxyV2.forceRotate();
      toast.success("Rotated to next available proxy");
      await fetchData();
    } catch (e: any) {
      toast.error("Rotate failed: " + (e?.message || String(e)));
    }
  };

  const handleEnableTor = async (overrideMode?: "exclusive" | "hybrid") => {
    setTorBusy(true);
    try {
      const count = Math.max(1, Math.min(10, parseInt(torCircuits) || 5));
      const useMode = overrideMode || torMode;
      const res = await api.proxyV2.enableTor(count, useMode);
      toast.success(
        useMode === "exclusive"
          ? `Exclusive Tor enabled (${res.circuits_healthy}/${res.circuits_total} circuits) — Proxy Pool auto-disabled & running agents switched immediately`
          : `Hybrid Tor + Pool enabled (${res.circuits_healthy}/${res.circuits_total} Tor circuits + active pool proxies)`,
      );
      await fetchData();
    } catch (e: any) {
      toast.error("Enable Tor failed: " + (e?.message || String(e)));
    } finally {
      setTorBusy(false);
    }
  };

  const handleTorModeChange = async (nextMode: "exclusive" | "hybrid") => {
    setTorMode(nextMode);
    if (torStatus?.enabled_in_pool) {
      await handleEnableTor(nextMode);
    }
  };

  const buildScraperConfigPayload = (
    overrides?: Partial<{ enabled: boolean; ai_agent_enabled: boolean; webshare_api_key: string }>,
  ) => {
    const protocols =
      scraperProtoMode === "socks5" ? ["socks5"] : scraperProtoMode === "http" ? ["http"] : ["http", "socks5"];
    const keyToSend = overrides?.webshare_api_key !== undefined ? overrides.webshare_api_key : webshareApiKey.trim();
    return {
      enabled: overrides?.enabled !== undefined ? overrides.enabled : scraperEnabled,
      ai_agent_enabled: overrides?.ai_agent_enabled !== undefined ? overrides.ai_agent_enabled : scraperAIEnabled,
      auto_enable_pool: scraperAutoEnablePool,
      interval_minutes: Math.max(5, parseInt(scraperInterval) || 30),
      max_proxies: Math.max(3, Math.min(100, parseInt(scraperMaxProxies) || 25)),
      max_latency_ms: Math.max(500, Math.min(15000, parseInt(scraperMaxLatency) || 4500)),
      protocols,
      country_mode: scraperCountryMode,
      ...(keyToSend ? { webshare_api_key: keyToSend } : {}),
    };
  };

  const handleSaveScraperConfig = async (
    overrides?: Partial<{ enabled: boolean; ai_agent_enabled: boolean; webshare_api_key: string }>,
    silent = false,
  ) => {
    setScraperBusy(true);
    try {
      const payload = buildScraperConfigPayload(overrides);
      const snap = await api.proxyV2.saveScraperConfig(payload);
      setScraper(snap);
      setWebshareKeySaved(Boolean(snap?.config?.webshare_key_saved));
      if (webshareApiKey.trim()) {
        setWebshareApiKey("");
      }
      if (!silent) {
        toast.success(
          payload.enabled
            ? "Online Proxy Scraper enabled — scraping & verifying proxies automatically"
            : "Online Proxy Scraper settings saved",
        );
      }
      await fetchData();
    } catch (e: any) {
      toast.error("Save scraper settings failed: " + (e?.message || String(e)));
    } finally {
      setScraperBusy(false);
    }
  };

  const handleRunScraperNow = async () => {
    setScraperBusy(true);
    try {
      await api.proxyV2.saveScraperConfig(buildScraperConfigPayload());
      const snap = await api.proxyV2.runScraperNow();
      setScraper(snap);
      toast.success("Started online proxy scraping & 2-stage HTTPS/Elite verification");
      await fetchData();
    } catch (e: any) {
      toast.error("Start scraper failed: " + (e?.message || String(e)));
    } finally {
      setScraperBusy(false);
    }
  };

  const handleRunHarvesterAgent = async () => {
    setScraperBusy(true);
    try {
      const res = await api.proxyV2.runScraperAgentNow();
      toast.success(
        res.conversation_id
          ? `Launched autonomous Proxy Harvester agent (Conversation #${res.conversation_id})`
          : "Proxy Harvester agent started",
      );
      await fetchData();
    } catch (e: any) {
      toast.error("Launch AI Harvester failed: " + (e?.message || String(e)));
    } finally {
      setScraperBusy(false);
    }
  };

  const handleStopScraper = async () => {
    try {
      const snap = await api.proxyV2.stopScraper();
      setScraper(snap);
      toast.info("Stopped active proxy scrape");
    } catch (e: any) {
      toast.error("Stop failed: " + (e?.message || String(e)));
    }
  };

  const handleClearScraped = async () => {
    setScraperBusy(true);
    try {
      const snap = await api.proxyV2.clearScrapedProxies();
      setScraper(snap);
      toast.success("Removed scraped proxies from pool and cleared scrape log");
      await fetchData();
    } catch (e: any) {
      toast.error("Clear scraped failed: " + (e?.message || String(e)));
    } finally {
      setScraperBusy(false);
    }
  };

  const handleDisableTor = async () => {
    setTorBusy(true);
    try {
      await api.proxyV2.disableTor();
      toast.success("Tor circuits removed from Proxy Pool");
      await fetchData();
    } catch (e: any) {
      toast.error("Disable Tor failed: " + (e?.message || String(e)));
    } finally {
      setTorBusy(false);
    }
  };

  const handleRotateTor = async () => {
    setTorBusy(true);
    try {
      const res = await api.proxyV2.rotateTorIdentity();
      toast.success(
        `Assigned fresh Tor exit circuits (${res.circuits_healthy}/${res.circuits_total} healthy)`,
      );
      await fetchData();
    } catch (e: any) {
      toast.error("Tor circuit rotation failed: " + (e?.message || String(e)));
    } finally {
      setTorBusy(false);
    }
  };

  const statusBadge = (status: ProxyStatus, isActiveEgress: boolean) => {
    const healthy = { label: "Healthy", variant: "default" as const, icon: <CheckCircle2 className="w-3 h-3" /> };
    const failed = { label: "Failed", variant: "destructive" as const, icon: <XCircle className="w-3 h-3" /> };
    const unknown = { label: "Untested", variant: "secondary" as const, icon: <span className="w-3 h-3">?</span> };
    const disabled = { label: "Disabled", variant: "outline" as const, icon: <span className="w-3 h-3">-</span> };
    const map: Record<ProxyStatus, { label: string; variant: "default" | "destructive" | "secondary" | "outline"; icon: React.ReactNode }> = {
      healthy,
      in_use: healthy,
      unhealthy: failed,
      untested: unknown,
      unknown,
      disabled,
    };
    const s = map[status] || unknown;
    return (
      <div className="flex items-center gap-1.5">
        <Badge variant={s.variant} className="gap-1">{s.icon}<span>{s.label}</span></Badge>
        {isActiveEgress && poolEnabled && (
          <Badge variant="outline" className="border-emerald-500/50 text-emerald-500 gap-1 text-[10px]">
            <ShieldCheck className="w-3 h-3" /> Active
          </Badge>
        )}
      </div>
    );
  };

  const nonEmptyPasteLines = React.useMemo(
    () => importText.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#")).length,
    [importText],
  );

  return (
    <div className="space-y-6 p-6" translate="no">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Globe className="w-6 h-6" />
            <span>{t("proxyPool.title")}</span>
            {loading && <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />}
          </h1>
          <p className="text-muted-foreground text-sm mt-1">{t("proxyPool.subtitle")}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleForceRotate}><Zap className="w-4 h-4 mr-1" /><span>Force Rotate</span></Button>
          <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="w-4 h-4 mr-1" /><span>Refresh</span></Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: "Total", value: stats.total, Icon: Globe },
          { label: "Healthy", value: stats.healthy, Icon: CheckCircle2 },
          { label: "Failed", value: stats.unhealthy, Icon: XCircle },
          { label: "Untested", value: stats.unknown, Icon: Activity },
          { label: "Disabled", value: stats.disabled, Icon: null },
        ].map(({ label, value, Icon }) => (
          <Card key={label}>
            <CardContent className="pt-4 pb-4 flex items-center gap-3">
              {Icon && <Icon className="w-5 h-5 text-muted-foreground" />}
              <div><p className="text-2xl font-bold">{value}</p><p className="text-xs text-muted-foreground">{label}</p></div>
            </CardContent>
          </Card>
        ))}
      </div>

      {poolEnabled && !stats.active_proxy_id && (
        <div className="rounded-lg border border-destructive/60 bg-destructive/10 p-4 flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
          <div className="space-y-1 text-sm">
            <p className="font-semibold text-destructive">
              Fail-Closed Proxy Guard Active — Direct Target Connections Blocked
            </p>
            <p className="text-muted-foreground text-xs leading-relaxed">
              Proxy Pool is enabled, and all configured proxies are currently unhealthy or out of bandwidth. Running Tasks and Agents have been automatically paused/stopped so your server IP is never exposed. Enable the free <strong>Tor Anonymity Network</strong> below, import fresh proxies, or toggle Proxy Pool off if you intend to connect directly.
            </p>
          </div>
        </div>
      )}

      <Card className="border-primary/25 bg-muted/15">
        <CardContent className="pt-4 pb-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-semibold text-sm flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
                Tor Anonymity Network
              </span>
              <Badge variant="secondary" className="text-[10px]">Free · Unlimited Bandwidth</Badge>
              {torStatus?.exclusive_active ? (
                <Badge variant="default" className="text-[10px] bg-emerald-600 hover:bg-emerald-600">
                  Exclusive Tor Active ({torStatus.circuits_healthy}/{torStatus.circuits_total} Circuits)
                </Badge>
              ) : torStatus?.enabled_in_pool ? (
                <Badge variant="default" className="text-[10px] bg-emerald-600 hover:bg-emerald-600">
                  Hybrid Active ({torStatus.circuits_healthy}/{torStatus.circuits_total} Circuits)
                </Badge>
              ) : torStatus?.daemon_running ? (
                <Badge variant="outline" className="text-[10px]">Daemon Running</Badge>
              ) : (
                <Badge variant="outline" className="text-[10px]">Standby</Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Routes scanning &amp; agent traffic over isolated SOCKS5 Tor exit circuits (<code className="bg-muted px-1 rounded">IsolateSOCKSAuth</code> + <code className="bg-muted px-1 rounded">SIGNAL NEWNYM</code>) with zero bandwidth charges. Running agents automatically pick up switches mid-task without restarting.
              {torStatus?.exclusive_active && (
                <span className="ml-1 text-emerald-500 font-medium">
                  (Proxy Pool auto-disabled — switching Proxy Pool ON automatically shuts down Exclusive Tor)
                </span>
              )}
              {torStatus?.exit_ips && torStatus.exit_ips.length > 0 && (
                <span className="ml-1 text-foreground/80">
                  Exit IPs: <code className="bg-muted px-1 rounded">{torStatus.exit_ips.slice(0, 4).join(", ")}</code>
                </span>
              )}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Select value={torMode} onValueChange={(v) => void handleTorModeChange(v as "exclusive" | "hybrid")} disabled={torBusy}>
              <SelectTrigger className="w-[195px] h-8 text-xs">
                <SelectValue placeholder="Tor Mode" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="exclusive">Exclusive Tor (Pause Pool)</SelectItem>
                <SelectItem value="hybrid">Hybrid (Tor + Pool Together)</SelectItem>
              </SelectContent>
            </Select>
            <Select value={torCircuits} onValueChange={setTorCircuits} disabled={torBusy}>
              <SelectTrigger className="w-[120px] h-8 text-xs">
                <SelectValue placeholder="Circuits" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="3">3 Circuits</SelectItem>
                <SelectItem value="5">5 Circuits</SelectItem>
                <SelectItem value="8">8 Circuits</SelectItem>
              </SelectContent>
            </Select>
            {torStatus?.enabled_in_pool ? (
              <>
                <Button size="sm" variant="outline" disabled={torBusy} onClick={() => void handleRotateTor()}>
                  {torBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <RefreshCw className="w-3.5 h-3.5 mr-1" />}
                  <span>New Exit IPs (NEWNYM)</span>
                </Button>
                <Button size="sm" variant="destructive" disabled={torBusy} onClick={() => void handleDisableTor()}>
                  <span>Disable Tor</span>
                </Button>
              </>
            ) : (
              <Button size="sm" disabled={torBusy} onClick={() => void handleEnableTor()}>
                {torBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <Zap className="w-3.5 h-3.5 mr-1" />}
                <span>Enable Free Tor Network</span>
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="proxies">
        <TabsList>
          <TabsTrigger value="proxies">Proxies ({stats.total})</TabsTrigger>
          <TabsTrigger value="scraper" className="gap-1.5">
            <Radar className="w-3.5 h-3.5" />
            <span>Online Scraper</span>
            {(scraper?.running || scraper?.ai_running) && (
              <Loader2 className="w-3 h-3 animate-spin text-emerald-500" />
            )}
          </TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
          <TabsTrigger value="logs">Switch Logs ({logs.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="proxies">
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-3">
                <CardTitle>Proxy List</CardTitle>
                <div className="flex items-center gap-2 rounded-full border bg-muted/30 px-3 py-1">
                  <Switch
                    id="header-pool-switch"
                    checked={poolEnabled}
                    disabled={savingConfig || (proxies.length === 0 && !poolEnabled)}
                    onCheckedChange={(checked) => void handleTogglePoolEnabled(checked)}
                  />
                  <Label htmlFor="header-pool-switch" className="cursor-pointer text-xs font-medium">
                    {!poolEnabled
                      ? torStatus?.exclusive_active
                        ? "Pool Disabled (Exclusive Tor Active)"
                        : "Pool Disabled"
                      : stats.active_proxy_id
                        ? torStatus?.hybrid_pool_active
                          ? "Pool Active (Hybrid Tor + Pool)"
                          : "Pool Active"
                        : "Pool Active (Fail-Closed · No Healthy Proxy)"}
                  </Label>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <input
                  ref={quickFileInputRef}
                  type="file"
                  multiple
                  accept=".txt,.csv,.tsv,.json,.list,.conf,text/plain,text/csv,application/json"
                  className="hidden"
                  onChange={(e) => void handleQuickFileUpload(e.target.files)}
                />
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={importing}
                  onClick={() => quickFileInputRef.current?.click()}
                >
                  {importing ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <FileUp className="w-4 h-4 mr-1" />}
                  <span>Upload File</span>
                </Button>

                <Dialog open={importOpen} onOpenChange={setImportOpen}>
                  <DialogTrigger asChild>
                    <Button size="sm"><Upload className="w-4 h-4 mr-1" /> Import / Paste</Button>
                  </DialogTrigger>
                  <DialogContent className="sm:max-w-xl">
                    <DialogHeader><DialogTitle>Import Proxies (Text or File)</DialogTitle></DialogHeader>
                    <div className="space-y-4">
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        Supports all common formats: <code className="bg-muted px-1 rounded">ip:port:user:pass</code> (Webshare / Oxylabs / IPRoyal),{" "}
                        <code className="bg-muted px-1 rounded">user:pass@ip:port</code>,{" "}
                        <code className="bg-muted px-1 rounded">http://</code> / <code className="bg-muted px-1 rounded">socks5://</code> URLs,{" "}
                        <code className="bg-muted px-1 rounded">.txt</code>, <code className="bg-muted px-1 rounded">.csv</code>, and <code className="bg-muted px-1 rounded">.json</code>.
                        You can also paste proxies directly into Chat and tell the agent to use them.
                      </p>

                      <div
                        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                        onDragLeave={() => setDragOver(false)}
                        onDrop={(e) => {
                          e.preventDefault();
                          setDragOver(false);
                          handleFilesChosen(e.dataTransfer.files);
                        }}
                        onClick={() => fileInputRef.current?.click()}
                        className={`cursor-pointer rounded-lg border-2 border-dashed p-4 text-center transition-colors ${
                          dragOver ? "border-primary bg-primary/5" : "border-border hover:border-primary/50 hover:bg-muted/30"
                        }`}
                      >
                        <input
                          ref={fileInputRef}
                          type="file"
                          multiple
                          accept=".txt,.csv,.tsv,.json,.list,.conf,text/plain,text/csv,application/json"
                          className="hidden"
                          onChange={(e) => handleFilesChosen(e.target.files)}
                        />
                        <FileUp className="w-5 h-5 mx-auto mb-1.5 text-muted-foreground" />
                        <p className="text-xs font-medium">
                          Drop proxy files here or <span className="text-primary underline">browse files</span> (.txt, .csv, .json)
                        </p>
                        {selectedFiles.length > 0 && (
                          <div className="mt-2 flex flex-wrap justify-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                            {selectedFiles.map((f, idx) => (
                              <Badge key={`${f.name}-${idx}`} variant="secondary" className="gap-1.5 text-xs">
                                <span>{f.name}</span>
                                <button
                                  type="button"
                                  className="text-muted-foreground hover:text-foreground"
                                  onClick={() => setSelectedFiles((prev) => prev.filter((_, i) => i !== idx))}
                                >
                                  ×
                                </button>
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>

                      <Textarea
                        rows={7}
                        className="font-mono text-xs"
                        placeholder={"107.180.188.171:6602:username:password\nhttp://user:pass@host:port|Name|Remark\nsocks5://user:pass@host:1080"}
                        value={importText}
                        onChange={(e) => setImportText(e.target.value)}
                      />

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 rounded-lg border bg-muted/20 p-3">
                        <div className="space-y-1.5">
                          <Label className="text-xs">Default Protocol (when no scheme in line)</Label>
                          <Select value={defaultType} onValueChange={setDefaultType}>
                            <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="http">HTTP / HTTPS Connect (Default)</SelectItem>
                              <SelectItem value="socks5">SOCKS5</SelectItem>
                              <SelectItem value="https">HTTPS Proxy</SelectItem>
                              <SelectItem value="socks4">SOCKS4</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2 flex flex-col justify-center">
                          <div className="flex items-center justify-between">
                            <Label className="text-xs cursor-pointer" htmlFor="auto-test-import">Auto-test immediately</Label>
                            <Switch id="auto-test-import" checked={autoTestOnImport} onCheckedChange={setAutoTestOnImport} />
                          </div>
                          <div className="flex items-center justify-between">
                            <Label className="text-xs cursor-pointer" htmlFor="replace-existing">Replace existing pool</Label>
                            <Switch id="replace-existing" checked={replaceExisting} onCheckedChange={setReplaceExisting} />
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs text-muted-foreground">
                          {selectedFiles.length > 0 ? `${selectedFiles.length} file(s)` : ""}
                          {selectedFiles.length > 0 && nonEmptyPasteLines > 0 ? " + " : ""}
                          {nonEmptyPasteLines > 0 ? `${nonEmptyPasteLines} pasted line(s)` : ""}
                        </span>
                        <div className="flex justify-end gap-2">
                          <Button
                            variant="outline"
                            onClick={() => { setImportText(""); setSelectedFiles([]); }}
                          >
                            <span>Clear</span>
                          </Button>
                          <Button
                            onClick={handleImport}
                            disabled={importing || (!importText.trim() && selectedFiles.length === 0)}
                          >
                            {importing ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <Upload className="w-4 h-4 mr-1" />}
                            <span>{importing ? (autoTestOnImport ? "Importing & Testing..." : "Importing...") : "Import Proxies"}</span>
                          </Button>
                        </div>
                      </div>
                    </div>
                  </DialogContent>
                </Dialog>

                <Button size="sm" variant="outline" onClick={handleTestAll} disabled={testingAll || importing}>
                  {testingAll ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <Play className="w-4 h-4 mr-1" />}
                  <span>Test All</span>
                </Button>
                <Button size="sm" variant="outline" onClick={handleClearFailed}>
                  <Trash2 className="w-4 h-4 mr-1" />
                  <span>Clear Failed</span>
                </Button>
                {proxies.length > 0 && (
                  <Button size="sm" variant="destructive" onClick={handleClearAll}>
                    <Trash2 className="w-4 h-4 mr-1" />
                    <span>Clear All</span>
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {!proxies.length ? (
                <div className="text-center text-muted-foreground py-12 space-y-2">
                  <p>No proxies in the pool yet.</p>
                  <p className="text-xs">
                    Click <strong>Upload File</strong> (.txt / .csv / .json), <strong>Import / Paste</strong>, or paste proxies directly into <strong>Chat</strong> and tell the agent to use them.
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Status</TableHead><TableHead>Proxy</TableHead><TableHead>Exit IP</TableHead><TableHead>Name</TableHead>
                    <TableHead>Type</TableHead><TableHead>Location</TableHead><TableHead>Latency</TableHead>
                    <TableHead>Fails</TableHead><TableHead>Last Check</TableHead><TableHead className="text-right">Actions</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>{proxies.map((p) => {
                    const isActiveEgress = stats.active_proxy_id === p.id;
                    const exitIP = p.response_ip || p.egress_ip;
                    return (
                      <TableRow key={p.id} className={isActiveEgress && poolEnabled ? "bg-emerald-500/5" : undefined}>
                        <TableCell>{statusBadge(p.status as ProxyStatus, isActiveEgress)}</TableCell>
                        <TableCell><code className="text-xs bg-muted px-1.5 py-0.5 rounded">{p.url}</code></TableCell>
                        <TableCell>{exitIP ? <code className="text-xs font-mono">{exitIP}</code> : "-"}</TableCell>
                        <TableCell className="max-w-[120px] truncate" title={p.name}>{p.name || "-"}</TableCell>
                        <TableCell><Badge variant="outline">{p.proxy_type}</Badge></TableCell>
                        <TableCell>{p.country ? (<span className="flex items-center gap-1 text-xs"><MapPin className="w-3 h-3" />{[p.country, p.city].filter(Boolean).join(", ")}</span>) : "-"}</TableCell>
                        <TableCell>{p.latency_ms > 0 ? p.latency_ms + "ms" : "-"}</TableCell>
                        <TableCell>{p.consecutive_failures > 0 ? (<span className="text-red-500">{p.consecutive_failures}</span>) : "0"}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{p.last_checked_at ? new Date(p.last_checked_at).toLocaleString() : "-"}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-1">
                            {isActiveEgress && poolEnabled ? (
                              <Button
                                size="sm"
                                variant="secondary"
                                onClick={() => handleStopUsing(p.id)}
                                title="Click to stop using this proxy"
                              >
                                Stop Using
                              </Button>
                            ) : (
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => handleActivate(p.id)}
                              >
                                Use
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleToggle(p.id, p.status === "disabled" || p.active === false)}
                            >
                              {p.status === "disabled" || p.active === false ? "Enable" : "Disable"}
                            </Button>
                            <Button size="sm" variant="ghost" onClick={() => handleTestOne(p.id)} disabled={testing === p.id} title="Test proxy">
                              {testing === p.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                            </Button>
                            <Button size="sm" variant="ghost" className="text-destructive" onClick={() => handleDelete(p.id)} title="Delete proxy">
                              <Trash2 className="w-3 h-3" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}</TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scraper" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Radar className="w-5 h-5 text-primary" />
                  <span>Online Proxy Scraper &amp; Self-Improving AI Harvester</span>
                  {scraper?.running && (
                    <Badge variant="default" className="gap-1 text-xs">
                      <Loader2 className="w-3 h-3 animate-spin" /> Scraping
                    </Badge>
                  )}
                  {scraper?.ai_running && (
                    <Badge variant="secondary" className="gap-1 text-xs border-primary/40">
                      <Sparkles className="w-3 h-3 text-primary animate-pulse" /> AI Harvester Active
                    </Badge>
                  )}
                </CardTitle>
                <p className="text-xs text-muted-foreground mt-1">
                  Crawls 30+ live proxy APIs, premium providers&apos; daily free lists (<code className="bg-muted px-1 rounded">IPRoyal</code>, <code className="bg-muted px-1 rounded">FineProxy</code>, <code className="bg-muted px-1 rounded">Webshare Free Tier</code>), JS-decoded HTML tables (<code className="bg-muted px-1 rounded">US-Proxy</code>, <code className="bg-muted px-1 rounded">ProxyNova US</code>, <code className="bg-muted px-1 rounded">SSLProxies</code>, <code className="bg-muted px-1 rounded">Spys.me</code>), and live JSON APIs (<code className="bg-muted px-1 rounded">GeoNode US</code>, <code className="bg-muted px-1 rounded">ProxyScrape v4 US</code>, <code className="bg-muted px-1 rounded">RoundProxies</code>) — prioritizing fast <strong>HTTP/HTTPS CONNECT</strong> &amp; <strong>United States</strong> exit IPs compatible with 100% of tools.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2 shrink-0">
                {scraper?.running ? (
                  <Button size="sm" variant="destructive" onClick={() => void handleStopScraper()}>
                    <Square className="w-3.5 h-3.5 mr-1" />
                    <span>Stop Scrape</span>
                  </Button>
                ) : (
                  <Button size="sm" disabled={scraperBusy} onClick={() => void handleRunScraperNow()}>
                    {scraperBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <Play className="w-3.5 h-3.5 mr-1" />}
                    <span>Scrape &amp; Verify Now</span>
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={scraperBusy || scraper?.ai_running}
                  onClick={() => void handleRunHarvesterAgent()}
                >
                  {scraper?.ai_running ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <Sparkles className="w-3.5 h-3.5 mr-1" />}
                  <span>Run AI Harvester</span>
                </Button>
                {scraper?.last_agent_conv_id ? (
                  <Button size="sm" variant="outline" asChild>
                    <a href={`/chat?c=${scraper.last_agent_conv_id}`}>
                      <ExternalLink className="w-3.5 h-3.5 mr-1" />
                      <span>Agent Run #{scraper.last_agent_conv_id}</span>
                    </a>
                  </Button>
                ) : null}
                <Button size="sm" variant="outline" disabled={scraperBusy} onClick={() => void handleClearScraped()}>
                  <Trash2 className="w-3.5 h-3.5 mr-1" />
                  <span>Clear Scraped</span>
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
                {[
                  { label: "Sources Polled", val: scraper?.sources_polled ?? 0 },
                  { label: "Raw Candidates", val: scraper?.candidates_found ?? 0 },
                  { label: "Stage-1 TCP Alive", val: scraper?.tcp_alive ?? 0 },
                  { label: "Stage-2 HTTPS Elite", val: scraper?.https_verified ?? 0 },
                  { label: "US Exit Verified", val: scraper?.us_verified ?? 0 },
                  { label: "Active in Pool", val: scraper?.added_to_pool ?? 0 },
                ].map((m) => (
                  <div key={m.label} className="rounded-lg border bg-muted/20 p-3">
                    <p className="text-xl font-bold">{m.val}</p>
                    <p className="text-[11px] text-muted-foreground">{m.label}</p>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex items-center justify-between rounded-lg border p-3">
                  <div className="space-y-0.5 pr-3">
                    <Label htmlFor="auto-scrape-switch" className="cursor-pointer font-medium">
                      Automatic Scheduled Scraping
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      Automatically scrape, 2-stage verify, prune dead scraped proxies, and top up Proxy Pool on schedule.
                    </p>
                  </div>
                  <Switch
                    id="auto-scrape-switch"
                    checked={scraperEnabled}
                    disabled={scraperBusy}
                    onCheckedChange={(checked) => {
                      setScraperEnabled(checked);
                      void handleSaveScraperConfig({ enabled: checked });
                    }}
                  />
                </div>

                <div className="flex items-center justify-between rounded-lg border p-3">
                  <div className="space-y-0.5 pr-3">
                    <Label htmlFor="ai-harvester-switch" className="cursor-pointer font-medium flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-primary" />
                      <span>Self-Improving AI Harvester Agent (<code className="text-[11px]">proxy_harvester</code>)</span>
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      Automatically hunts fresh GitHub repos &amp; APIs, registers new feeds, prunes dead feeds, and evolves harvesting skills.
                    </p>
                  </div>
                  <Switch
                    id="ai-harvester-switch"
                    checked={scraperAIEnabled}
                    disabled={scraperBusy}
                    onCheckedChange={(checked) => {
                      setScraperAIEnabled(checked);
                      void handleSaveScraperConfig({ ai_agent_enabled: checked }, true);
                    }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-6 gap-3 items-end">
                <div className="space-y-1.5">
                  <Label className="text-xs">Protocols</Label>
                  <Select value={scraperProtoMode} onValueChange={(v) => setScraperProtoMode(v as any)}>
                    <SelectTrigger className="h-9 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="http">HTTP / HTTPS Only (Universal)</SelectItem>
                      <SelectItem value="both">HTTP Preferred + SOCKS5</SelectItem>
                      <SelectItem value="socks5">SOCKS5 Only</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Country Targeting</Label>
                  <Select value={scraperCountryMode} onValueChange={(v) => setScraperCountryMode(v as any)}>
                    <SelectTrigger className="h-9 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="us_preferred">Prefer US First (+ Global Top-Up)</SelectItem>
                      <SelectItem value="us_only">Strict United States Only</SelectItem>
                      <SelectItem value="all">All Countries (Fastest Global)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Max Verified to Keep</Label>
                  <Input
                    type="number"
                    min={3}
                    max={100}
                    className="h-9 text-xs"
                    value={scraperMaxProxies}
                    onChange={(e) => setScraperMaxProxies(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Max Latency (ms)</Label>
                  <Input
                    type="number"
                    min={500}
                    max={15000}
                    className="h-9 text-xs"
                    value={scraperMaxLatency}
                    onChange={(e) => setScraperMaxLatency(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Refresh Every (mins)</Label>
                  <Input
                    type="number"
                    min={5}
                    max={1440}
                    className="h-9 text-xs"
                    value={scraperInterval}
                    onChange={(e) => setScraperInterval(e.target.value)}
                  />
                </div>
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Switch
                      id="scraper-auto-enable"
                      checked={scraperAutoEnablePool}
                      onCheckedChange={setScraperAutoEnablePool}
                    />
                    <Label htmlFor="scraper-auto-enable" className="text-xs cursor-pointer">Auto-Enable Pool</Label>
                  </div>
                  <Button size="sm" variant="outline" disabled={scraperBusy} onClick={() => void handleSaveScraperConfig()}>
                    Save
                  </Button>
                </div>
              </div>

              <div className="rounded-lg border bg-muted/15 p-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <Label className="text-xs font-medium">Optional Premium Free-Tier API: Webshare (10 Dedicated Datacenter HTTP Proxies)</Label>
                    {webshareKeySaved && (
                      <Badge variant="default" className="text-[10px] bg-emerald-600 hover:bg-emerald-600">
                        API Token Connected
                      </Badge>
                    )}
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    Paste a free Webshare API token (<code className="bg-muted px-1 rounded">proxy.webshare.io</code> — 10 dedicated fast HTTP proxies, no credit card) to auto-sync them alongside public US/HTTP feeds.
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Input
                    type="password"
                    placeholder={webshareKeySaved ? "Token saved (enter new to replace)" : "Webshare API Token (optional)"}
                    className="h-8 text-xs w-60 font-mono"
                    value={webshareApiKey}
                    onChange={(e) => setWebshareApiKey(e.target.value)}
                  />
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={scraperBusy || !webshareApiKey.trim()}
                    onClick={() => void handleSaveScraperConfig()}
                  >
                    Save Token
                  </Button>
                  {webshareKeySaved && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-destructive text-xs"
                      disabled={scraperBusy}
                      onClick={() => void handleSaveScraperConfig({ webshare_api_key: "CLEAR" })}
                    >
                      Clear
                    </Button>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Live Scraping &amp; Verification Log {scraper?.phase && scraper.phase !== "Idle" ? `— ${scraper.phase}` : ""}</span>
                  </h4>
                  {scraper?.last_run_at && (
                    <span className="text-[11px] text-muted-foreground">
                      Last run: {new Date(scraper.last_run_at).toLocaleString()}
                    </span>
                  )}
                </div>
                <div className="rounded-lg border bg-zinc-950 text-zinc-200 font-mono text-xs p-3 h-72 overflow-y-auto space-y-1">
                  {!scraper?.logs?.length ? (
                    <p className="text-zinc-500">
                      No scrape events yet. Click &quot;Scrape &amp; Verify Now&quot; or enable &quot;Automatic Scheduled Scraping&quot; to begin live harvesting.
                    </p>
                  ) : (
                    scraper.logs.map((entry, idx) => {
                      const color =
                        entry.level === "verified"
                          ? "text-emerald-400"
                          : entry.level === "ai"
                            ? "text-purple-400"
                            : entry.level === "summary"
                              ? "text-cyan-300 font-semibold"
                              : entry.level === "warn"
                                ? "text-amber-400"
                                : entry.level === "source"
                                  ? "text-blue-300"
                                  : "text-zinc-300";
                      return (
                        <div key={idx} className="leading-relaxed break-all">
                          <span className="text-zinc-500 mr-2">[{entry.timestamp}]</span>
                          <span className={color}>{entry.message}</span>
                        </div>
                      );
                    })
                  )}
                  <div ref={logEndRef} />
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Registered Scrape Feeds ({scraper?.sources?.length ?? 0} total)
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-56 overflow-y-auto pr-1">
                  {(scraper?.sources || []).map((src) => (
                    <div key={src.id} className="flex items-center justify-between rounded border px-3 py-2 text-xs">
                      <div className="min-w-0 pr-2">
                        <div className="flex items-center gap-1.5">
                          <span className="font-medium truncate">{src.name}</span>
                          <Badge variant="outline" className="text-[10px] uppercase">{src.protocol}</Badge>
                          {src.country_hint && (
                            <Badge variant="secondary" className="text-[10px] uppercase">{src.country_hint}</Badge>
                          )}
                          {src.added_by_agent && (
                            <Badge variant="secondary" className="text-[10px] gap-0.5">
                              <Sparkles className="w-2.5 h-2.5" /> AI Discovered
                            </Badge>
                          )}
                        </div>
                        <p className="text-[11px] text-muted-foreground truncate">{src.url}</p>
                      </div>
                      <div className="text-right shrink-0">
                        {src.last_error ? (
                          <span className="text-destructive text-[11px]">{src.last_error}</span>
                        ) : src.last_polled_at ? (
                          <span className="text-muted-foreground text-[11px]">
                            {src.last_candidates} raw · <strong className="text-emerald-500">{src.last_verified} verified</strong>
                          </span>
                        ) : (
                          <span className="text-muted-foreground text-[11px]">Ready</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="config">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Pool Configuration</CardTitle>
                <Badge variant={poolEnabled ? "default" : "secondary"}>
                  {poolEnabled ? "Routing Active" : "Pool Disabled"}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h3 className="font-medium flex items-center gap-2"><Settings className="w-4 h-4" /> Rotation Settings</h3>
                  <div className="flex items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5 pr-4">
                      <Label htmlFor="pool-enabled-switch" className="cursor-pointer">Enable Proxy Pool</Label>
                      <p className="text-xs text-muted-foreground">
                        Takes effect immediately across Agents, Bash, WebFetch, Scanners, and Browser Inspection. Overrides any single static Global Proxy while enabled.
                      </p>
                    </div>
                    <Switch
                      id="pool-enabled-switch"
                      checked={poolEnabled}
                      disabled={savingConfig}
                      onCheckedChange={(checked) => void handleTogglePoolEnabled(checked)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label>Rotation Strategy</Label>
                    <Select value={rotationStrategy} onValueChange={setRotationStrategy}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="round_robin">Round Robin (Sequential)</SelectItem>
                        <SelectItem value="random">Random</SelectItem>
                        <SelectItem value="least_used">Least Used</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label>Rotation Interval (seconds)</Label>
                    <Input
                      type="number"
                      min={5}
                      value={rotationInterval}
                      disabled={sessionSticky}
                      onChange={e => setRotationInterval(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      {sessionSticky
                        ? "Timed rotation is paused while Session Sticky is enabled (rotates only on failure or Force Rotate)."
                        : "Automatically rotates to the next healthy proxy at this interval."}
                    </p>
                  </div>
                  <div className="flex items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5 pr-4">
                      <Label>Auto-rotate on Failure</Label>
                      <p className="text-xs text-muted-foreground">Automatically fail over to another healthy proxy when consecutive failures hit threshold.</p>
                    </div>
                    <Switch checked={autoRotateOnFailure} onCheckedChange={setAutoRotateOnFailure} />
                  </div>
                  <div className="flex items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5 pr-4">
                      <Label>Session Sticky</Label>
                      <p className="text-xs text-muted-foreground">Keep a consistent exit IP during authenticated target workflows; turn off to rotate on a timer.</p>
                    </div>
                    <Switch checked={sessionSticky} onCheckedChange={setSessionSticky} />
                  </div>
                </div>
                <div className="space-y-4">
                  <h3 className="font-medium flex items-center gap-2"><Activity className="w-4 h-4" /> Health Check</h3>
                  <div className="space-y-1.5">
                    <Label>Check Interval (seconds)</Label>
                    <Input type="number" min={10} value={healthInterval} onChange={e => setHealthInterval(e.target.value)} />
                    <p className="text-xs text-muted-foreground">Background connectivity &amp; GeoIP probe frequency.</p>
                  </div>
                  <div className="space-y-1.5">
                    <Label>Max Consecutive Failures</Label>
                    <Input type="number" min={1} value={maxFailures} onChange={e => setMaxFailures(e.target.value)} />
                    <p className="text-xs text-muted-foreground">Number of failed probes before cooling down a proxy and failing over.</p>
                  </div>
                  <div className="space-y-1.5">
                    <Label>Cooldown (seconds)</Label>
                    <Input type="number" min={10} value={cooldown} onChange={e => setCooldown(e.target.value)} />
                    <p className="text-xs text-muted-foreground">Wait time before re-probing a failed proxy to check recovery.</p>
                  </div>
                </div>
              </div>
              <Button onClick={() => void handleSaveConfig()} disabled={savingConfig}>
                {savingConfig ? <><Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> Saving...</> : "Save Configuration"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="logs">
          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2"><Clock className="w-4 h-4" /> Switch History</CardTitle></CardHeader>
            <CardContent>
              {!logs.length ? (<p className="text-center text-muted-foreground py-8">No switch logs yet</p>) : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Time</TableHead><TableHead>From</TableHead><TableHead>To</TableHead><TableHead>Reason</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>{[...logs].reverse().map((log) => (
                    <TableRow key={log.id}>
                      <TableCell className="text-xs">{new Date(log.timestamp).toLocaleString()}</TableCell>
                      <TableCell><code className="text-xs bg-muted px-1.5 py-0.5 rounded">{log.from_proxy_id || "(direct)"}</code></TableCell>
                      <TableCell><code className="text-xs bg-muted px-1.5 py-0.5 rounded">{log.to_proxy_id || "(direct)"}</code></TableCell>
                      <TableCell>{log.reason}</TableCell>
                    </TableRow>
                  ))}</TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}