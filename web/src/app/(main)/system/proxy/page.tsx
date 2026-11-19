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
  Loader2, Globe, Activity, Zap, Settings, MapPin, Clock, FileUp, ShieldCheck,
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


  const fetchData = React.useCallback(async () => {
    try {
      const [proxyList, poolStats, switchLogs, poolConfig] = await Promise.all([
        api.proxyV2.listProxies().catch(() => []),
        api.proxyV2.getStats().catch(() => null),
        api.proxyV2.getLogs().catch(() => []),
        api.proxyV2.getConfig().catch(() => null),
      ]);
      setProxies(Array.isArray(proxyList) ? proxyList : []);
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
      toast.success("Active egress proxy updated");
      await fetchData();
    } catch (e: any) {
      toast.error("Activate failed: " + (e?.message || String(e)));
    }
  };

  const handleToggle = async (id: string) => {
    try {
      await api.proxyV2.proxyAction(id, "toggle");
      toast.success("Proxy enabled/disabled");
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
    setPoolEnabled(checked);
    await persistPoolConfig(checked, false);
    toast.success(
      checked
        ? "Proxy Pool enabled — outbound target & scanner traffic now routes through the pool"
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

      <Tabs defaultValue="proxies">
        <TabsList>
          <TabsTrigger value="proxies">Proxies ({stats.total})</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
          <TabsTrigger value="logs">Switch Logs ({logs.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="proxies">
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <CardTitle>Proxy List</CardTitle>
                <Badge variant={poolEnabled ? "default" : "secondary"} className="text-xs">
                  {poolEnabled ? "Pool Active" : "Pool Disabled"}
                </Badge>
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
                            <Button size="sm" variant="ghost" onClick={() => handleActivate(p.id)} disabled={isActiveEgress && poolEnabled}>
                              {isActiveEgress && poolEnabled ? "In Use" : "Use"}
                            </Button>
                            <Button size="sm" variant="ghost" onClick={() => handleToggle(p.id)}>
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