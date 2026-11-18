"use client";

import * as React from "react";

import {
  Activity, AlertTriangle, Bug, CheckCircle2, Download, Eye,
  Loader2, Pause, Play, Plus, RefreshCw, Search, Shield,
  ShieldAlert, ShieldCheck, Target, Terminal, Trash2, X,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

// ---------- Types ----------

interface PatchSource {
  id: number; name: string; url: string; source_type: string;
  check_interval_minutes: number; last_check_at: string | null;
  last_hash: string | null; is_active: boolean; created_at: string;
}

interface Vulnerability {
  id: number; source_id: number; source_name: string;
  cve_id: string | null; title: string; description: string | null;
  severity: string; cvss_score: number | null;
  affected_versions: string | null; patched_version: string | null;
  reference_urls: string[] | null; status: string; discovered_at: string;
}

interface ExploitTarget {
  id: number; name: string; target_type: string;
  host: string; port: number; service: string | null;
  version: string | null; os_type: string | null;
  notes: string | null; status: string; created_at: string;
}

// ---------- API Helpers ----------

import { apiFetch } from "@/lib/api";
import { useLiveTranslation } from "@/i18n/use-live-translation";

const apiBase = "/api/patch-monitor";

function getAuthHeaders(extra?: HeadersInit): HeadersInit {
  const token = typeof window !== "undefined" ? localStorage.getItem("artex_token") : null;
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(extra || {}),
  };
}

async function fetchAPI<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await apiFetch(`${apiBase}${path}`, {
    ...options,
    headers: getAuthHeaders(options?.headers),
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ---------- Main Component ----------

export default function PatchMonitorPage() {
  const { t } = useLiveTranslation();
  const [loading, setLoading] = React.useState(false);
  const [monitorRunning, setMonitorRunning] = React.useState(false);
  const [sources, setSources] = React.useState<PatchSource[]>([]);
  const [vulns, setVulns] = React.useState<Vulnerability[]>([]);
  const [targets, setTargets] = React.useState<ExploitTarget[]>([]);
  const [selectedVuln, setSelectedVuln] = React.useState<Vulnerability | null>(null);
  const [generatedPoC, setGeneratedPoC] = React.useState<string>("");
  const [generatingPoC, setGeneratingPoC] = React.useState(false);
  const [searchQuery, setSearchQuery] = React.useState("");
  const [statusFilter, setStatusFilter] = React.useState("all");
  const [showAddTarget, setShowAddTarget] = React.useState(false);
  const [newTarget, setNewTarget] = React.useState<Partial<ExploitTarget>>({
    target_type: "web", port: 80,
  });

  React.useEffect(() => { loadAll(); checkStatus(); }, []);

  async function loadAll() {
    setLoading(true);
    try {
      const [src, vln, tgt] = await Promise.all([
        fetchAPI<PatchSource[]>("/sources"),
        fetchAPI<Vulnerability[]>("/vulns"),
        fetchAPI<ExploitTarget[]>("/targets"),
      ]);
      setSources(Array.isArray(src) ? src : []);
      setVulns(Array.isArray(vln) ? vln : []);
      setTargets(Array.isArray(tgt) ? tgt : []);
    } catch (e) { console.error("Failed to load:", e); }
    finally { setLoading(false); }
  }

  async function checkStatus() {
    try { const s = await fetchAPI<{ running: boolean }>("/status"); setMonitorRunning(!!s?.running); } catch {}
  }

  async function toggleMonitor(start: boolean) {
    try {
      await fetchAPI(start ? "/start" : "/stop", { method: "POST" });
      toast.success(`Patch monitor ${start ? "started" : "stopped"}`);
      setMonitorRunning(start);
    } catch { toast.error(`Failed to ${start ? "start" : "stop"} monitor`); }
  }

  async function handleAddTarget() {
    if (!newTarget.name || !newTarget.host) {
      toast.warning("Target name and host are required");
      return;
    }
    try {
      await fetchAPI("/targets", { method: "POST", body: JSON.stringify(newTarget) });
      toast.success("Target added"); setShowAddTarget(false);
      setNewTarget({ target_type: "web", port: 80 }); loadAll();
    } catch { toast.error("Failed to add target"); }
  }

  async function handleDeleteTarget(id: number) {
    try {
      await fetchAPI(`/targets/${id}`, { method: "DELETE" });
      toast.success("Target removed");
      loadAll();
    } catch { toast.error("Failed to remove target"); }
  }

  async function handleGenerateExploit(vulnId: number) {
    setGeneratingPoC(true);
    try {
      const res = await fetchAPI<Array<{ code: string }>>("/exploits/generate", {
        method: "POST",
        body: JSON.stringify({ vuln_id: vulnId }),
      });
      if (Array.isArray(res) && res.length > 0 && res[0].code) {
        setGeneratedPoC(res[0].code);
        toast.success("PoC exploit generated");
      } else {
        toast.error("No exploit template matched");
      }
    } catch {
      toast.error("Failed to generate PoC exploit");
    } finally {
      setGeneratingPoC(false);
    }
  }

  const filteredVulns = vulns.filter((v) => {
    if (statusFilter !== "all" && v.status !== statusFilter) return false;
    if (searchQuery && !v.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !(v.cve_id?.toLowerCase().includes(searchQuery.toLowerCase()))) return false;
    return true;
  });

  function severityBadge(severity: string, cvss?: number | null) {
    const cls = severity.toLowerCase();
    if (cls === "critical" || (cvss && cvss >= 9.0)) return <Badge variant="destructive">CRITICAL</Badge>;
    if (cls === "high" || (cvss && cvss >= 7.0)) return <Badge className="bg-red-500 text-white">HIGH</Badge>;
    if (cls === "medium" || (cvss && cvss >= 4.0)) return <Badge className="bg-yellow-500 text-black">MEDIUM</Badge>;
    return <Badge variant="secondary">LOW</Badge>;
  }

  function statusIcon(status: string) {
    switch (status) {
      case "active": return <ShieldCheck className="size-4 text-green-500" />;
      case "patched": return <CheckCircle2 className="size-4 text-blue-500" />;
      case "exploitable": return <ShieldAlert className="size-4 text-red-500" />;
      default: return <Shield className="size-4 text-gray-400" />;
    }
  }

  return (
    <div className="flex flex-1 flex-col gap-5 p-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 font-semibold text-xl"><Shield /> {t("patchMonitor.title")}</h1>
          <p className="mt-1 text-muted-foreground text-sm">{t("patchMonitor.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant={monitorRunning ? "destructive" : "default"} size="sm" onClick={() => toggleMonitor(!monitorRunning)}>
            {monitorRunning ? <><Pause className="size-4" /> Stop</> : <><Play className="size-4" /> Start</>}
          </Button>
          <Button variant="outline" size="sm" onClick={loadAll} disabled={loading}>
            <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} /> Refresh
          </Button>
        </div>
      </div>

      {/* Status Bar */}
      <Card>
        <CardContent className="flex items-center gap-6 py-4">
          <div className="flex items-center gap-2">
            <Activity className={`size-4 ${monitorRunning ? "text-green-500 animate-pulse" : "text-gray-400"}`} />
            <span className="text-sm font-medium">Monitor:</span>
            <Badge variant={monitorRunning ? "default" : "secondary"}>{monitorRunning ? "Running" : "Stopped"}</Badge>
          </div>
          <div className="flex items-center gap-2">
            <Bug className="size-4 text-red-400" /><span className="text-sm font-medium">Vulns:</span>
            <Badge variant="destructive">{vulns.filter(v => v.status === "active").length} active</Badge>
          </div>
          <div className="flex items-center gap-2">
            <Target className="size-4 text-blue-400" /><span className="text-sm font-medium">Targets:</span>
            <Badge variant="secondary">{targets.length}</Badge>
          </div>
          <div className="flex items-center gap-2">
            <Search className="size-4 text-gray-400" /><span className="text-sm font-medium">Sources:</span>
            <Badge variant="outline">{sources.filter(s => s.is_active).length}/{sources.length}</Badge>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs defaultValue="vulnerabilities" className="flex-1">
        <TabsList>
          <TabsTrigger value="vulnerabilities"><AlertTriangle className="mr-1 size-4" /> Vulnerabilities</TabsTrigger>
          <TabsTrigger value="sources"><Download className="mr-1 size-4" /> Sources</TabsTrigger>
          <TabsTrigger value="targets"><Target className="mr-1 size-4" /> Targets</TabsTrigger>
          <TabsTrigger value="payloads"><Bug className="mr-1 size-4" /> Payloads</TabsTrigger>
        </TabsList>

        <TabsContent value="vulnerabilities" className="mt-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div><CardTitle>Security Vulnerabilities</CardTitle><CardDescription>Tracked CVEs and security advisories</CardDescription></div>
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
                    <Input placeholder="Search..." className="w-64 pl-8" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
                  </div>
                  <Select value={statusFilter} onValueChange={setStatusFilter}>
                    <SelectTrigger className="w-36"><SelectValue placeholder="Status" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Status</SelectItem>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="patched">Patched</SelectItem>
                      <SelectItem value="exploitable">Exploitable</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="flex items-center justify-center py-12"><Loader2 className="size-8 animate-spin text-muted-foreground" /></div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead><TableHead>Severity</TableHead><TableHead>CVE ID</TableHead>
                      <TableHead>Title</TableHead><TableHead>Source</TableHead><TableHead>CVSS</TableHead>
                      <TableHead>Discovered</TableHead><TableHead></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredVulns.map((vuln) => (
                      <TableRow key={vuln.id} className="cursor-pointer" onClick={() => { setSelectedVuln(vuln); setGeneratedPoC(""); }}>
                        <TableCell>{statusIcon(vuln.status)}</TableCell>
                        <TableCell>{severityBadge(vuln.severity, vuln.cvss_score)}</TableCell>
                        <TableCell className="font-mono text-sm">{vuln.cve_id || "-"}</TableCell>
                        <TableCell className="max-w-md truncate">{vuln.title}</TableCell>
                        <TableCell><Badge variant="outline">{vuln.source_name}</Badge></TableCell>
                        <TableCell>{vuln.cvss_score?.toFixed(1) || "-"}</TableCell>
                        <TableCell className="text-muted-foreground text-xs">{new Date(vuln.discovered_at).toLocaleDateString()}</TableCell>
                        <TableCell onClick={(e) => { e.stopPropagation(); setSelectedVuln(vuln); setGeneratedPoC(""); }}>
                          <Button variant="ghost" size="sm"><Eye className="size-4" /></Button>
                        </TableCell>
                      </TableRow>
                    ))}
                    {filteredVulns.length === 0 && (
                      <TableRow><TableCell colSpan={8} className="py-12 text-center text-muted-foreground">No vulnerabilities found</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
          {selectedVuln && (
            <Card className="mt-4">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{selectedVuln.cve_id || "Details"}</CardTitle>
                  <Button variant="ghost" size="sm" onClick={() => setSelectedVuln(null)}><X className="size-4" /></Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div><h4 className="mb-1 font-semibold">{selectedVuln.title}</h4><p className="text-muted-foreground text-sm">{selectedVuln.description || "No description"}</p></div>
                <div className="grid grid-cols-2 gap-4">
                  <div><Label className="text-muted-foreground text-xs">Severity</Label><div className="mt-1">{severityBadge(selectedVuln.severity, selectedVuln.cvss_score)}</div></div>
                  <div><Label className="text-muted-foreground text-xs">CVSS Score</Label><div className="mt-1 font-mono">{selectedVuln.cvss_score?.toFixed(1) || "N/A"}</div></div>
                  <div><Label className="text-muted-foreground text-xs">Affected Versions</Label><div className="mt-1 text-sm">{selectedVuln.affected_versions || "N/A"}</div></div>
                  <div><Label className="text-muted-foreground text-xs">Patched Version</Label><div className="mt-1 text-sm">{selectedVuln.patched_version || "N/A"}</div></div>
                </div>
                <div className="flex items-center gap-2 pt-2">
                  <Button size="sm" onClick={() => handleGenerateExploit(selectedVuln.id)} disabled={generatingPoC}>
                    {generatingPoC ? <><Loader2 className="mr-1.5 size-4 animate-spin" /> Generating PoC...</> : <><Terminal className="mr-1.5 size-4" /> Generate PoC Exploit</>}
                  </Button>
                </div>
                {generatedPoC && (
                  <pre className="max-h-80 overflow-auto rounded-md bg-gray-950 p-4 text-green-400 text-xs">
                    <code>{generatedPoC}</code>
                  </pre>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="sources" className="mt-4">
          <Card>
            <CardHeader><CardTitle>Patch Sources</CardTitle><CardDescription>Configured vulnerability feed sources</CardDescription></CardHeader>
            <CardContent>
              <Table>
                <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Interval</TableHead><TableHead>Last Check</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
                <TableBody>
                  {sources.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell className="font-medium">{s.name}</TableCell>
                      <TableCell><Badge variant="outline">{s.source_type}</Badge></TableCell>
                      <TableCell>{s.check_interval_minutes} min</TableCell>
                      <TableCell className="text-muted-foreground text-sm">{s.last_check_at ? new Date(s.last_check_at).toLocaleString() : "Never"}</TableCell>
                      <TableCell><Badge variant={s.is_active ? "default" : "secondary"}>{s.is_active ? "Active" : "Inactive"}</Badge></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="targets" className="mt-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div><CardTitle>Exploit Targets</CardTitle><CardDescription>Managed targets for security testing</CardDescription></div>
                <Button size="sm" onClick={() => setShowAddTarget(true)}><Plus className="mr-1 size-4" /> Add Target</Button>
              </div>
            </CardHeader>
            <CardContent>
              {showAddTarget && (
                <Card className="mb-4 border-dashed">
                  <CardHeader className="pb-3"><CardTitle className="text-base">Add New Target</CardTitle></CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4">
                      <div><Label>Name</Label><Input placeholder="Target name" value={newTarget.name || ""} onChange={(e) => setNewTarget({ ...newTarget, name: e.target.value })} /></div>
                      <div><Label>Type</Label>
                        <Select value={newTarget.target_type} onValueChange={(v) => setNewTarget({ ...newTarget, target_type: v })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="web">Web Application</SelectItem><SelectItem value="api">API Endpoint</SelectItem>
                            <SelectItem value="host">Host/Server</SelectItem><SelectItem value="network">Network Device</SelectItem>
                          </SelectContent>
                        </Select></div>
                      <div><Label>Host / URL</Label><Input placeholder="192.168.1.100 or https://target.com" value={newTarget.host || ""} onChange={(e) => setNewTarget({ ...newTarget, host: e.target.value })} /></div>
                      <div><Label>Port</Label><Input type="number" value={newTarget.port || 80} onChange={(e) => setNewTarget({ ...newTarget, port: parseInt(e.target.value) || 80 })} /></div>
                    </div>
                    <div className="mt-4 flex justify-end gap-2">
                      <Button variant="outline" onClick={() => setShowAddTarget(false)}>Cancel</Button>
                      <Button onClick={handleAddTarget}>Add Target</Button>
                    </div>
                  </CardContent>
                </Card>
              )}
              <Table>
                <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Host:Port</TableHead><TableHead>Service</TableHead><TableHead>Version</TableHead><TableHead>Status</TableHead><TableHead></TableHead></TableRow></TableHeader>
                <TableBody>
                  {targets.map((t) => (
                    <TableRow key={t.id}>
                      <TableCell className="font-medium">{t.name}</TableCell>
                      <TableCell><Badge variant="outline">{t.target_type}</Badge></TableCell>
                      <TableCell className="font-mono text-sm">{t.host}:{t.port}</TableCell>
                      <TableCell>{t.service || "-"}</TableCell>
                      <TableCell className="font-mono text-xs">{t.version || "-"}</TableCell>
                      <TableCell><Badge variant={t.status === "online" ? "default" : t.status === "offline" ? "destructive" : "secondary"}>{t.status}</Badge></TableCell>
                      <TableCell><Button variant="ghost" size="sm" onClick={() => handleDeleteTarget(t.id)}><Trash2 className="size-4 text-red-400" /></Button></TableCell>
                    </TableRow>
                  ))}
                  {targets.length === 0 && <TableRow><TableCell colSpan={7} className="py-12 text-center text-muted-foreground">No targets configured</TableCell></TableRow>}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="payloads" className="mt-4">
          <PayloadGeneratorTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ---------- Payload Generator Component ----------

function PayloadGeneratorTab() {
  const [payloadType, setPayloadType] = React.useState("cc_skimmer");
  const [generatedPayload, setGeneratedPayload] = React.useState("");
  const [generating, setGenerating] = React.useState(false);
  const [config, setConfig] = React.useState<Record<string, string>>({});

  const payloadTypes = [
    { value: "cc_skimmer", label: "CC Skimmer", desc: "JS credit card form grabber" },
    { value: "cookie_exfil", label: "Cookie Exfil", desc: "Cookie stealer with HttpOnly bypass" },
    { value: "crypto_swap_dom", label: "Crypto Swap DOM", desc: "DOM-based crypto address swapper" },
    { value: "crypto_swap_clipboard", label: "Crypto Clipboard", desc: "Clipboard address replacer" },
    { value: "screen_exfil", label: "Screen Exfil", desc: "Screenshot capture & exfil" },
  ];

  async function generatePayload() {
    setGenerating(true);
    try {
      const res = await apiFetch("/api/payloads/generate", {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ type: payloadType, config }),
      });
      const data = await res.json();
      if (data.payload) { setGeneratedPayload(data.payload); toast.success("Payload generated"); }
      else throw new Error(data.error || "Failed");
    } catch { toast.error("Generation failed"); }
    finally { setGenerating(false); }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Terminal /> Payload Generator</CardTitle>
          <CardDescription>Generate client-side attack payloads for security testing</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div><Label>Payload Type</Label>
            <Select value={payloadType} onValueChange={setPayloadType}>
              <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
              <SelectContent>
                {payloadTypes.map((pt) => (<SelectItem key={pt.value} value={pt.value}>{pt.label} — {pt.desc}</SelectItem>))}
              </SelectContent>
            </Select>
          </div>
          {(payloadType === "cc_skimmer" || payloadType === "cookie_exfil" || payloadType === "screen_exfil") && (
            <div><Label>Exfiltration URL</Label>
              <Input placeholder="https://attacker.com/exfil" value={config.exfil_url || ""} onChange={(e) => setConfig({ ...config, exfil_url: e.target.value })} />
            </div>
          )}
          {(payloadType === "crypto_swap_dom" || payloadType === "crypto_swap_clipboard") && (
            <div className="grid grid-cols-2 gap-4">
              <div><Label>Attacker BTC</Label><Input placeholder="bc1q..." value={config.attacker_btc || ""} onChange={(e) => setConfig({ ...config, attacker_btc: e.target.value })} /></div>
              <div><Label>Attacker ETH</Label><Input placeholder="0x..." value={config.attacker_eth || ""} onChange={(e) => setConfig({ ...config, attacker_eth: e.target.value })} /></div>
            </div>
          )}
          <Button onClick={generatePayload} disabled={generating}>
            {generating ? <><Loader2 className="mr-2 size-4 animate-spin" /> Generating...</> : <><Bug className="mr-2 size-4" /> Generate Payload</>}
          </Button>
        </CardContent>
      </Card>
      {generatedPayload && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Generated Payload</CardTitle>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => { navigator.clipboard.writeText(generatedPayload); toast.success("Copied!"); }}>Copy</Button>
                <Button variant="outline" size="sm" onClick={() => {
                  const blob = new Blob([generatedPayload], { type: "application/javascript" });
                  const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
                  a.download = `${payloadType}_${Date.now()}.js`; a.click();
                }}><Download className="mr-1 size-4" /> Download</Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <pre className="max-h-96 overflow-auto rounded-md bg-gray-950 p-4 text-green-400 text-xs">
              <code>{generatedPayload}</code>
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

