"use client";

import * as React from "react";
import Link from "next/link";

import {
  Award,
  Bot,
  Bug,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  DollarSign,
  ExternalLink,
  Globe,
  Loader2,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Target,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api, apiFetch } from "@/lib/api";

interface BountyScopeAsset {
  target: string;
  asset_type?: string;
  eligible_for_bounty?: boolean;
  max_severity?: string;
  instruction?: string;
}

interface BountyProgramItem {
  id: number;
  program_key: string;
  name: string;
  platform: string;
  program_url: string;
  submission_url: string;
  offers_bounty: boolean;
  min_bounty_usd: number;
  max_bounty_usd: number;
  currency: string;
  registration_type: "open_direct" | "free_platform_account" | "application_or_kyc" | string;
  registration_steps: string;
  safe_harbor: boolean;
  in_scope_assets: BountyScopeAsset[];
  out_of_scope_assets: BountyScopeAsset[];
  in_scope_count: number;
  description: string;
  focus_vulns: string;
  tracker_status: string;
  linked_task_id?: number;
  linked_conversation_id?: number;
  earned_usd: number;
  submission_notes: string;
  source_feed: string;
  discovered_at: string;
  updated_at: string;
  started_hunting_at?: string;
  task_status?: string;
  finding_stats?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

interface BountyStatsSummary {
  total_discovered: number;
  paid_programs: number;
  no_registration_needed: number;
  actively_hunting: number;
  bugs_found_ready: number;
  submitted_or_rewarded: number;
  total_earned_usd: number;
}

interface BountyScannerState {
  config: {
    enabled: boolean;
    interval_hours: number;
    agent_assist: boolean;
    llm_profile_id?: number;
    paid_only: boolean;
  };
  running: boolean;
  last_run_at: string;
  last_added: number;
  last_refreshed: number;
  logs: {
    seq: number;
    timestamp: string;
    level: string;
    message: string;
  }[];
  summary: BountyStatsSummary;
}

import type { LLMProfile } from "@/lib/types";

async function bountyFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("behemoth_token") : null;
  const res = await apiFetch(`/api/bounties${path}`, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers as Record<string, string> | undefined),
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

function formatPayout(p: BountyProgramItem): string {
  if (!p.offers_bounty) return "VDP / Reputation";
  const sym = p.currency === "EUR" ? "EUR " : "$";
  if (p.max_bounty_usd > 0 && p.min_bounty_usd > 0) {
    return `${sym}${p.min_bounty_usd.toLocaleString()} - ${sym}${p.max_bounty_usd.toLocaleString()}`;
  }
  if (p.max_bounty_usd > 0) {
    return `Up to ${sym}${p.max_bounty_usd.toLocaleString()}`;
  }
  return "Paid Cash Bounty";
}

function platformLabel(plat: string): string {
  switch (plat.toLowerCase()) {
    case "self_hosted":
      return "Self-Hosted / Direct";
    case "hackerone":
      return "HackerOne";
    case "bugcrowd":
      return "Bugcrowd";
    case "intigriti":
      return "Intigriti";
    case "yeswehack":
      return "YesWeHack";
    case "immunefi":
      return "Immunefi (Web3)";
    case "federacy":
      return "Federacy";
    default:
      return plat.toUpperCase();
  }
}

function registrationBadge(regType: string) {
  switch (regType) {
    case "open_direct":
      return (
        <Badge className="bg-emerald-500/15 text-emerald-500 border-emerald-500/30 hover:bg-emerald-500/20">
          No Registration Needed
        </Badge>
      );
    case "application_or_kyc":
      return (
        <Badge variant="outline" className="border-amber-500/40 text-amber-500">
          Application / KYC Required
        </Badge>
      );
    default:
      return (
        <Badge variant="secondary" className="text-blue-400">
          Open Public Platform
        </Badge>
      );
  }
}

function trackerStatusBadge(st: string) {
  switch (st) {
    case "hunting":
      return <Badge className="bg-blue-500/15 text-blue-400 border-blue-500/30">Actively Hunting</Badge>;
    case "bug_found":
      return <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/40">Bug Found · Ready to Report</Badge>;
    case "submitted":
      return <Badge className="bg-violet-500/15 text-violet-400 border-violet-500/30">Submitted</Badge>;
    case "triaged":
      return <Badge className="bg-cyan-500/15 text-cyan-400 border-cyan-500/30">Triaged</Badge>;
    case "rewarded":
      return <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/40">Rewarded</Badge>;
    case "paused":
      return <Badge variant="outline">Paused</Badge>;
    default:
      return <Badge variant="outline">Discovered</Badge>;
  }
}

export default function BugBountiesPage() {
  const { t } = useLiveTranslation();
  const [activeTab, setActiveTab] = React.useState<string>("finder");
  const [finderPrograms, setFinderPrograms] = React.useState<BountyProgramItem[]>([]);
  const [trackerPrograms, setTrackerPrograms] = React.useState<BountyProgramItem[]>([]);
  const [summary, setSummary] = React.useState<BountyStatsSummary>({
    total_discovered: 0,
    paid_programs: 0,
    no_registration_needed: 0,
    actively_hunting: 0,
    bugs_found_ready: 0,
    submitted_or_rewarded: 0,
    total_earned_usd: 0,
  });
  const [scanner, setScanner] = React.useState<BountyScannerState | null>(null);
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);

  const [query, setQuery] = React.useState("");
  const [platformFilter, setPlatformFilter] = React.useState("all");
  const [regFilter, setRegFilter] = React.useState("all");
  const [paidOnly, setPaidOnly] = React.useState(true);
  const [sortBy, setSortBy] = React.useState("payout");

  const [loading, setLoading] = React.useState(true);
  const [scanningNow, setScanningNow] = React.useState(false);
  const [scoutingAgent, setScoutingAgent] = React.useState(false);
  const [expandedId, setExpandedId] = React.useState<number | null>(null);

  const [huntModalProg, setHuntModalProg] = React.useState<BountyProgramItem | null>(null);
  const [huntFocus, setHuntFocus] = React.useState("");
  const [huntProfileId, setHuntProfileId] = React.useState<string>("default");
  const [startingHunt, setStartingHunt] = React.useState(false);

  const [addOpen, setAddOpen] = React.useState(false);
  const [newName, setNewName] = React.useState("");
  const [newPlatform, setNewPlatform] = React.useState("self_hosted");
  const [newURL, setNewURL] = React.useState("");
  const [newSubURL, setNewSubURL] = React.useState("");
  const [newRegType, setNewRegType] = React.useState("open_direct");
  const [newMaxUSD, setNewMaxUSD] = React.useState("");
  const [newInScope, setNewInScope] = React.useState("");
  const [newOutScope, setNewOutScope] = React.useState("");
  const [newDesc, setNewDesc] = React.useState("");
  const [savingNew, setSavingNew] = React.useState(false);

  const [editTrackProg, setEditTrackProg] = React.useState<BountyProgramItem | null>(null);
  const [editStatus, setEditStatus] = React.useState("hunting");
  const [editEarned, setEditEarned] = React.useState("0");
  const [editNotes, setEditNotes] = React.useState("");
  const [savingTrack, setSavingTrack] = React.useState(false);

  const loadData = React.useCallback(async () => {
    try {
      const qs = new URLSearchParams({
        tab: "finder",
        platform: platformFilter,
        registration_type: regFilter,
        paid_only: paidOnly ? "true" : "false",
        sort: sortBy,
        limit: "250",
      });
      if (query.trim()) qs.set("q", query.trim());

      const [finderRes, trackerRes, scannerRes] = await Promise.all([
        bountyFetch<{ programs: BountyProgramItem[]; summary: BountyStatsSummary }>(`/programs?${qs.toString()}`),
        bountyFetch<{ programs: BountyProgramItem[]; summary: BountyStatsSummary }>(`/programs?tab=tracker&sort=updated&limit=200`),
        bountyFetch<BountyScannerState>("/scanner"),
      ]);
      setFinderPrograms(finderRes.programs ?? []);
      setTrackerPrograms(trackerRes.programs ?? []);
      setSummary(finderRes.summary ?? scannerRes.summary);
      setScanner(scannerRes);
    } catch {
      /* next poll retries */
    } finally {
      setLoading(false);
    }
  }, [platformFilter, regFilter, paidOnly, sortBy, query]);

  React.useEffect(() => {
    void loadData();
    api
      .llmProfiles()
      .then((list) => setProfiles(list))
      .catch(() => {});
  }, [loadData]);

  React.useEffect(() => {
    const timer = window.setInterval(() => {
      void loadData();
    }, scanner?.running ? 3000 : 12000);
    return () => window.clearInterval(timer);
  }, [loadData, scanner?.running]);

  const handleScanNow = async (scoutOnly = false) => {
    if (scoutOnly) setScoutingAgent(true);
    else setScanningNow(true);
    try {
      const res = await bountyFetch<{ ok: boolean; scout_conversation_id?: number }>("/scanner/run", {
        method: "POST",
        body: JSON.stringify({ scout_only: scoutOnly }),
      });
      if (scoutOnly && res.scout_conversation_id) {
        toast.success(`Bounty Scout AI Agent dispatched (Chat Conversation #${res.scout_conversation_id})`);
      } else {
        toast.success("Online Bug Bounty directory scan started");
      }
      setTimeout(() => void loadData(), 1500);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setScanningNow(false);
      setScoutingAgent(false);
    }
  };

  const handleUpdateScannerCfg = async (patch: Partial<BountyScannerState["config"]>) => {
    if (!scanner) return;
    const nextCfg = { ...scanner.config, ...patch };
    try {
      await bountyFetch("/scanner", {
        method: "PUT",
        body: JSON.stringify(nextCfg),
      });
      toast.success("Bounty scanner configuration updated");
      void loadData();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  };

  const handleConfirmStartHunt = async () => {
    if (!huntModalProg) return;
    setStartingHunt(true);
    try {
      const pid = huntProfileId !== "default" ? Number(huntProfileId) : undefined;
      const res = await bountyFetch<{ ok: boolean; task_id: string }>(`/programs/${huntModalProg.id}/hunt`, {
        method: "POST",
        body: JSON.stringify({
          custom_focus: huntFocus.trim(),
          llm_profile_id: pid,
        }),
      });
      toast.success(`Autonomous Bounty Hunt started (Task #${res.task_id}) — moved to Active Tracker!`);
      setHuntModalProg(null);
      setHuntFocus("");
      setActiveTab("tracker");
      await loadData();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setStartingHunt(false);
    }
  };

  const handleCreateCustomProgram = async () => {
    if (!newName.trim() || !newURL.trim()) {
      toast.warning("Program Name and Policy URL are required.");
      return;
    }
    setSavingNew(true);
    try {
      const inList = newInScope
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const outList = newOutScope
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      await bountyFetch("/programs", {
        method: "POST",
        body: JSON.stringify({
          name: newName.trim(),
          platform: newPlatform,
          program_url: newURL.trim(),
          submission_url: newSubURL.trim() || newURL.trim(),
          registration_type: newRegType,
          max_bounty_usd: Number(newMaxUSD) || 0,
          offers_bounty: true,
          safe_harbor: true,
          in_scope_targets: inList,
          out_of_scope_targets: outList,
          description: newDesc.trim(),
        }),
      });
      toast.success("Bug Bounty Program registered");
      setAddOpen(false);
      setNewName("");
      setNewURL("");
      setNewSubURL("");
      setNewMaxUSD("");
      setNewInScope("");
      setNewOutScope("");
      setNewDesc("");
      await loadData();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingNew(false);
    }
  };

  const handleSaveTrackerUpdate = async () => {
    if (!editTrackProg) return;
    setSavingTrack(true);
    try {
      await bountyFetch(`/programs/${editTrackProg.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          tracker_status: editStatus,
          earned_usd: Number(editEarned) || 0,
          submission_notes: editNotes,
        }),
      });
      toast.success("Bounty tracker updated");
      setEditTrackProg(null);
      await loadData();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingTrack(false);
    }
  };

  const handleToggleLinkedTask = async (p: BountyProgramItem) => {
    if (!p.linked_task_id) return;
    try {
      if (p.task_status === "running") {
        await api.controlTask(String(p.linked_task_id), "pause");
        await bountyFetch(`/programs/${p.id}`, {
          method: "PATCH",
          body: JSON.stringify({ tracker_status: "paused" }),
        });
        toast.info(`Paused hunting Task #${p.linked_task_id}`);
      } else {
        await api.controlTask(String(p.linked_task_id), "resume");
        await bountyFetch(`/programs/${p.id}`, {
          method: "PATCH",
          body: JSON.stringify({ tracker_status: "hunting" }),
        });
        toast.success(`Resumed hunting Task #${p.linked_task_id}`);
      }
      await loadData();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  };

  const handleDeleteProgram = async (id: number) => {
    try {
      await bountyFetch(`/programs/${id}`, { method: "DELETE" });
      toast.success("Program removed");
      await loadData();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="flex flex-1 flex-col gap-5 pb-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2.5 text-xl font-semibold tracking-tight">
            <Award className="h-5 w-5 text-amber-400" />
            {t("bounties.title")}
          </h1>
          <p className="mt-1 text-xs text-muted-foreground">
            {t("bounties.subtitle")}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setAddOpen(true)}>
            <Plus className="mr-1.5 h-3.5 w-3.5" />
            {t("bounties.addProgram")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void handleScanNow(true)}
            disabled={scoutingAgent}
          >
            {scoutingAgent ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Sparkles className="mr-1.5 h-3.5 w-3.5 text-violet-400" />}
            {t("bounties.runScout")}
          </Button>
          <Button
            size="sm"
            onClick={() => void handleScanNow(false)}
            disabled={scanningNow || scanner?.running}
          >
            {scanningNow || scanner?.running ? (
              <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
            )}
            {scanner?.running ? t("bounties.scanning") : t("bounties.scanOnline")}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Card className="gap-1">
          <CardHeader className="pb-1">
            <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <Globe className="h-3.5 w-3.5" />
              Discovered Bounties
            </div>
            <div className="text-2xl font-semibold tabular-nums">{summary.total_discovered}</div>
          </CardHeader>
          <CardContent className="text-[11px] text-muted-foreground">
            {summary.paid_programs} offering monetary rewards
          </CardContent>
        </Card>

        <Card className="gap-1">
          <CardHeader className="pb-1">
            <div className="flex items-center gap-1.5 text-[11px] text-emerald-400">
              <ShieldCheck className="h-3.5 w-3.5" />
              No Signup Needed
            </div>
            <div className="text-2xl font-semibold tabular-nums text-emerald-400">
              {summary.no_registration_needed}
            </div>
          </CardHeader>
          <CardContent className="text-[11px] text-muted-foreground">
            Self-hosted &amp; direct-submission scopes
          </CardContent>
        </Card>

        <Card className="gap-1">
          <CardHeader className="pb-1">
            <div className="flex items-center gap-1.5 text-[11px] text-blue-400">
              <Target className="h-3.5 w-3.5" />
              Actively Hunting
            </div>
            <div className="text-2xl font-semibold tabular-nums text-blue-400">{summary.actively_hunting}</div>
          </CardHeader>
          <CardContent className="text-[11px] text-muted-foreground">
            Autonomous tasks probing in-scope assets
          </CardContent>
        </Card>

        <Card className="gap-1">
          <CardHeader className="pb-1">
            <div className="flex items-center gap-1.5 text-[11px] text-rose-400">
              <Bug className="h-3.5 w-3.5" />
              Bugs Ready to Report
            </div>
            <div className="text-2xl font-semibold tabular-nums text-rose-400">{summary.bugs_found_ready}</div>
          </CardHeader>
          <CardContent className="text-[11px] text-muted-foreground">
            {summary.submitted_or_rewarded} submitted / rewarded
          </CardContent>
        </Card>

        <Card className="gap-1">
          <CardHeader className="pb-1">
            <div className="flex items-center gap-1.5 text-[11px] text-amber-400">
              <DollarSign className="h-3.5 w-3.5" />
              Rewards Earned
            </div>
            <div className="text-2xl font-semibold tabular-nums text-amber-400">
              ${summary.total_earned_usd.toLocaleString()}
            </div>
          </CardHeader>
          <CardContent className="text-[11px] text-muted-foreground">Tracked USD bounty payouts</CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="finder">
            {t("bounties.tabFinder")} ({finderPrograms.length})
          </TabsTrigger>
          <TabsTrigger value="tracker">
            {t("bounties.tabTracker")} ({trackerPrograms.length})
          </TabsTrigger>
          <TabsTrigger value="scanner">
            {t("bounties.tabScanner")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="finder" className="space-y-4">
          <Card>
            <CardContent className="pt-4">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative min-w-[220px] flex-1">
                  <Search className="pointer-events-none absolute top-2.5 left-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search companies, domains (*.example.com), APIs, or keywords..."
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    className="pl-8 text-sm"
                  />
                </div>
                <Select value={platformFilter} onValueChange={setPlatformFilter}>
                  <SelectTrigger className="w-[185px] text-xs">
                    <SelectValue placeholder="Platform" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Platforms</SelectItem>
                    <SelectItem value="self_hosted">Self-Hosted / Direct</SelectItem>
                    <SelectItem value="hackerone">HackerOne</SelectItem>
                    <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                    <SelectItem value="intigriti">Intigriti</SelectItem>
                    <SelectItem value="yeswehack">YesWeHack</SelectItem>
                    <SelectItem value="immunefi">Immunefi (Web3)</SelectItem>
                    <SelectItem value="federacy">Federacy</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={regFilter} onValueChange={setRegFilter}>
                  <SelectTrigger className="w-[195px] text-xs">
                    <SelectValue placeholder="Registration" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Enrollment Types</SelectItem>
                    <SelectItem value="open_direct">No Registration Needed</SelectItem>
                    <SelectItem value="free_platform_account">Open Public Platform</SelectItem>
                    <SelectItem value="application_or_kyc">Application / KYC Required</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={sortBy} onValueChange={setSortBy}>
                  <SelectTrigger className="w-[165px] text-xs">
                    <SelectValue placeholder="Sort by" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="payout">Highest Bounty ($)</SelectItem>
                    <SelectItem value="scope">Most In-Scope Assets</SelectItem>
                    <SelectItem value="newest">Newest Discovered</SelectItem>
                  </SelectContent>
                </Select>

                <div className="flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs">
                  <Switch id="paid-only" checked={paidOnly} onCheckedChange={setPaidOnly} />
                  <Label htmlFor="paid-only" className="cursor-pointer text-xs">
                    Paid Bounties Only
                  </Label>
                </div>
              </div>
            </CardContent>
          </Card>

          {loading ? (
            <Card>
              <CardContent className="flex items-center justify-center py-14 text-sm text-muted-foreground">
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Loading discovered bug bounty programs...
              </CardContent>
            </Card>
          ) : finderPrograms.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center gap-3 py-14 text-center">
                <Award className="h-8 w-8 text-muted-foreground/60" />
                <div className="text-sm font-medium">No matching bug bounty programs yet</div>
                <p className="max-w-md text-xs text-muted-foreground">
                  Click &ldquo;Scan Online Bounties&rdquo; to pull hundreds of live paid programs from ProjectDiscovery Chaos, HackerOne, Bugcrowd, Intigriti, and YesWeHack, or dispatch the AI Bounty Scout agent.
                </p>
                <Button size="sm" onClick={() => void handleScanNow(false)}>
                  <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
                  Scan Online Bounties Now
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {finderPrograms.map((p) => {
                const isExpanded = expandedId === p.id;
                const alreadyTracked = p.tracker_status !== "discovered";
                return (
                  <Card key={p.id} className="transition-colors hover:border-foreground/20">
                    <CardContent className="p-4">
                      <div className="flex flex-wrap items-start justify-between gap-4">
                        <div className="min-w-0 flex-1 space-y-1.5">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-base font-semibold">{p.name}</span>
                            <Badge variant="outline" className="font-mono text-[11px]">
                              {platformLabel(p.platform)}
                            </Badge>
                            {registrationBadge(p.registration_type)}
                            {p.safe_harbor && (
                              <Badge variant="outline" className="border-emerald-500/30 text-emerald-500 text-[11px]">
                                Safe Harbor
                              </Badge>
                            )}
                            {alreadyTracked && trackerStatusBadge(p.tracker_status)}
                          </div>
                          <p className="text-xs text-muted-foreground line-clamp-2">
                            {p.description || "Authorized public vulnerability reward program."}
                          </p>
                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                            <span className="font-medium text-amber-400">{formatPayout(p)}</span>
                            <span>{p.in_scope_count || p.in_scope_assets.length} in-scope asset(s)</span>
                            <a
                              href={p.program_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-blue-400 hover:underline"
                            >
                              Policy &amp; Rules <ExternalLink className="h-3 w-3" />
                            </a>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setExpandedId(isExpanded ? null : p.id)}
                          >
                            {isExpanded ? (
                              <>
                                Hide Scope <ChevronUp className="ml-1 h-4 w-4" />
                              </>
                            ) : (
                              <>
                                View Scope <ChevronDown className="ml-1 h-4 w-4" />
                              </>
                            )}
                          </Button>
                          {p.linked_task_id ? (
                            <Button asChild variant="outline" size="sm">
                              <Link href={`/function/tasks/detail?id=${p.linked_task_id}`}>
                                View Hunt Task #{p.linked_task_id}
                              </Link>
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              onClick={() => {
                                setHuntModalProg(p);
                                setHuntFocus("");
                              }}
                            >
                              <Play className="mr-1.5 h-3.5 w-3.5" />
                              Start Hunting
                            </Button>
                          )}
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="mt-4 space-y-3 border-t pt-3 text-xs">
                          <div className="rounded-md bg-muted/40 p-3">
                            <div className="font-semibold mb-1">Enrollment &amp; Submission Guide</div>
                            <p className="text-muted-foreground">
                              {p.registration_steps || "Review the official program policy before submitting findings."}
                            </p>
                            {p.submission_url && (
                              <a
                                href={p.submission_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="mt-1.5 inline-flex items-center gap-1 text-emerald-400 hover:underline"
                              >
                                Direct Report Submission Link <ExternalLink className="h-3 w-3" />
                              </a>
                            )}
                          </div>

                          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                            <div className="rounded-md border p-3">
                              <div className="mb-2 font-semibold text-emerald-400">
                                Authorized In-Scope Assets ({p.in_scope_assets.length})
                              </div>
                              <div className="max-h-48 space-y-1.5 overflow-y-auto pr-1">
                                {p.in_scope_assets.map((a, idx) => (
                                  <div key={idx} className="flex flex-col rounded bg-muted/30 px-2 py-1">
                                    <div className="flex items-center justify-between gap-2">
                                      <span className="font-mono font-medium">{a.target}</span>
                                      <div className="flex items-center gap-1">
                                        {a.asset_type && (
                                          <span className="text-[10px] text-muted-foreground">{a.asset_type}</span>
                                        )}
                                        {a.eligible_for_bounty && (
                                          <Badge variant="secondary" className="text-[10px] px-1 py-0 text-amber-400">
                                            Bounty
                                          </Badge>
                                        )}
                                      </div>
                                    </div>
                                    {a.instruction && (
                                      <span className="text-[11px] text-muted-foreground mt-0.5">{a.instruction}</span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>

                            <div className="rounded-md border p-3">
                              <div className="mb-2 font-semibold text-rose-400">
                                Out-of-Scope Exclusions ({p.out_of_scope_assets.length})
                              </div>
                              {p.out_of_scope_assets.length === 0 ? (
                                <p className="text-muted-foreground">
                                  No explicit out-of-scope domains listed (standard Safe Harbor exclusions apply: no DoS, spam, or social engineering).
                                </p>
                              ) : (
                                <div className="max-h-48 space-y-1.5 overflow-y-auto pr-1">
                                  {p.out_of_scope_assets.map((o, idx) => (
                                    <div key={idx} className="rounded bg-rose-500/5 px-2 py-1 font-mono text-[11px] text-rose-300">
                                      {o.target}
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="tracker" className="space-y-4">
          {trackerPrograms.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center gap-3 py-14 text-center">
                <Target className="h-8 w-8 text-muted-foreground/60" />
                <div className="text-sm font-medium">No active bounty hunts yet</div>
                <p className="max-w-md text-xs text-muted-foreground">
                  Pick any bug bounty program in the Bounty Finder tab and click &ldquo;Start Hunting&rdquo; — BEHEMOTH will automatically enroll its authorized scope, block out-of-scope hosts, launch an autonomous bug-hunting task, and track confirmed findings &amp; payouts here.
                </p>
                <Button variant="outline" size="sm" onClick={() => setActiveTab("finder")}>
                  Browse Bounty Finder
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {trackerPrograms.map((p) => {
                const fs = p.finding_stats ?? { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
                return (
                  <Card key={p.id}>
                    <CardContent className="p-4 space-y-3">
                      <div className="flex flex-wrap items-start justify-between gap-4">
                        <div className="space-y-1.5">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-base font-semibold">{p.name}</span>
                            <Badge variant="outline" className="font-mono text-[11px]">
                              {platformLabel(p.platform)}
                            </Badge>
                            {trackerStatusBadge(p.tracker_status)}
                            {p.task_status && (
                              <Badge variant="secondary" className="font-mono text-[11px]">
                                Task #{p.linked_task_id}: {p.task_status}
                              </Badge>
                            )}
                          </div>
                          <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
                            <span className="font-medium text-amber-400">{formatPayout(p)}</span>
                            {p.earned_usd > 0 && (
                              <span className="font-semibold text-emerald-400">
                                Earned: ${p.earned_usd.toLocaleString()}
                              </span>
                            )}
                            <a
                              href={p.submission_url || p.program_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-blue-400 hover:underline"
                            >
                              Submit Report <ExternalLink className="h-3 w-3" />
                            </a>
                          </div>
                        </div>

                        <div className="flex flex-wrap items-center gap-2">
                          {p.linked_task_id && (
                            <>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => void handleToggleLinkedTask(p)}
                              >
                                {p.task_status === "running" ? (
                                  <>
                                    <Pause className="mr-1 h-3.5 w-3.5" /> Pause Hunt
                                  </>
                                ) : (
                                  <>
                                    <Play className="mr-1 h-3.5 w-3.5" /> Resume Hunt
                                  </>
                                )}
                              </Button>
                              <Button asChild size="sm" variant="secondary">
                                <Link href={`/function/tasks/detail?id=${p.linked_task_id}`}>
                                  Open Live Task #{p.linked_task_id}
                                </Link>
                              </Button>
                            </>
                          )}
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setEditTrackProg(p);
                              setEditStatus(p.tracker_status);
                              setEditEarned(String(p.earned_usd || 0));
                              setEditNotes(p.submission_notes || "");
                            }}
                          >
                            Update Status / Payout
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => void handleDeleteProgram(p.id)}
                          >
                            <Trash2 className="h-4 w-4 text-muted-foreground hover:text-destructive" />
                          </Button>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-muted/30 px-3 py-2 text-xs">
                        <div className="flex flex-wrap items-center gap-3">
                          <span className="font-medium">Confirmed Findings Discovered:</span>
                          <span className="font-semibold text-rose-500">Critical: {fs.critical}</span>
                          <span className="font-semibold text-red-400">High: {fs.high}</span>
                          <span className="text-amber-400">Medium: {fs.medium}</span>
                          <span className="text-slate-400">Low: {fs.low}</span>
                        </div>
                        {fs.total > 0 && (
                          <Link href="/function/findings" className="text-emerald-400 hover:underline font-medium">
                            Open Findings &amp; Bounty Reports ({fs.total}) -&gt;
                          </Link>
                        )}
                      </div>

                      {p.submission_notes && (
                        <div className="rounded-md bg-muted/20 px-3 py-2 text-xs text-muted-foreground">
                          <span className="font-medium text-foreground">Notes: </span>
                          {p.submission_notes}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="scanner" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Bot className="h-4 w-4 text-violet-400" />
                Automated Online Bug Bounty Scanner &amp; Scout Agent
              </CardTitle>
              <CardDescription>
                Continuously harvest public bug bounty feeds (ProjectDiscovery Chaos, HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy) and dispatch the built-in <span className="font-mono">bounty_scout</span> AI agent to discover self-hosted &amp; zero-signup bounty programs across the internet
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <div className="flex items-center justify-between rounded-lg border p-3">
                  <div>
                    <Label className="text-sm font-medium">Auto-Scan Online Bounties</Label>
                    <p className="text-xs text-muted-foreground">Periodically refresh public bounty directories</p>
                  </div>
                  <Switch
                    checked={scanner?.config.enabled ?? false}
                    onCheckedChange={(v) => void handleUpdateScannerCfg({ enabled: v })}
                  />
                </div>

                <div className="flex items-center justify-between rounded-lg border p-3">
                  <div>
                    <Label className="text-sm font-medium">AI Bounty Scout Agent</Label>
                    <p className="text-xs text-muted-foreground">Use Search + Chromium to find self-hosted bounties</p>
                  </div>
                  <Switch
                    checked={scanner?.config.agent_assist ?? true}
                    onCheckedChange={(v) => void handleUpdateScannerCfg({ agent_assist: v })}
                  />
                </div>

                <div className="flex items-center justify-between rounded-lg border p-3">
                  <Label className="text-sm font-medium">Scan Interval</Label>
                  <Select
                    value={String(scanner?.config.interval_hours ?? 12)}
                    onValueChange={(v) => void handleUpdateScannerCfg({ interval_hours: Number(v) })}
                  >
                    <SelectTrigger className="w-[130px] text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="6">Every 6 hours</SelectItem>
                      <SelectItem value="12">Every 12 hours</SelectItem>
                      <SelectItem value="24">Every 24 hours</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="rounded-lg border bg-black/40 p-3">
                <div className="mb-2 flex items-center justify-between text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">Live Bounty Scanner Log</span>
                  {scanner?.last_run_at && (
                    <span>
                      Last scan: {new Date(scanner.last_run_at).toLocaleString()} (+{scanner.last_added} new,{" "}
                      {scanner.last_refreshed} updated)
                    </span>
                  )}
                </div>
                <div className="max-h-72 space-y-1 overflow-y-auto font-mono text-xs">
                  {!scanner?.logs || scanner.logs.length === 0 ? (
                    <div className="py-6 text-center text-muted-foreground">
                      No scan logs yet — click &ldquo;Scan Online Bounties&rdquo; to harvest programs now.
                    </div>
                  ) : (
                    [...scanner.logs].reverse().map((l) => (
                      <div key={l.seq} className="flex items-start gap-2">
                        <span className="shrink-0 text-muted-foreground">
                          {new Date(l.timestamp).toLocaleTimeString()}
                        </span>
                        <span
                          className={
                            l.level === "success"
                              ? "text-emerald-400"
                              : l.level === "warn" || l.level === "error"
                                ? "text-amber-400"
                                : l.level === "source"
                                  ? "text-cyan-400"
                                  : "text-foreground/90"
                          }
                        >
                          {l.message}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Dialog open={!!huntModalProg} onOpenChange={(o) => !o && setHuntModalProg(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              Start Autonomous Bug Bounty Hunt: {huntModalProg?.name}
            </DialogTitle>
            <DialogDescription>
              BEHEMOTH will automatically import this program&apos;s authorized in-scope domains into the Asset Scope Guard, apply block rules for out-of-scope hosts, spawn a dedicated Bug Bounty Hunting Task, and track confirmed findings until reportable bugs are verified.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1.5">
              <Label className="text-xs">LLM Profile for Hunting Agents</Label>
              <Select value={huntProfileId} onValueChange={setHuntProfileId}>
                <SelectTrigger className="text-xs">
                  <SelectValue placeholder="Use Active Default Profile" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">Active Default LLM Profile</SelectItem>
                  {profiles.map((p) => (
                    <SelectItem key={p.id} value={String(p.id)}>
                      {p.name} ({p.model})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Optional Hunting Focus / Program Instructions</Label>
              <Textarea
                placeholder="e.g. Prioritize API authentication bypass, IDOR/BOLA, SSRF, and SQLi on api.* subdomains; include X-Bug-Bounty researcher header if required..."
                value={huntFocus}
                onChange={(e) => setHuntFocus(e.target.value)}
                rows={3}
                className="text-xs"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setHuntModalProg(null)} disabled={startingHunt}>
              Cancel
            </Button>
            <Button size="sm" onClick={() => void handleConfirmStartHunt()} disabled={startingHunt}>
              {startingHunt ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Play className="mr-1.5 h-3.5 w-3.5" />}
              Launch Bounty Hunt &amp; Track
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Register Custom Bug Bounty Program</DialogTitle>
            <DialogDescription>
              Add a standalone company bounty, private invite, or Web3 program to the Finder &amp; Tracker.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label className="text-xs">Program / Company Name</Label>
                <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Acme Corp" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Platform</Label>
                <Select value={newPlatform} onValueChange={setNewPlatform}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="self_hosted">Self-Hosted / Direct</SelectItem>
                    <SelectItem value="hackerone">HackerOne</SelectItem>
                    <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                    <SelectItem value="intigriti">Intigriti</SelectItem>
                    <SelectItem value="yeswehack">YesWeHack</SelectItem>
                    <SelectItem value="immunefi">Immunefi</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label className="text-xs">Policy URL</Label>
                <Input value={newURL} onChange={(e) => setNewURL(e.target.value)} placeholder="https://example.com/security" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Max Critical Payout (USD)</Label>
                <Input type="number" value={newMaxUSD} onChange={(e) => setNewMaxUSD(e.target.value)} placeholder="15000" />
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Registration Requirement</Label>
              <Select value={newRegType} onValueChange={setNewRegType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="open_direct">No Registration Needed (Direct Submission)</SelectItem>
                  <SelectItem value="free_platform_account">Open Public Platform Account</SelectItem>
                  <SelectItem value="application_or_kyc">Application / KYC Required</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Authorized In-Scope Targets (one per line or comma-separated)</Label>
              <Textarea
                rows={3}
                value={newInScope}
                onChange={(e) => setNewInScope(e.target.value)}
                placeholder="*.example.com&#10;https://api.example.com"
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Out-of-Scope Exclusions (optional)</Label>
              <Textarea
                rows={2}
                value={newOutScope}
                onChange={(e) => setNewOutScope(e.target.value)}
                placeholder="blog.example.com, status.example.com"
                className="font-mono text-xs"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setAddOpen(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={() => void handleCreateCustomProgram()} disabled={savingNew}>
              {savingNew && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
              Save Program
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!editTrackProg} onOpenChange={(o) => !o && setEditTrackProg(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Update Bounty Tracker: {editTrackProg?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <div className="space-y-1">
              <Label className="text-xs">Pipeline Status</Label>
              <Select value={editStatus} onValueChange={setEditStatus}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="hunting">Actively Hunting</SelectItem>
                  <SelectItem value="bug_found">Bug Found · Ready to Report</SelectItem>
                  <SelectItem value="submitted">Submitted to Program</SelectItem>
                  <SelectItem value="triaged">Triaged</SelectItem>
                  <SelectItem value="rewarded">Rewarded</SelectItem>
                  <SelectItem value="paused">Paused</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Confirmed Bounty Earned (USD)</Label>
              <Input type="number" value={editEarned} onChange={(e) => setEditEarned(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Submission &amp; Finding Notes</Label>
              <Textarea
                rows={3}
                value={editNotes}
                onChange={(e) => setEditNotes(e.target.value)}
                placeholder="Report ID, triage feedback, or verified vulnerability summary..."
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setEditTrackProg(null)}>
              Cancel
            </Button>
            <Button size="sm" onClick={() => void handleSaveTrackerUpdate()} disabled={savingTrack}>
              {savingTrack && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
