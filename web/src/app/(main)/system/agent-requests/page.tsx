"use client";

import * as React from "react";

import Link from "next/link";

import type { TFunction } from "i18next";
import {
  BellRing,
  CheckIcon,
  CircleCheckIcon,
  CpuIcon,
  LightbulbIcon,
  MessageSquareWarningIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  Trash2Icon,
  WrenchIcon,
  XIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { notificationError } from "@/i18n/notify-runtime";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api } from "@/lib/api";
import type { AgentRequest, AgentRequestKind, AgentRequestStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 50;

const URGENCY_CLASS: Record<string, string> = {
  high: "bg-red-500/15 text-red-600 dark:text-red-400",
  normal: "",
  low: "bg-muted text-muted-foreground",
};

const STATUS_CLASS: Record<string, string> = {
  new: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  acknowledged: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  resolved: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  dismissed: "bg-muted text-muted-foreground",
};

const KIND_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  tool: WrenchIcon,
  tool_error: MessageSquareWarningIcon,
  resource: CpuIcon,
  capability: WrenchIcon,
  integration: WrenchIcon,
  infra: CpuIcon,
  data: WrenchIcon,
  other: LightbulbIcon,
};

const KIND_FILTERS: Array<AgentRequestKind | "all"> = [
  "all",
  "tool",
  "tool_error",
  "resource",
  "capability",
  "integration",
  "infra",
  "data",
  "other",
];

// splitRecommendation pulls a trailing "Recommendation: …" out of the free-text
// details so the card can render it as its own plain-language section.
function splitRecommendation(details: string): { body: string; recommendation: string } {
  const m = /recommendation\s*[:：]\s*/i.exec(details);
  if (!m) return { body: details, recommendation: "" };
  const idx = m.index;
  return {
    body: details.slice(0, idx).trim(),
    recommendation: details.slice(idx + m[0].length).trim(),
  };
}

export default function AgentRequestsPage() {
  const { t, liveT } = useLiveTranslation();
  const [tab, setTab] = React.useState<AgentRequestStatus | "all">("new");
  const [kind, setKind] = React.useState<AgentRequestKind | "all">("all");
  const [items, setItems] = React.useState<AgentRequest[]>([]);
  const [counts, setCounts] = React.useState<Record<string, number>>({});
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(0);
  const [busyId, setBusyId] = React.useState(0);

  const load = React.useCallback(() => {
    const status = tab === "all" ? "" : tab;
    api
      .agentRequests({ status, kind: kind === "all" ? undefined : kind, limit: PAGE_SIZE, offset: page * PAGE_SIZE })
      .then((r) => {
        setItems(r.requests);
        setTotal(r.total);
        setCounts(r.counts);
      })
      .catch((e) => toast.error(liveT("agentRequests.loadFailed", { message: notificationError(e, liveT) })));
  }, [tab, kind, page, liveT]);

  React.useEffect(() => {
    load();
    // New requests can land at any moment while the page is open — poll lightly.
    const id = setInterval(load, 20_000);
    return () => clearInterval(id);
  }, [load]);

  const act = React.useCallback(
    async (req: AgentRequest, status: AgentRequestStatus) => {
      setBusyId(req.id);
      try {
        await api.setAgentRequestStatus(req.id, status);
        toast.success(liveT("agentRequests.statusUpdated"));
        load();
      } catch (e) {
        toast.error(liveT("agentRequests.actionFailed", { message: notificationError(e, liveT) }));
      } finally {
        setBusyId(0);
      }
    },
    [load, liveT],
  );

  const remove = React.useCallback(
    async (req: AgentRequest) => {
      setBusyId(req.id);
      try {
        await api.deleteAgentRequest(req.id);
        toast.success(liveT("agentRequests.deleted"));
        load();
      } catch (e) {
        toast.error(liveT("agentRequests.actionFailed", { message: notificationError(e, liveT) }));
      } finally {
        setBusyId(0);
      }
    },
    [load, liveT],
  );

  const tabCount = (key: AgentRequestStatus | "all") => (key === "all" ? (counts.total ?? 0) : (counts[key] ?? 0));

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-4">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <BellRing className="size-4 shrink-0 text-muted-foreground" />
            <CardTitle className="truncate text-base">{t("agentRequests.title")}</CardTitle>
          </div>
          <CardDescription>{t("agentRequests.subtitle")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Tabs
              value={tab}
              onValueChange={(v) => {
                setTab(v as AgentRequestStatus | "all");
                setPage(0);
              }}
            >
              <TabsList>
                {(["new", "acknowledged", "resolved", "dismissed", "all"] as const).map((key) => (
                  <TabsTrigger key={key} value={key}>
                    {t(`agentRequests.tab.${key}`, { count: tabCount(key) })}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
            <Button variant="outline" size="sm" onClick={load}>
              <RefreshCwIcon /> {t("agentRequests.refresh")}
            </Button>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {KIND_FILTERS.map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => {
                  setKind(value);
                  setPage(0);
                }}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-xs transition-colors",
                  kind === value
                    ? "border-foreground/30 bg-foreground/10 font-medium text-foreground"
                    : "border-border text-muted-foreground hover:text-foreground",
                )}
              >
                {t(`agentRequests.kind.${value}`)}
              </button>
            ))}
          </div>

          {items.length === 0 ? (
            <div className="flex flex-col items-center gap-1 py-10 text-center">
              <MessageSquareWarningIcon className="size-6 text-muted-foreground" />
              <p className="text-sm">{t("agentRequests.empty")}</p>
              <p className="text-muted-foreground text-xs">{t("agentRequests.emptyHint")}</p>
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              {items.map((req) => (
                <RequestCard key={req.id} req={req} busy={busyId === req.id} t={t} onAct={act} onRemove={remove} />
              ))}
            </div>
          )}

          {pages > 1 && (
            <div className="flex items-center justify-between pt-1">
              <span className="text-muted-foreground text-xs">
                {t("agentRequests.pageInfo", { page: page + 1, total })}
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                  {t("agentRequests.prevPage")}
                </Button>
                <Button variant="outline" size="sm" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>
                  {t("agentRequests.nextPage")}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function RequestCard({
  req,
  busy,
  t,
  onAct,
  onRemove,
}: {
  req: AgentRequest;
  busy: boolean;
  t: TFunction;
  onAct: (req: AgentRequest, status: AgentRequestStatus) => Promise<void>;
  onRemove: (req: AgentRequest) => Promise<void>;
}) {
  const Icon = KIND_ICON[req.kind] ?? LightbulbIcon;
  const { body, recommendation } = splitRecommendation(req.details ?? "");
  const defaultRec = ["tool", "tool_error", "resource", "capability"].includes(req.kind)
    ? t(`agentRequests.defaultRec.${req.kind}`)
    : "";
  const suggestion = recommendation || defaultRec;

  return (
    <div className={cn("rounded-lg border p-3", req.status === "new" && "border-l-4 border-l-blue-500")}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className={cn(STATUS_CLASS[req.status])}>
          {t(`agentRequests.status.${req.status}`)}
        </Badge>
        <Badge variant="outline" className="gap-1">
          <Icon className="size-3" />
          {t(`agentRequests.kind.${req.kind}`)}
        </Badge>
        <Badge variant="outline" className={cn(URGENCY_CLASS[req.urgency])}>
          {t(`agentRequests.urgency.${req.urgency}`)}
        </Badge>
        <span className="truncate text-sm font-medium">{req.title}</span>
        <span className="ml-auto shrink-0 text-muted-foreground text-xs">{req.agent_key}</span>
      </div>

      <div className="mt-2 flex flex-col gap-2">
        {req.context && (
          <p className="text-xs">
            <span className="font-medium">{t("agentRequests.section.workingOn")}: </span>
            <span className="whitespace-pre-wrap text-muted-foreground">{req.context}</span>
          </p>
        )}
        {body && (
          <p className="text-xs">
            <span className="font-medium">{t("agentRequests.section.whatHappened")}: </span>
            <span className="whitespace-pre-wrap text-muted-foreground">{body}</span>
          </p>
        )}
        {suggestion && (
          <p className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1.5 text-xs">
            <span className="font-medium">{t("agentRequests.section.recommendation")}: </span>
            <span className="whitespace-pre-wrap">{suggestion}</span>
          </p>
        )}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-3">
        {req.task_id && (
          <Link
            href={`/function/tasks/${req.task_id}`}
            className="text-primary text-xs underline-offset-4 hover:underline"
          >
            {t("agentRequests.task")} #{req.task_id}
          </Link>
        )}
        <span className="text-muted-foreground text-xs">{req.created_at}</span>
        <div className="ml-auto flex flex-wrap gap-1.5">
          {req.status !== "new" && req.status !== "dismissed" && (
            <Button variant="outline" size="sm" disabled={busy} onClick={() => void onAct(req, "new")}>
              <RotateCcwIcon /> {t("agentRequests.reopen")}
            </Button>
          )}
          {req.status === "new" && (
            <Button variant="outline" size="sm" disabled={busy} onClick={() => void onAct(req, "acknowledged")}>
              <CheckIcon /> {t("agentRequests.acknowledge")}
            </Button>
          )}
          {req.status !== "resolved" && (
            <Button variant="outline" size="sm" disabled={busy} onClick={() => void onAct(req, "resolved")}>
              <CircleCheckIcon /> {t("agentRequests.resolve")}
            </Button>
          )}
          {req.status !== "dismissed" && (
            <Button variant="outline" size="sm" disabled={busy} onClick={() => void onAct(req, "dismissed")}>
              <XIcon /> {t("agentRequests.dismiss")}
            </Button>
          )}
          <Button variant="ghost" size="sm" disabled={busy} onClick={() => void onRemove(req)}>
            <Trash2Icon /> {t("agentRequests.delete")}
          </Button>
        </div>
      </div>
    </div>
  );
}
