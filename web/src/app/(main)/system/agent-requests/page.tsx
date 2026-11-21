"use client";

import * as React from "react";

import Link from "next/link";

import type { TFunction } from "i18next";
import {
  BellRing,
  CheckIcon,
  CircleCheckIcon,
  MessageSquareWarningIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  Trash2Icon,
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
import type { AgentRequest, AgentRequestStatus } from "@/lib/types";
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

export default function AgentRequestsPage() {
  const { t, liveT } = useLiveTranslation();
  const [tab, setTab] = React.useState<AgentRequestStatus | "all">("new");
  const [items, setItems] = React.useState<AgentRequest[]>([]);
  const [counts, setCounts] = React.useState<Record<string, number>>({});
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(0);
  const [busyId, setBusyId] = React.useState(0);

  const load = React.useCallback(() => {
    const status = tab === "all" ? "" : tab;
    api
      .agentRequests({ status, limit: PAGE_SIZE, offset: page * PAGE_SIZE })
      .then((r) => {
        setItems(r.requests);
        setTotal(r.total);
        setCounts(r.counts);
      })
      .catch((e) => toast.error(liveT("agentRequests.loadFailed", { message: notificationError(e, liveT) })));
  }, [tab, page, liveT]);

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
  return (
    <div className={cn("rounded-lg border p-3", req.status === "new" && "border-l-4 border-l-blue-500")}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className={cn("capitalize", STATUS_CLASS[req.status])}>
          {req.status}
        </Badge>
        <Badge variant="outline" className="capitalize">
          {req.kind}
        </Badge>
        <Badge variant="outline" className={cn("capitalize", URGENCY_CLASS[req.urgency])}>
          {req.urgency}
        </Badge>
        <span className="truncate font-medium text-sm">{req.title}</span>
        <span className="ml-auto shrink-0 text-muted-foreground text-xs">{req.agent_key}</span>
      </div>
      {(req.details ?? req.context) && (
        <div className="mt-2 flex flex-col gap-1.5">
          {req.details && (
            <p className="whitespace-pre-wrap text-muted-foreground text-xs">
              <span className="font-medium">{t("agentRequests.details")}: </span>
              {req.details}
            </p>
          )}
          {req.context && (
            <p className="whitespace-pre-wrap text-muted-foreground text-xs">
              <span className="font-medium">{t("agentRequests.context")}: </span>
              {req.context}
            </p>
          )}
        </div>
      )}
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
