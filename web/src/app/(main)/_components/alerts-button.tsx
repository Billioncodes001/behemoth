"use client";

import * as React from "react";

import Link from "next/link";

import { BellIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { api } from "@/lib/api";

/**
 * 顶栏的「Agent 请求」提醒铃铛：每 30 秒轮询一次未处理（status=new）的
 * report_need 请求计数，有新请求就亮出角标，点击直达
 * System → Agent Requests 页。轮询失败一律静默——顶栏不是报错的地方。
 */
export function AlertsButton() {
  const { t } = useTranslation();
  const [unread, setUnread] = React.useState(0);

  React.useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .agentRequestCounts()
        .then((c) => {
          if (alive) setUnread(c.new ?? 0);
        })
        .catch(() => {
          // 静默：后端未就绪 / 网络抖动都不该在顶栏弹错误。
        });
    void load();
    const id = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const hint = unread > 0 ? t("agentRequests.alertsHint", { count: unread }) : t("agentRequests.alertsTitle");

  return (
    <Link
      href="/system/agent-requests"
      title={hint}
      aria-label={hint}
      className="relative inline-flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
    >
      <BellIcon className="size-4" />
      {unread > 0 && (
        <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-1 font-medium text-[10px] text-primary-foreground">
          {unread > 99 ? "99+" : unread}
        </span>
      )}
    </Link>
  );
}
