import type { TFunction } from "i18next";

import { localizedError } from "./errors";
import { notifyMessages } from "./notify-messages";

// Only recognize messages owned by BEHEMOTH. Provider responses remain verbatim.
const messages: Record<string, string> = {
  "The notification configuration response is incomplete. Refresh to try again.": "notify.runtime.invalidMeta",
};
for (const [key, [zh, en]] of Object.entries(notifyMessages)) {
  if (!key.startsWith("notify.runtime.") || zh.includes("{{")) continue;
  messages[zh] = key;
  messages[en] = key;
}
const prefixes: [string, string][] = [
  ["渠道类型无效，可选：", "notify.runtime.kindOptions"],
  ["Invalid channel type. Choose: ", "notify.runtime.kindOptions"],
  ["Webhook 地址无效: ", "notify.runtime.webhookInvalid"],
  ["Invalid webhook URL: ", "notify.runtime.webhookInvalid"],
  ["API 地址无效: ", "notify.runtime.apiInvalid"],
  ["Invalid API URL: ", "notify.runtime.apiInvalid"],
  ["目标 URL 无效: ", "notify.runtime.targetInvalid"],
  ["Invalid target URL: ", "notify.runtime.targetInvalid"],
  ["请求体模板语法错误: ", "notify.runtime.templateSyntax"],
  ["Body template syntax error: ", "notify.runtime.templateSyntax"],
  ["渲染请求体模板失败: ", "notify.runtime.templateRender"],
  ["Could not render body template: ", "notify.runtime.templateRender"],
  ["请求体不是合法 JSON: ", "notify.runtime.requestJson"],
  ["Request body is not valid JSON: ", "notify.runtime.requestJson"],
];
export function notificationError(error: unknown, translate: TFunction): string {
  const value = localizedError(error, translate);
  if (messages[value]) return translate(messages[value]);
  for (const [prefix, key] of prefixes) {
    if (value.startsWith(prefix)) return translate(key, { detail: value.slice(prefix.length) });
  }
  return value;
}
