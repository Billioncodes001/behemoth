import type { TFunction } from "i18next";

import { localizedError } from "./errors";
import { scheduleRuntimeText } from "./schedule-runtime";
import { taskMessages } from "./task-messages";

const messages: Record<string, string> = {};
for (const [key, [zh, en]] of Object.entries(taskMessages)) {
  if (!key.startsWith("taskUI.runtime.") || zh.includes("{{")) continue;
  messages[zh] = key;
  messages[en] = key;
}
const patterns: [RegExp, string][] = [
  [/^任务名称最多 (\d+) 个字符$/, "taskUI.runtime.nameLimit"],
  [/^Task name must be (\d+) characters or fewer$/, "taskUI.runtime.nameLimit"],
  [/^备注最多 (\d+) 个字符$/, "taskUI.runtime.remarkLimit"],
  [/^Notes must be (\d+) characters or fewer$/, "taskUI.runtime.remarkLimit"],
  [/^Worker 运行数量最多 (\d+)$/, "taskUI.runtime.workerLimit"],
  [/^Worker count must be (\d+) or fewer$/, "taskUI.runtime.workerLimit"],
  [/^task_ids 数量必须为 1-(\d+)$/, "taskUI.runtime.taskIdCount"],
  [/^Select between 1 and (\d+) task IDs$/, "taskUI.runtime.taskIdCount"],
];
export function taskError(error: unknown, translate: TFunction): string {
  const value = scheduleRuntimeText(localizedError(error, translate), translate);
  if (messages[value]) return translate(messages[value]);
  for (const [pattern, key] of patterns) {
    const match = pattern.exec(value);
    if (match) return translate(key, { limit: match[1] });
  }
  return value;
}
