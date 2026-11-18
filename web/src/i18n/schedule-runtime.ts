import type { TFunction } from "i18next";

import { scheduleMessages } from "./schedule-messages";

// Recognize existing server-owned schedule messages, including stored history.
// Unknown details and user content are preserved verbatim.
const messages: Record<string, string> = {};
for (const [key, [zh, en]] of Object.entries(scheduleMessages)) {
  if (!key.startsWith("schedule.runtime.") || zh.includes("{{")) continue;
  messages[zh] = key;
  messages[en] = key;
}
const taskMessages: [RegExp, string][] = [
  [/^任务 #(\d+) 未找到$/, "schedule.runtime.taskNotFound"],
  [/^Task #(\d+) not found$/, "schedule.runtime.taskNotFound"],
  [/^任务 #(\d+) 不存在$/, "schedule.runtime.taskMissing"],
  [/^Task #(\d+) does not exist$/, "schedule.runtime.taskMissing"],
  [/^任务 #(\d+) 已结束，无法立即运行$/, "schedule.runtime.taskEnded"],
  [/^Task #(\d+) has ended and cannot run immediately$/, "schedule.runtime.taskEnded"],
  [/^任务 #(\d+) 状态读取失败$/, "schedule.runtime.taskStateFailed"],
  [/^Could not read the state of task #(\d+)$/, "schedule.runtime.taskStateFailed"],
  [/^任务 #(\d+) 由人工暂停，计划不能强制恢复$/, "schedule.runtime.taskManualPause"],
  [/^Task #(\d+) was paused manually and cannot be resumed by the schedule$/, "schedule.runtime.taskManualPause"],
];
export function scheduleRuntimeText(value: string, translate: TFunction): string {
  const key = messages[value];
  if (key) return translate(key);
  for (const [pattern, message] of taskMessages) {
    const match = pattern.exec(value);
    if (match) return translate(message, { id: match[1] });
  }
  // Scheduler summaries join several task failures with semicolons.
  if (value.includes("; ") && (value.startsWith("任务 #") || value.startsWith("Task #")))
    return value
      .split("; ")
      .map((part) => scheduleRuntimeText(part, translate))
      .join("; ");
  const taskError = /^(?:任务|Task) #(\d+)[:：]\s*([\s\S]*)$/.exec(value);
  if (taskError)
    return translate("schedule.runtime.taskError", {
      id: taskError[1],
      message: scheduleRuntimeText(taskError[2], translate),
    });
  return value;
}
