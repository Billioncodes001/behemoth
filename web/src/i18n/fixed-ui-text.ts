import catalog from "./screen-catalog.json";
import type { UITranslate } from "./use-ui-translation";

// Translate only product-authored messages at explicit UI boundaries. Never run
// this over reports, prompts, request bodies, user names or arbitrary AI output.
const fixedKeys = new Map<string, string>();
for (const [key, pair] of Object.entries(catalog)) {
  if (!fixedKeys.has(pair[0])) fixedKeys.set(pair[0], key);
  if (!fixedKeys.has(pair[1])) fixedKeys.set(pair[1], key);
}

export function translateFixedUIText(text: string, ui: UITranslate): string {
  const key = fixedKeys.get(text);
  if (key) return ui(key);
  const limit = /^最多 (\d+) 个字符$/.exec(text) ?? /^Use at most (\d+) characters$/.exec(text);
  if (limit) return ui("screen.scopeCharacterLimit", { count: Number(limit[1]) });
  return text;
}

export function repeaterGroupLabel(group: { id: string; name: string }, ui: UITranslate): string {
  if (group.id === "default" && (group.name === "默认" || group.name === "Default")) {
    return translateFixedUIText("默认", ui);
  }
  const autoGroup = /^(?:分组|Group) (\d+)$/.exec(group.name);
  if (autoGroup) return ui("screen.repeaterAutoGroup", { count: Number(autoGroup[1]) });
  return group.name;
}

// Conversation titles are stored once (in the DB) with whatever label the
// server had when the conversation was created — including older builds that
// wrote Chinese trigger/agent prefixes ("工具触发 · …", "凭据整理 · …"). Rewrite
// those known product-authored prefixes at display time so the English UI never
// shows them. User-authored titles and AI body text are left untouched.
const titleAgentPrefixes: Array<[string, string]> = [
  ["凭据整理", "builtinAgent.credential_processor.name"],
  ["报告撰写", "builtinAgent.reporter.name"],
  ["资产梳理", "builtinAgent.asset_mapper.name"],
  ["渗透测试", "builtinAgent.pentest.name"],
  ["补丁监控", "builtinAgent.patch_watch.name"],
  ["漏洞复测", "builtinAgent.retester.name"],
  ["目标拆解", "builtinAgent.goals.name"],
  ["规划", "builtinAgent.planner.name"],
  ["主", "builtinAgent.mainagent.name"],
  ["执行", "builtinAgent.worker.name"],
];

// Longest first so "任务创建触发" wins over a hypothetical "任务创建" style overlap.
const titleTriggerPrefixes: Array<[RegExp, string]> = [
  [/^任务创建触发 · /, "Task created trigger · "],
  [/^工具触发 · /, "Tool trigger · "],
  [/^定时触发 · /, "Scheduled trigger · "],
  [/^目标触发 · /, "Goal trigger · "],
  [/^超时触发 · /, "Timeout trigger · "],
  [/^finding 触发 · /, "Finding trigger · "],
];

export function conversationTitleLabel(title: string | undefined, translate: (key: string) => string): string {
  const trimmed = title?.trim() ?? "";
  if (!trimmed || trimmed === "新对话" || trimmed === "New conversation") {
    return translate("overview.newConversation");
  }
  for (const [zh, key] of titleAgentPrefixes) {
    if (trimmed.startsWith(`${zh} · `)) {
      return `${translate(key)} · ${trimmed.slice(zh.length + 3)}`;
    }
  }
  for (const [re, en] of titleTriggerPrefixes) {
    if (re.test(trimmed)) return trimmed.replace(re, en);
  }
  return trimmed;
}
