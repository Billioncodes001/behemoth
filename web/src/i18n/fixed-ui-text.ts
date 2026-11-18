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

export function conversationTitleLabel(title: string | undefined, translate: (key: string) => string): string {
  const trimmed = title?.trim() ?? "";
  return !trimmed || trimmed === "新对话" || trimmed === "New conversation"
    ? translate("overview.newConversation")
    : trimmed;
}
