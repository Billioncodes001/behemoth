import type { TFunction } from "i18next";

import { errorMessages } from "./error-messages";

const messageToKey = new Map<string, string>();
for (const [key, [zh, en]] of Object.entries(errorMessages)) {
  if (!messageToKey.has(zh)) messageToKey.set(zh, key);
  if (!messageToKey.has(en)) messageToKey.set(en, key);
}

export function localizedError(error: unknown, translate: TFunction): string {
  if (typeof error === "string") {
    const mapped = messageToKey.get(error);
    return mapped ? translate(mapped, { defaultValue: error }) : translate(error, { defaultValue: error });
  }
  if (error instanceof Error) {
    const { code, params } = error as Error & { code?: string; params?: Record<string, unknown> };
    if (code) return translate(`error.${code}`, { ...params, defaultValue: error.message });
    const mapped = messageToKey.get(error.message.trim());
    if (mapped) return translate(mapped, { ...params, defaultValue: error.message });
    return error.message;
  }
  return translate("auth.backendUnavailable");
}
