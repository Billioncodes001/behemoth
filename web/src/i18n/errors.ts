import type { TFunction } from "i18next";

import { errorMessages } from "./error-messages";

const zhMessageToKey = new Map<string, string>(
  Object.entries(errorMessages).map(([key, [zh]]) => [zh, key]),
);

export function localizedError(error: unknown, translate: TFunction): string {
  if (typeof error === "string") {
    const mapped = zhMessageToKey.get(error);
    return mapped ? translate(mapped, { defaultValue: error }) : translate(error, { defaultValue: error });
  }
  if (error instanceof Error) {
    const { code, params } = error as Error & { code?: string; params?: Record<string, unknown> };
    if (code) return translate(`error.${code}`, { ...params, defaultValue: error.message });
    const mapped = zhMessageToKey.get(error.message.trim());
    if (mapped) return translate(mapped, { ...params, defaultValue: error.message });
    return error.message;
  }
  return translate("auth.backendUnavailable");
}
