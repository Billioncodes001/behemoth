export const DEFAULT_LOCALE = "en";
export const SUPPORTED_LOCALES = [DEFAULT_LOCALE, "zh-CN", "ja"] as const;
export type AppLocale = (typeof SUPPORTED_LOCALES)[number];
export const LOCALE_STORAGE_KEY = "behemoth_locale";

export function resolveLocale(value: string | null | undefined): AppLocale {
  if (/^ja(?:-JP|$)/i.test(value ?? "")) return "ja";
  return /^zh(?:-CN|$)/i.test(value ?? "") ? "zh-CN" : DEFAULT_LOCALE;
}
