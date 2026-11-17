"use client";

import { enUS } from "date-fns/locale/en-US";
import { zhCN } from "date-fns/locale/zh-CN";
import { useTranslation } from "react-i18next";

import { resolveLocale } from "./config";

export function useDateLocale() {
  const { i18n } = useTranslation();
  const locale = resolveLocale(i18n.resolvedLanguage);
  return {
    locale,
    dateLocale: locale === "zh-CN" ? zhCN : enUS,
    datePattern: locale === "zh-CN" ? "yyyy年M月d日" : "MMM d, yyyy",
  };
}
