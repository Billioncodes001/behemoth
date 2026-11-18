import { translateFixedUIText } from "@/i18n/fixed-ui-text";
import type { UITranslate } from "@/i18n/use-ui-translation";
import type { NewAssetType } from "@/lib/types";

const ASSET_TYPE_LABELS: Record<NewAssetType, string> = {
  app: "Application",
  endpoint: "Endpoint",
  ip: "IP",
  root_domain: "Root domain",
  service: "Service",
  subdomain: "Subdomain",
};

const TASK_ASSET_SOURCE_LABELS: Record<string, string> = {
  agent: "Agent discovery",
  anchor: "Board anchor",
  api: "Asset API",
  company: "Company link",
  legacy: "Historical link",
  manual: "Added manually",
  system: "System link",
  task: "Task initialization",
};

export function taskAssetTypeLabel(type: NewAssetType, ui?: UITranslate): string {
  const label = ASSET_TYPE_LABELS[type];
  return ui ? translateFixedUIText(label, ui) : label;
}

export function taskAssetSourceLabel(source: string, ui?: UITranslate): string {
  const label = TASK_ASSET_SOURCE_LABELS[source] ?? source;
  return ui ? translateFixedUIText(label, ui) : label;
}
