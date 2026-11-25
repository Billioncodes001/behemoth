// Locale-aware, compact timestamps for list/metadata rows. Server timestamps
// arrive as RFC3339 with nanoseconds ("2026-11-25 12:33:14.379269+00"), which is
// unreadable inline; keep the raw value in a `title` attribute for precision
// and render a short local form instead.

const FALLBACK = "—";

// Go's RFC3339Nano is not always ECMAScript-parseable: it uses a space separator
// in some code paths and hour-only offsets ("+00"). Normalise both, then parse.
function parseTimestamp(value: string): Date | null {
  const raw = value.trim();
  if (!raw) return null;
  const iso = raw.replace(" ", "T").replace(/([+-]\d{2})$/, "$1:00");
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function formatDateTime(value: string | null | undefined, locale: string): string {
  if (!value) return FALLBACK;
  const parsed = parseTimestamp(value);
  if (!parsed) return value.trim() || FALLBACK;
  try {
    return new Intl.DateTimeFormat(locale || undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
  } catch {
    return parsed.toISOString().slice(0, 16).replace("T", " ");
  }
}

// Relative age for "how fresh is this" scanning; falls back to the absolute form
// once older than a week so old rows stay unambiguous.
export function formatWhen(value: string | null | undefined, locale: string, now = new Date()): string {
  if (!value) return FALLBACK;
  const parsed = parseTimestamp(value);
  if (!parsed) return value.trim() || FALLBACK;
  const diffMs = now.getTime() - parsed.getTime();
  if (diffMs > 7 * 24 * 60 * 60 * 1000) return formatDateTime(value, locale);
  // Server clocks can run slightly ahead; treat small future skew as "now".
  const minutes = Math.floor(Math.max(diffMs, 0) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
