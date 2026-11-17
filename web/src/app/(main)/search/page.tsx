"use client";

import * as React from "react";
import Link from "next/link";
import { Search, ExternalLink, Globe, Loader2, Settings2, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api } from "@/lib/api";
import type { SearchResultItem, SearchResponse, SearchMode, SearchEnginesStatus, SearchEngineType } from "@/lib/types";

const MODES: { value: SearchMode }[] = [
  { value: "general" },
  { value: "exploit" },
  { value: "technical" },
  { value: "osint" },
];

const ENGINE_LABELS: Record<SearchEngineType, string> = {
  duckduckgo: "DuckDuckGo",
  sploitus: "Sploitus (Exploit/PoC)",
  google: "Google CSE",
  tavily: "Tavily AI",
  searxng: "SearXNG",
};

export default function SearchPage() {
  const { t } = useLiveTranslation();
  const [query, setQuery] = React.useState("");
  const [siteFilter, setSiteFilter] = React.useState("");
  const [mode, setMode] = React.useState<SearchMode>("general");
  const [results, setResults] = React.useState<SearchResponse | null>(null);
  const [enginesStatus, setEnginesStatus] = React.useState<SearchEnginesStatus | null>(null);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    api.search
      .engines()
      .then(setEnginesStatus)
      .catch(() => {});
  }, []);

  const handleSearch = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!query.trim()) {
      toast.warning("Please enter a search query.");
      return;
    }
    setLoading(true);
    try {
      const res = await api.search.search({
        query: query.trim(),
        mode,
        max_results: 10,
        site_filter: siteFilter.trim() || undefined,
      });
      setResults(res);
      if (res.warnings && res.warnings.length > 0) {
        toast.warning(`Some search engines reported warnings: ${res.warnings.join("; ")}`);
      }
      if (!res.results || res.results.length === 0) {
        toast.info("No results matched your query. Try broadening your search terms or switching search mode.");
      }
    } catch (err) {
      toast.error(t("search.failed") + ": " + (err instanceof Error ? err.message : String(err)));
    } finally {
      setLoading(false);
    }
  };
  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Search className="h-8 w-8" />
            {t("search.title")}
          </h1>
          <p className="text-muted-foreground mt-2">{t("search.subtitle")}</p>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link href="/system/settings">
            <Settings2 className="mr-1.5 h-4 w-4" />
            Configure Search Engines
          </Link>
        </Button>
      </div>

      {enginesStatus && (
        <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-muted-foreground font-medium">Engines:</span>
          {(Object.keys(ENGINE_LABELS) as SearchEngineType[]).map((eng) => {
            const active = enginesStatus.engine_status?.[eng] ?? false;
            return (
              <Badge
                key={eng}
                variant={active ? "secondary" : "outline"}
                className={active ? "gap-1 text-emerald-600 dark:text-emerald-400" : "gap-1 text-muted-foreground opacity-70"}
              >
                {active ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                {ENGINE_LABELS[eng]}
              </Badge>
            );
          })}
        </div>
      )}

      <Card className="mb-6">
        <CardContent className="pt-6">
          <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
            <Input
              placeholder={t("search.queryPlaceholder")}
              value={query}
              onChange={e => setQuery(e.target.value)}
              className="flex-1 text-base"
            />
            <Input
              placeholder="Optional site filter (e.g. github.com)"
              value={siteFilter}
              onChange={e => setSiteFilter(e.target.value)}
              className="sm:w-64 text-sm font-mono"
            />
            <Button type="submit" disabled={loading}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              {t("search.button")}
            </Button>
          </form>
          <div className="flex flex-wrap items-center justify-between gap-2 mt-4">
            <div className="flex flex-wrap gap-2">
              {MODES.map(m => (
                <Badge
                  key={m.value}
                  variant={mode === m.value ? "default" : "outline"}
                  className="cursor-pointer"
                  onClick={() => setMode(m.value)}
                >
                  {t(`search.mode.${m.value}`)}
                </Badge>
              ))}
            </div>
            {results?.engines_used && results.engines_used.length > 0 && (
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <span>Served by:</span>
                {results.engines_used.map((eng) => (
                  <Badge key={eng} variant="secondary" className="text-[11px] font-mono">
                    {eng}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {results && (
        <div className="space-y-4">
          {results.warnings && results.warnings.length > 0 && (
            <div className="flex items-center gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-600 dark:text-amber-400">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>Engine warnings: {results.warnings.join(" | ")}</span>
            </div>
          )}
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">
              {t("search.results", { count: results.results?.length || 0 })}
            </h2>
            <span className="text-sm text-muted-foreground">
              {results.query_time_ms}ms
            </span>
          </div>
          {results.results?.length === 0 ? (
            <Card><CardContent className="py-12 text-center text-muted-foreground">{t("search.noResults")}</CardContent></Card>
          ) : (
            results.results?.map((item, i) => <ResultCard key={i} item={item} index={i} t={t} />)
          )}
        </div>
      )}
    </div>
  );
}

function ResultCard({ item, index, t }: { item: SearchResultItem; index: number; t: (key: string, opts?: Record<string, unknown>) => string }) {
  let hostname = "";
  try { hostname = new URL(item.url).hostname; } catch {}
  
  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <span className="text-muted-foreground text-sm font-mono">#{index + 1}</span>
          <div className="flex-1 min-w-0">
            <a href={item.url} target="_blank" rel="noopener noreferrer"
               className="text-blue-600 hover:underline font-medium line-clamp-1">
              {item.title || t("search.untitled")}
              <ExternalLink className="inline h-3 w-3 ml-1" />
            </a>
            <p className="text-sm text-muted-foreground mt-1 line-clamp-2">
              {item.snippet || t("search.noDescription")}
            </p>
            <div className="flex items-center gap-2 mt-2">
              <Globe className="h-3 w-3 text-muted-foreground" />
              <span className="text-xs text-muted-foreground">{hostname}</span>
              {item.engine && <Badge variant="secondary" className="text-xs">{item.engine}</Badge>}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}