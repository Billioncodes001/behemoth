"use client";

import * as React from "react";
import { Globe, Key, Loader2, RefreshCw, CheckCircle, XCircle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api } from "@/lib/api";
import type { SearchEngineType, SearchEnginesStatus } from "@/lib/types";

const ENGINES: {
  type: SearchEngineType;
  label: string;
  desc: string;
  key: boolean;
  keyLabel: string;
  placeholder?: string;
  env: string;
  builtInNote?: string;
}[] = [
  {
    type: "firecrawl",
    label: "Firecrawl",
    desc: "Search + crawl API (cloud or self-hosted)",
    key: true,
    keyLabel: "API Key | Base URL",
    placeholder: "fc-... (or http://127.0.0.1:3002)",
    env: "SEARCH_FIRECRAWL_API_KEY",
  },
  {
    type: "duckduckgo",
    label: "DuckDuckGo",
    desc: "Free HTML search (no key)",
    key: false,
    keyLabel: "",
    env: "",
    builtInNote: "No API key required",
  },
  {
    type: "tavily",
    label: "Tavily AI",
    desc: "AI-powered search",
    key: true,
    keyLabel: "API Key",
    placeholder: "tvly-...",
    env: "SEARCH_TAVILY_API_KEY",
  },
  {
    type: "brave",
    label: "Brave",
    desc: "Brave Search API",
    key: true,
    keyLabel: "API Key",
    placeholder: "API Key",
    env: "SEARCH_BRAVE_API_KEY",
  },
  {
    type: "searxng",
    label: "SearXNG",
    desc: "Self-hosted meta-search (runs locally on this server)",
    key: false,
    keyLabel: "",
    env: "",
    builtInNote: "Self-hosted on server — no API key or URL required",
  },
  {
    type: "sploitus",
    label: "Sploitus",
    desc: "Exploit database",
    key: false,
    keyLabel: "",
    env: "",
    builtInNote: "No API key required",
  },
];

interface Props {
  enginesStatus: SearchEnginesStatus | null;
  onRefresh: () => void;
}

export function SearchConfigCard({ enginesStatus, onRefresh }: Props) {
  const { t } = useLiveTranslation();
  const [keys, setKeys] = React.useState<Record<string, string>>({});
  const [savedKeys, setSavedKeys] = React.useState<Record<string, string>>({});
  const [saving, setSaving] = React.useState<string | null>(null);
  const [testing, setTesting] = React.useState<string | null>(null);

  React.useEffect(() => {
    const k: Record<string, string> = {};
    ENGINES.forEach(e => {
      if (e.key) {
        const s = localStorage.getItem("behemoth_search_" + e.type);
        if (s) k[e.type] = s;
      }
    });
    setKeys(k);
    setSavedKeys(k);
  }, []);

  React.useEffect(() => {
    if (!enginesStatus?.searxng_provisioning && enginesStatus?.engine_status?.searxng) {
      return;
    }
    if (!enginesStatus?.searxng_provisioning) {
      return;
    }
    const timer = window.setInterval(() => {
      onRefresh();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [enginesStatus?.searxng_provisioning, enginesStatus?.engine_status?.searxng, onRefresh]);

  const validateEngineValue = (type: string, val: string): string | null => {
    if (!val) {
      return `Please enter a value for ${type} before saving.`;
    }
    if (/\s/.test(val)) {
      return `Invalid ${type} value: remove any spaces or line breaks.`;
    }
    return null;
  };

  const saveKey = async (type: string): Promise<boolean> => {
    const val = (keys[type] || "").trim();
    const errMsg = validateEngineValue(type, val);
    if (errMsg) {
      toast.warning(errMsg);
      return false;
    }
    setSaving(type);
    try {
      await api.search.saveConfig({ engine: type, api_key: val });
      localStorage.setItem("behemoth_search_" + type, val);
      setSavedKeys(p => ({ ...p, [type]: val }));
      toast.success(`${type.toUpperCase()} search configuration saved`);
      onRefresh();
      return true;
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
      return false;
    } finally {
      setSaving(null);
    }
  };

  const testEngine = async (type: SearchEngineType) => {
    const meta = ENGINES.find(e => e.type === type);
    const typed = (keys[type] || "").trim();
    // If the user pasted a new or unsaved API key and clicked Test directly, persist it first.
    if (meta?.key && typed && (typed !== (savedKeys[type] || "") || !avail(type))) {
      const ok = await saveKey(type);
      if (!ok) return;
    }
    setTesting(type);
    try {
      const res = await api.search.search({
        query: "cve-2024",
        mode: type === "sploitus" ? "exploit" : "general",
        engine: type,
        max_results: 3,
      });
      onRefresh();
      if (res.results && res.results.length > 0) {
        toast.success(`${type.toUpperCase()} test succeeded (${res.results.length} results in ${res.query_time_ms ?? 0}ms)`);
      } else {
        toast.warning(`${type.toUpperCase()} responded with 0 results.`);
      }
    } catch (e) {
      toast.error(`${type.toUpperCase()} test failed: ` + (e instanceof Error ? e.message : String(e)));
    } finally {
      setTesting(null);
    }
  };

  const avail = (type: SearchEngineType) => enginesStatus?.engine_status?.[type] ?? false;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            <CardTitle>Multi-Engine Web Search</CardTitle>
          </div>
          <Button variant="outline" size="sm" onClick={onRefresh}>
            <RefreshCw className="h-4 w-4 mr-1" />Refresh
          </Button>
        </div>
        <CardDescription>Configure Pentagi-inspired multi-engine web search</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {enginesStatus && (
          <div className="rounded-md bg-muted p-3">
            <div className="text-sm font-medium mb-2">Engine Status</div>
            <div className="grid grid-cols-2 sm:grid-cols-6 gap-2">
              {ENGINES.map(e => {
                const active = avail(e.type);
                return (
                  <div key={e.type} className={
                    "flex items-center gap-1.5 text-xs font-medium p-2 rounded-md border " +
                    (active
                      ? "bg-emerald-500/15 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/20 dark:text-emerald-300"
                      : "bg-muted text-muted-foreground border-border")
                  }>
                    {active ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                    {e.label}
                  </div>
                );
              })}
            </div>
            <div className="text-xs text-muted-foreground mt-2">
              Available: {enginesStatus.available_engines} / {enginesStatus.total_engines_registered}
            </div>
          </div>
        )}
        {ENGINES.map(e => (
          <div key={e.type} className="border rounded-lg p-4 space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <Label className="text-sm font-medium">{e.label}</Label>
                <p className="text-xs text-muted-foreground">{e.desc}</p>
              </div>
              {avail(e.type) && (
                <span className="text-xs text-green-600 flex items-center gap-1">
                  <CheckCircle className="h-3 w-3" /> Active
                </span>
              )}
            </div>
            {e.key ? (
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <Key className="h-3 w-3" />{e.keyLabel}
                </div>
                <div className="flex gap-2">
                  <Input
                    type="password"
                    placeholder={
                      avail(e.type) || enginesStatus?.configured_keys?.[e.type]
                        ? "Configured on server — enter new key to replace"
                        : e.placeholder || e.keyLabel
                    }
                    value={keys[e.type] || ""}
                    onChange={ev => setKeys(p => ({ ...p, [e.type]: ev.target.value }))}
                    className="font-mono text-sm"
                  />
                  <Button size="sm" onClick={() => void saveKey(e.type)} disabled={saving === e.type}>
                    {saving === e.type ? <Loader2 className="h-4 w-4 animate-spin" /> : "Save"}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => void testEngine(e.type)} disabled={testing === e.type || saving === e.type}>
                    {testing === e.type ? <Loader2 className="h-4 w-4 animate-spin" /> : "Test"}
                  </Button>
                </div>
                {e.type === "firecrawl" && (
                  <p className="text-xs text-muted-foreground">
                    Cloud: paste your fc-… key. Self-hosted: enter the base URL (e.g. http://127.0.0.1:3002) — no key needed.
                  </p>
                )}
                <p className="text-xs text-muted-foreground">Env: {e.env}</p>
              </div>
            ) : (
              <div className="flex items-center justify-between gap-2 text-xs text-green-600 bg-green-50 dark:bg-green-950 p-2 rounded">
                <div className="flex items-center gap-2">
                  {e.type === "searxng" && !avail("searxng") && enginesStatus?.searxng_provisioning ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin text-amber-500" />
                      <span className="text-amber-600 dark:text-amber-400">Starting local SearXNG service on server...</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle className="h-4 w-4" />
                      <span>{e.builtInNote || "No API key required"}</span>
                    </>
                  )}
                </div>
                <Button variant="outline" size="sm" onClick={() => void testEngine(e.type)} disabled={testing === e.type}>
                  {testing === e.type ? <Loader2 className="h-4 w-4 animate-spin" /> : "Test"}
                </Button>
              </div>
            )}
          </div>
        ))}
        <details className="text-xs">
          <summary className="text-muted-foreground cursor-pointer">Search Modes &amp; Fallback Chains</summary>
          <div className="mt-3 space-y-2 text-muted-foreground">
            <div><strong>General:</strong> Tavily -&gt; SearXNG (self-hosted) -&gt; Firecrawl -&gt; DuckDuckGo -&gt; Brave</div>
            <div><strong>Exploit:</strong> Sploitus -&gt; SearXNG -&gt; Firecrawl -&gt; Brave -&gt; DuckDuckGo -&gt; Tavily</div>
            <div><strong>Technical:</strong> Tavily -&gt; SearXNG -&gt; Firecrawl -&gt; Brave -&gt; DuckDuckGo</div>
            <div><strong>OSINT:</strong> SearXNG -&gt; Firecrawl -&gt; Brave -&gt; DuckDuckGo -&gt; Tavily</div>
          </div>
        </details>
      </CardContent>
    </Card>
  );
}