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

const ENGINES = [
  { type: "google" as SearchEngineType, label: "Google CSE", desc: "Google Programmable Search", key: true, keyLabel: "API Key + CSE ID", env: "SEARCH_GOOGLE_API_KEY" },
  { type: "duckduckgo" as SearchEngineType, label: "DuckDuckGo", desc: "Free HTML search (no key)", key: false, keyLabel: "", env: "" },
  { type: "tavily" as SearchEngineType, label: "Tavily AI", desc: "AI-powered search", key: true, keyLabel: "API Key", env: "SEARCH_TAVILY_API_KEY" },
  { type: "searxng" as SearchEngineType, label: "SearXNG", desc: "Self-hosted meta-search", key: true, keyLabel: "Instance URL", env: "SEARCH_SEARXNG_URL" },
  { type: "sploitus" as SearchEngineType, label: "Sploitus", desc: "Exploit database", key: false, keyLabel: "", env: "" },
];

interface Props {
  enginesStatus: SearchEnginesStatus | null;
  onRefresh: () => void;
}

export function SearchConfigCard({ enginesStatus, onRefresh }: Props) {
  const { t } = useLiveTranslation();
  const [keys, setKeys] = React.useState<Record<string, string>>({});
  const [saving, setSaving] = React.useState<string | null>(null);
  const [testing, setTesting] = React.useState<string | null>(null);

  React.useEffect(() => {
    const k: Record<string, string> = {};
    ENGINES.forEach(e => {
      if (e.key) {
        const s = localStorage.getItem("artex_search_" + e.type);
        if (s) k[e.type] = s;
      }
    });
    setKeys(k);
  }, []);

  const saveKey = async (type: string) => {
    const val = (keys[type] || "").trim();
    if (!val) {
      toast.warning(`Please enter a value for ${type} before saving.`);
      return;
    }
    if (type === "google" && !val.includes("|") && !val.includes(":")) {
      toast.warning("For Google CSE, please enter both API Key and CSE ID separated by '|' (e.g. AIzaSy...|cx_id).");
      return;
    }
    setSaving(type);
    try {
      await api.search.saveConfig({ engine: type, api_key: val });
      localStorage.setItem("artex_search_" + type, val);
      toast.success(`${type.toUpperCase()} search configuration saved`);
      onRefresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(null);
    }
  };

  const testEngine = async (type: string) => {
    setTesting(type);
    try {
      const res = await api.search.search({ query: "cve-2024", mode: type === "sploitus" ? "exploit" : "general", engine: type, max_results: 3 });
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

  const avail = (type: SearchEngineType) => enginesStatus?.engine_status[type] ?? false;

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
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
              {ENGINES.map(e => {
                const active = avail(e.type);
                return (
                  <div key={e.type} className={
                    "flex items-center gap-1.5 text-xs p-1.5 rounded " +
                    (active ? "bg-green-100 text-green-800 dark:bg-green-900" : "bg-gray-100 text-gray-600")
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
                    type={e.type === "searxng" ? "url" : "password"}
                    placeholder={e.keyLabel}
                    value={keys[e.type] || ""}
                    onChange={ev => setKeys(p => ({ ...p, [e.type]: ev.target.value }))}
                    className="font-mono text-sm"
                  />
                  <Button size="sm" onClick={() => saveKey(e.type)} disabled={saving === e.type}>
                    {saving === e.type ? <Loader2 className="h-4 w-4 animate-spin" /> : "Save"}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => testEngine(e.type)} disabled={testing === e.type}>
                    {testing === e.type ? <Loader2 className="h-4 w-4 animate-spin" /> : "Test"}
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">Env: {e.env}</p>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-xs text-green-600 bg-green-50 dark:bg-green-950 p-2 rounded">
                <CheckCircle className="h-4 w-4" /> No API key required
              </div>
            )}
          </div>
        ))}
        <details className="text-xs">
          <summary className="text-muted-foreground cursor-pointer">Search Modes &amp; Fallback Chains</summary>
          <div className="mt-3 space-y-2 text-muted-foreground">
            <div><strong>General:</strong> Tavily -&gt; Google -&gt; DuckDuckGo -&gt; SearXNG</div>
            <div><strong>Exploit:</strong> Sploitus -&gt; Google -&gt; DuckDuckGo -&gt; Tavily</div>
            <div><strong>Technical:</strong> Tavily -&gt; Google -&gt; SearXNG -&gt; DuckDuckGo</div>
            <div><strong>OSINT:</strong> DuckDuckGo -&gt; Google -&gt; SearXNG -&gt; Tavily</div>
          </div>
        </details>
      </CardContent>
    </Card>
  );
}