"use client";

import * as React from "react";
import { Camera, CheckCircle2, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";

export function BrowserConfigCard() {
  const [scraperURL, setScraperURL] = React.useState("");
  const [useLocal, setUseLocal] = React.useState(true);
  const [chromePath, setChromePath] = React.useState("");
  const [testURL, setTestURL] = React.useState("https://example.com");
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);

  React.useEffect(() => {
    api.browser
      .getConfig()
      .then((cfg) => {
        setScraperURL(cfg.scraper_url || "");
        setUseLocal(cfg.use_local_chrome ?? true);
        setChromePath(cfg.chrome_path || "");
      })
      .catch(() => {
        setScraperURL(localStorage.getItem("artex_browser_scraper_url") || "");
        const savedLocal = localStorage.getItem("artex_browser_use_local");
        setUseLocal(savedLocal ? savedLocal === "true" : true);
      });
  }, []);

  const persistConfig = async (nextScraperURL: string, nextUseLocal: boolean) => {
    setSaving(true);
    try {
      await api.browser.saveConfig({ scraper_url: nextScraperURL, use_local_chrome: nextUseLocal });
      localStorage.setItem("artex_browser_scraper_url", nextScraperURL);
      localStorage.setItem("artex_browser_use_local", String(nextUseLocal));
      toast.success("Browser configuration saved");
    } catch (e) {
      toast.error(String(e));
    } finally {
      setSaving(false);
    }
  };

  const save = () => persistConfig(scraperURL, useLocal);

  const toggleLocal = (checked: boolean) => {
    setUseLocal(checked);
    void persistConfig(scraperURL, checked);
  };

  const test = async () => {
    setTesting(true);
    try {
      const r = await api.browser.content(testURL || "https://example.com");
      toast.success(r.success ? `Browser test succeeded (${r.title || testURL})` : "Partial success");
    } catch (e) {
      toast.error("Test failed: " + e);
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Camera className="h-5 w-5" />
          <CardTitle>Browser Automation</CardTitle>
        </div>
        <CardDescription>Configure headless Chrome (chromedp) and external scraper integration</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="border rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <Label className="text-sm font-medium">Use Local Chrome</Label>
              <p className="text-xs text-muted-foreground">
                Headless Chrome via chromedp{chromePath ? ` (${chromePath})` : ""}
              </p>
            </div>
            <div className="flex items-center gap-2">
              {useLocal && (
                <span className="flex items-center gap-1 text-xs text-emerald-600">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Enabled
                </span>
              )}
              <Switch checked={useLocal} onCheckedChange={toggleLocal} />
            </div>
          </div>
        </div>

        <div className="border rounded-lg p-4 space-y-3">
          <Label className="text-sm font-medium">External Scraper URL (Optional)</Label>
          <p className="text-xs text-muted-foreground">Optional remote scraper service URL; leave blank to use local Chrome</p>
          <div className="flex gap-2">
            <Input
              type="url"
              placeholder="http://scraper-host:3000"
              value={scraperURL}
              onChange={(e) => setScraperURL(e.target.value)}
              className="font-mono text-sm"
            />
            <Button size="sm" onClick={save} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <span>Save</span>}
            </Button>
          </div>
        </div>

        <div className="border rounded-lg p-4 space-y-3">
          <Label className="text-sm font-medium">Test Browser Extraction</Label>
          <div className="flex gap-2">
            <Input
              type="url"
              value={testURL}
              onChange={(e) => setTestURL(e.target.value)}
              placeholder="https://example.com"
              className="font-mono text-sm"
            />
            <Button variant="outline" size="sm" onClick={test} disabled={testing}>
              {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <span>Test</span>}
            </Button>
          </div>
        </div>

        <details className="text-xs">
          <summary className="text-muted-foreground cursor-pointer">How Browser Automation Works</summary>
          <div className="mt-3 space-y-2 text-muted-foreground">
            <div><strong>Local Chrome:</strong> Uses chromedp to control headless Chrome for screenshots &amp; DOM content</div>
            <div><strong>External Scraper:</strong> Sends URL to a dedicated scraper microservice when configured</div>
            <div><strong>Fallback:</strong> Automatic HTTP content extraction when headless browser is unavailable</div>
          </div>
        </details>
      </CardContent>
    </Card>
  );
}