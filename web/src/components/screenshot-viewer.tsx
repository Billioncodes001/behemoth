"use client";

import * as React from "react";
import { Camera, Download, Maximize2, Loader2, Image as ImageIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api } from "@/lib/api";

interface ScreenshotViewerProps {
  className?: string;
}

export function ScreenshotViewer({ className }: ScreenshotViewerProps) {
  const { t } = useLiveTranslation();
  const [url, setUrl] = React.useState("");
  const [screenshot, setScreenshot] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [fullscreen, setFullscreen] = React.useState(false);

  const capture = async () => {
    if (!url.trim()) return;
    setLoading(true);
    try {
      const res = await api.browser.screenshot(url);
      if (res.screenshot) {
        // If it's a base64 string or URL
        setScreenshot(res.screenshot);
        toast.success("Screenshot captured!");
      } else if (res.success) {
        toast.success("Screenshot saved successfully");
      } else {
        toast.error(res.error || "Failed to capture screenshot");
      }
    } catch (err) {
      toast.error("Screenshot failed: " + err);
    } finally {
      setLoading(false);
    }
  };

  const download = () => {
    if (!screenshot) return;
    const a = document.createElement("a");
    a.href = screenshot.startsWith("data:") ? screenshot : screenshot;
    a.download = `screenshot-${Date.now()}.png`;
    a.click();
  };
  return (
    <Card className={className}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Camera className="h-5 w-5" />
            <CardTitle>Screenshot Viewer</CardTitle>
          </div>
          {screenshot && (
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={download}>
                <Download className="h-4 w-4 mr-1" /> Download
              </Button>
              <Button variant="outline" size="sm" onClick={() => setFullscreen(!fullscreen)}>
                <Maximize2 className="h-4 w-4" />
              </Button>
            </div>
          )}
        </div>
        <CardDescription>Capture and view website screenshots</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input
            type="url"
            placeholder="https://example.com"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === "Enter" && capture()}
          />
          <Button onClick={capture} disabled={loading || !url.trim()}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Camera className="h-4 w-4 mr-1" />}
            Capture
          </Button>
        </div>

        {screenshot ? (
          <div className={`border rounded-lg overflow-hidden bg-muted ${fullscreen ? "fixed inset-0 z-50 m-0 rounded-none" : ""}`}>
            {fullscreen && (
              <button
                className="absolute top-4 right-4 p-2 bg-background/80 rounded-full"
                onClick={() => setFullscreen(false)}
              >
                ✕
              </button>
            )}
            <img
              src={screenshot.startsWith("data:") ? screenshot : screenshot}
              alt="Screenshot"
              className={`w-full ${fullscreen ? "h-full object-contain" : ""}`}
            />
          </div>
        ) : (
          <div className="border border-dashed rounded-lg p-12 text-center text-muted-foreground">
            <ImageIcon className="h-12 w-12 mx-auto mb-3 opacity-50" />
            <p>Enter a URL and click Capture to take a screenshot</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}