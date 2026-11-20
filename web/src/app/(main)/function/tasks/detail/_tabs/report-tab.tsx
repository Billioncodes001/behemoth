"use client";
import * as React from "react";

import {
  ArchiveIcon,
  CheckIcon,
  CopyIcon,
  DownloadIcon,
  FileTextIcon,
  FolderArchiveIcon,
  Loader2Icon,
  RefreshCwIcon,
  SparklesIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import { copyText } from "@/lib/utils";

export function ReportTab({ taskId }: { taskId: string }) {
  const { ui } = useUITranslation();

  const [report, setReport] = React.useState<string>("");
  const [loading, setLoading] = React.useState(true);
  const [refreshing, setRefreshing] = React.useState(false);
  const [generatingDeepDive, setGeneratingDeepDive] = React.useState(false);
  const [exportingZip, setExportingZip] = React.useState(false);
  const [downloadingArtifacts, setDownloadingArtifacts] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  const loadReport = React.useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      else setRefreshing(true);
      try {
        const text = await api.report(taskId);
        setReport(text);
        if (silent) toast.success("Engagement report refreshed.");
      } catch (e) {
        if (!silent) setReport("");
        toast.error(`Failed to load report: ${(e as Error).message}`);
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [taskId],
  );

  React.useEffect(() => {
    void loadReport(false);
  }, [loadReport]);

  async function copy() {
    if (!report) return;
    const ok = await copyText(report);
    if (ok) {
      setCopied(true);
      toast.success(ui("screen.891604e7f54fb8"));
      setTimeout(() => setCopied(false), 1500);
    } else {
      toast.error(ui("screen.c883084221db6b"));
    }
  }

  function downloadMarkdown() {
    if (!report) {
      toast.warning("No report content available to download.");
      return;
    }
    const blob = new Blob([report], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `artex-task-${taskId}-full-report.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast.success(`Downloaded artex-task-${taskId}-full-report.md`);
  }

  async function generateAllFindingReports() {
    setGeneratingDeepDive(true);
    try {
      const findings = await api.findings(taskId);
      const actionable = findings.filter((f) => !f.inherited && (f.finding_id || f.id));
      if (actionable.length === 0) {
        toast.warning("No confirmed findings in this task yet. Run or complete testing first.");
        return;
      }
      let triggered = 0;
      for (const f of actionable) {
        const fid = f.finding_id || f.id;
        try {
          await api.generateFindingReport(fid);
          triggered++;
        } catch {
          // continue for remaining findings
        }
      }
      if (triggered > 0) {
        toast.success(
          `Triggered AI Deep-Dive Report generation for ${triggered} finding(s). Refreshing report in 4s...`,
        );
        window.setTimeout(() => void loadReport(true), 4000);
      } else {
        toast.error("Could not trigger AI report generation. Check that an LLM profile is active in /system/llm.");
      }
    } catch (e) {
      toast.error(`Failed to trigger deep-dive reports: ${(e as Error).message}`);
    } finally {
      setGeneratingDeepDive(false);
    }
  }

  async function exportEvidenceBundle() {
    setExportingZip(true);
    try {
      await api.exportFindings({
        format: "md-zip",
        scope: "filtered",
        filters: { task: taskId },
      });
      toast.success("Downloaded findings evidence & HTTP packet bundle (.zip).");
    } catch (e) {
      toast.error(`Failed to export evidence bundle: ${(e as Error).message}`);
    } finally {
      setExportingZip(false);
    }
  }

  async function downloadWorkspaceArtifacts() {
    setDownloadingArtifacts(true);
    try {
      await api.taskFilesArchiveAll(taskId);
      toast.success("Downloaded task workspace artifacts (.zip).");
    } catch (e) {
      toast.error(`No workspace artifacts available or download failed: ${(e as Error).message}`);
    } finally {
      setDownloadingArtifacts(false);
    }
  }

  let content: React.ReactNode;
  if (loading) {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <Loader2Icon className="size-8 animate-spin opacity-40" />
        {ui("screen.4927a53bcc886a")}
      </div>
    );
  } else if (report) {
    content = (
      <div className="max-h-[75vh] overflow-auto rounded-md border bg-muted/20 p-6">
        <Markdown text={report} />
      </div>
    );
  } else {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        {ui("screen.38148ac20505f9")}
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <CardTitle className="flex items-center gap-2 text-sm">
            <FileTextIcon className="size-4" /> End-to-End Engagement Report & Artifacts
          </CardTitle>
          <CardDescription className="mt-1 text-xs">
            Full chronological testing timeline, executed tool traces, confirmed findings, HTTP traffic evidence,
            intelligence, and workspace artifacts.
          </CardDescription>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => void loadReport(true)} disabled={refreshing || loading}>
            <RefreshCwIcon className={refreshing ? "animate-spin" : ""} /> Refresh
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void generateAllFindingReports()}
            disabled={generatingDeepDive}
            title="Run the Reporter Agent to generate or refresh detailed technical write-ups for all findings in this task"
          >
            {generatingDeepDive ? <Loader2Icon className="animate-spin" /> : <SparklesIcon />}
            AI Deep-Dive Writeups
          </Button>
          <Button
            size="sm"
            variant="default"
            onClick={() => api.openDeliverableReport({ taskId, autoPrint: true })}
            title="Open client-ready Executive + Technical HTML / Print-to-PDF Deliverable"
          >
            <FileTextIcon /> Export PDF / HTML
          </Button>
          {report && (
            <>
              <Button size="sm" variant="outline" onClick={downloadMarkdown}>
                <DownloadIcon /> Download .md
              </Button>
              <Button size="sm" variant="outline" onClick={() => void exportEvidenceBundle()} disabled={exportingZip}>
                {exportingZip ? <Loader2Icon className="animate-spin" /> : <ArchiveIcon />}
                Evidence Bundle (.zip)
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => void downloadWorkspaceArtifacts()}
                disabled={downloadingArtifacts}
              >
                {downloadingArtifacts ? <Loader2Icon className="animate-spin" /> : <FolderArchiveIcon />}
                Workspace Artifacts (.zip)
              </Button>
              <Button size="sm" variant="outline" onClick={() => void copy()}>
                {copied ? <CheckIcon /> : <CopyIcon />} {ui("screen.63d90d977348ab")}
              </Button>
            </>
          )}
        </div>
      </CardHeader>
      <CardContent>{content}</CardContent>
    </Card>
  );
}
