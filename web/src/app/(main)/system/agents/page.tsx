"use client";
import * as React from "react";

import { Bot, PlusIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { AgentEditor } from "@/components/agent-editor";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { agentDisplayDescription, agentDisplayName } from "@/i18n/agent-display";
import { useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import type { Agent } from "@/lib/types";

// AgentGridCard is one clickable tile opening the agent's editor drawer. Custom
// (non-builtin) agents get a delete button.
function AgentGridCard({ agent, onOpen, onDeleted }: { agent: Agent; onOpen: () => void; onDeleted: () => void }) {
  const { ui } = useUITranslation();

  async function del() {
    try {
      await api.deleteAgent(agent.key);
      toast.success(ui("screen.097a613ffd4834", { v0: agent.name }));
      onDeleted();
    } catch (e) {
      toast.error(ui("screen.0580fcee37e020") + (e as Error).message);
    }
  }
  return (
    <div className="hover:border-primary/50 group relative flex flex-col gap-2 rounded-lg border p-4 transition-colors">
      <button type="button" onClick={onOpen} className="flex flex-col gap-2 text-left">
        <div className="flex flex-wrap items-center gap-2">
          <Bot className="text-muted-foreground size-4" />
          <span className="text-sm font-medium">{agentDisplayName(agent, ui)}</span>
          <span className="text-muted-foreground font-mono text-xs">{agent.key}</span>
          {agent.builtin ? (
            <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
              {ui("screen.95e35aabd9a9ff")}
            </Badge>
          ) : (
            <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
              {ui("screen.4eafa9e925b30b")}
            </Badge>
          )}
          {!agent.enabled && (
            <Badge variant="outline" className="text-destructive px-1.5 py-0 text-[10px]">
              {ui("screen.a8c3698b5b8c48")}
            </Badge>
          )}
        </div>
        <p className="text-muted-foreground line-clamp-2 min-h-8 text-xs">
          {agentDisplayDescription(agent, ui) || ui("screen.0042f188770453")}
        </p>
        <div className="text-muted-foreground flex flex-wrap gap-1.5 text-[10px]">
          <span className="rounded border px-1.5 py-0.5">MCP {agent.mcp_count ?? 0}</span>
          <span className="rounded border px-1.5 py-0.5">Skill {agent.skill_count ?? 0}</span>
          <span className="rounded border px-1.5 py-0.5">
            {ui("screen.5ca6730d441522")}
            {agent.tool_count ?? 0}
          </span>
        </div>
      </button>
      {!agent.builtin && (
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button
              variant="ghost"
              size="icon-sm"
              className="text-muted-foreground hover:text-destructive absolute top-2 right-2 opacity-0 transition-opacity group-hover:opacity-100"
            >
              <Trash2Icon className="size-3.5" />
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>
                {ui("screen.c9e5773d0471ff")}
                {agentDisplayName(agent, ui)}
                {ui("punctuation.a33706e414")}
              </AlertDialogTitle>
              <AlertDialogDescription>{ui("screen.091f836bcad039")}</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>{ui("screen.2cd0f3be8738a8")}</AlertDialogCancel>
              <AlertDialogAction onClick={del}>{ui("screen.2f9daa828907b9")}</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      )}
    </div>
  );
}

type AgentPreset = {
  label: string;
  key: string;
  name: string;
  description: string;
  prompt: string;
};

const AGENT_PRESETS: AgentPreset[] = [
  {
    label: "Web App Pentester",
    key: "web_pentester",
    name: "Web Application Pentester",
    description: "End-to-end OWASP Top 10 & WSTG v4.2 web penetration testing specialist.",
    prompt:
      "You are an expert Web Application Penetration Tester operating under explicit authorization.\n\n" +
      "## Methodology (OWASP WSTG v4.2 / Top 10)\n" +
      "1. **Recon & Fingerprinting**: Identify frameworks, headers, hidden routes, and JS bundle endpoints.\n" +
      "2. **Auth & Access Control**: Test IDOR/BOLA, vertical privilege escalation, session handling, and JWT weaknesses.\n" +
      "3. **Injection & Input Validation**: Probe SQLi, NoSQLi, SSTI, command injection, XXE, SSRF, and XSS.\n" +
      "4. **Adversarial Verification**: Confirm every finding with a non-destructive proof-of-concept and raw HTTP evidence.\n",
  },
  {
    label: "API Security Auditor",
    key: "api_auditor",
    name: "API Security Specialist",
    description: "REST, GraphQL, and gRPC security specialist focused on OWASP API Security Top 10 (BOLA/BFLA/Mass Assignment).",
    prompt:
      "You are an API Security Specialist assessing REST and GraphQL endpoints per OWASP API Top 10 2023.\n\n" +
      "## Core Focus\n" +
      "- Discover OpenAPI/Swagger schemas, GraphQL introspection, and undocumented v1/v2 routes.\n" +
      "- Test BOLA (ID swapping), BFLA (admin endpoints with low-priv tokens), and Mass Assignment.\n" +
      "- Verify rate limits, batching abuse, SSRF in webhooks, and broken token validation.\n",
  },
  {
    label: "Recon & OSINT",
    key: "recon_specialist",
    name: "Recon & Attack Surface Analyst",
    description: "External attack surface discovery, subdomain enumeration, port scanning, and CVE fingerprinting.",
    prompt:
      "You are an External Attack Surface & Reconnaissance Analyst following MITRE ATT&CK Recon tactics.\n\n" +
      "## Workflow\n" +
      "- Enumerate subdomains, DNS records, certificate transparency logs, and virtual hosts.\n" +
      "- Fingerprint exposed services, versions, admin panels, and cloud storage buckets.\n" +
      "- Map versions to known CVEs/CISA KEV and prioritize high-value targets.\n",
  },
  {
    label: "Cloud & Container",
    key: "cloud_auditor",
    name: "Cloud & Infrastructure Auditor",
    description: "AWS/GCP/Azure metadata, Kubernetes, Docker, IAM misconfiguration, and CIS benchmark auditor.",
    prompt:
      "You are a Cloud & Container Security Auditor.\n\n" +
      "## Workflow\n" +
      "- Check for exposed `.env`, `.git`, actuator endpoints, Docker sockets, and Kubernetes APIs.\n" +
      "- Safely test SSRF vectors against cloud metadata services and verify IAM/storage permissions.\n" +
      "- Produce clear remediation guidance aligned with CIS benchmarks.\n",
  },
  {
    label: "Exploit & PoC Verifier",
    key: "poc_verifier",
    name: "Exploit & PoC Verifier",
    description: "Adversarial verification specialist that reproduces candidate vulnerabilities and eliminates false positives.",
    prompt:
      "You are an Adversarial Exploit & PoC Verifier.\n\n" +
      "## Rules\n" +
      "- Never trust scanner banners or version numbers alone; reproduce every finding with a minimal, harmless PoC.\n" +
      "- Record exact HTTP requests, responses, and reproduction commands.\n" +
      "- Reject false positives and clearly document root causes.\n",
  },
];

function CreateAgentDialog({ onCreated }: { onCreated: (key: string) => void }) {
  const { ui } = useUITranslation();

  const [open, setOpen] = React.useState(false);
  const [key, setKey] = React.useState("");
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [presetPrompt, setPresetPrompt] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function create() {
    setBusy(true);
    try {
      const a = await api.createAgent(key.trim(), name.trim(), description.trim());
      if (presetPrompt.trim()) {
        await api.saveAgentPrompt(a.key, presetPrompt.trim()).catch(() => {});
      }
      toast.success(ui("screen.e3157f17b61218", { v0: a.name }));
      setOpen(false);
      setKey("");
      setName("");
      setDescription("");
      setPresetPrompt("");
      onCreated(a.key);
    } catch (e) {
      toast.error(ui("screen.39e6db7a1b1a1d") + (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const keyOk = /^[a-z][a-z0-9_]*$/.test(key.trim());
  const canCreate = keyOk && name.trim().length > 0 && !busy;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <PlusIcon /> {ui("screen.0587b9924d4b94")}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{ui("screen.d22e3cbae44582")}</DialogTitle>
          <DialogDescription>{ui("screen.fbc0da0804457d")}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-1.5">
            <Label className="text-muted-foreground text-xs">Quick Template</Label>
            <div className="flex flex-wrap gap-1.5">
              {AGENT_PRESETS.map((preset) => (
                <button
                  key={preset.key}
                  type="button"
                  onClick={() => {
                    setKey(preset.key);
                    setName(preset.name);
                    setDescription(preset.description);
                    setPresetPrompt(preset.prompt);
                  }}
                  className={`rounded-md border px-2 py-1 text-xs transition-colors hover:bg-accent hover:text-accent-foreground ${
                    key === preset.key ? "border-primary bg-primary/10 text-primary" : "bg-muted/40"
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="agent-key">Key</Label>
            <Input
              id="agent-key"
              placeholder={ui("screen.cfa4d8b368c6c2")}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              className="font-mono"
            />
            {key.length > 0 && !keyOk && (
              <span className="text-destructive text-xs">{ui("screen.9af467fca90b41")}</span>
            )}
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="agent-name">{ui("screen.d44e9b3d3b31d3")}</Label>
            <Input
              id="agent-name"
              placeholder={ui("screen.6c975aeebf3234")}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="agent-desc">{ui("screen.dc2ba467fc7ac9")}</Label>
            <Textarea
              id="agent-desc"
              placeholder={ui("screen.9f306d966127ca")}
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button onClick={create} disabled={!canCreate}>
            {ui("screen.cde2cd071d25bb")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function AgentsPage() {
  const { ui } = useUITranslation();

  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [editKey, setEditKey] = React.useState<string | null>(null);

  const reload = React.useCallback(() => {
    api
      .agents()
      .then(setAgents)
      .catch(() => setAgents([]));
  }, []);
  React.useEffect(() => {
    reload();
  }, [reload]);

  const editing = agents.find((a) => a.key === editKey) ?? null;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Agent</h1>
          <p className="text-muted-foreground text-sm">{ui("screen.154f21a81d023e")}</p>
        </div>
        <CreateAgentDialog
          onCreated={(key) => {
            reload();
            setEditKey(key);
          }}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{ui("screen.6b0edca7dde4ef")}</CardTitle>
          <CardDescription>
            {ui("screen.76e547a8fa5463")}
            {agents.length} {ui("screen.3a116815bc9da1")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {agents.length === 0 ? (
            <p className="text-muted-foreground py-6 text-center text-sm">{ui("screen.1ece46293a50b7")}</p>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {agents.map((a) => (
                <AgentGridCard key={a.key} agent={a} onOpen={() => setEditKey(a.key)} onDeleted={reload} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Sheet open={!!editing} onOpenChange={(o) => !o && setEditKey(null)}>
        <SheetContent
          side="right"
          className="flex flex-col gap-0 p-0 data-[side=right]:w-[45vw] data-[side=right]:sm:max-w-[45vw]"
        >
          {editing && (
            <>
              <SheetHeader className="px-4">
                <SheetTitle className="flex items-center gap-2">
                  {agentDisplayName(editing, ui)}
                  <span className="text-muted-foreground font-mono text-xs">{editing.key}</span>
                  {!editing.builtin && (
                    <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
                      {ui("screen.4eafa9e925b30b")}
                    </Badge>
                  )}
                </SheetTitle>
                <SheetDescription>
                  {agentDisplayDescription(editing, ui) || ui("screen.8d84b90da03a1f")}
                </SheetDescription>
              </SheetHeader>
              <AgentEditor agentKey={editing.key} onSaved={reload} />
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
