import catalog from "./screen-catalog.json";
import type { UITranslate } from "./use-ui-translation";

// These are shipped names, not arbitrary Agent names or prompt content. Match
// both the reserved key and the original value so user edits remain untouched.
const shippedNames: Record<string, string[]> = {
  goals: ["目标拆解", "目标拆解器", "Goal Decomposer", "Goal decomposition"],
  planner: ["规划", "规划者", "Planner", "Planning"],
  mainagent: ["主", "主 Agent", "Main", "Main Agent"],
  worker: ["执行", "Work Agent", "Worker", "Execution"],
  auto: ["Auto"],
  asset_mapper: ["资产梳理", "Asset Mapper", "Asset mapping"],
  pentest: ["渗透测试", "Solo Pentest", "Penetration testing"],
  patch_watch: ["补丁监控", "Patch Watch", "Security Watch"],
  retester: ["漏洞复测", "Finding Retester", "Finding retest"],
  reporter: ["报告撰写", "Report Writer", "Report writing"],
  credential_processor: ["凭据整理", "Credential Processor", "Credential processing"],
};

export function agentDisplayName(agent: { key: string; name: string }, ui: (key: string) => string): string {
  return shippedNames[agent.key]?.includes(agent.name) ? ui(`builtinAgent.${agent.key}.name`) : agent.name;
}

const shippedDescriptions = new Map(
  Object.entries(catalog)
    .filter(([key]) => key.startsWith("builtinAgentDescription."))
    .map(([key, pair]) => [pair[0], key]),
);

export function agentDisplayDescription(agent: { key: string; description?: string }, ui: (key: string) => string): string {
  const text = agent.description ?? "";
  const key = shippedNames[agent.key] ? shippedDescriptions.get(text) : undefined;
  return key ? ui(key) : text;
}
