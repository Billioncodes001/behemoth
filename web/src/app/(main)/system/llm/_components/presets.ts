export type LLMModelOption = {
  id: string;
  label: string;
  badge?: string;
  baseUrl?: string;
  format?: "anthropic" | "openai" | "openai-responses";
  thinkingType?: "none" | "enabled" | "disabled";
  effort?: "none" | "low" | "medium" | "high" | "xhigh" | "max";
  contextWindowK?: number;
  maxTokens?: number;
  maxTokensField?: "none" | "max_completion_tokens";
};

export type LLMProviderPreset = {
  name: string;
  hint: string;
  format: "anthropic" | "openai" | "openai-responses";
  baseUrl: string;
  model: string;
  models: LLMModelOption[];
};

export const LLM_PRESETS: LLMProviderPreset[] = [
  {
    name: "Cline",
    hint: "api.cline.bot/api/v1 — Cline Official Gateway (Recommended, Frontier & Free Models)",
    format: "openai",
    baseUrl: "https://api.cline.bot/api/v1",
    model: "anthropic/claude-sonnet-5.5",
    models: [
      { id: "anthropic/claude-sonnet-5.5", label: "Claude Sonnet 5.5 — Recommended", badge: "NEW", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "google/gemini-4-argon", label: "Gemini 4 Argon — Coding & Cyber Defense", badge: "NEW", effort: "high", contextWindowK: 1000, maxTokens: 65536 },
      { id: "anthropic/claude-opus-5.5", label: "Claude Opus 5.5 — Recommended Flagship", badge: "NEW", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "openai/gpt-6-astra", label: "GPT-6 Astra — Recommended Frontier", badge: "NEW", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "openai/gpt-6.1-sol", label: "GPT-6.1 Sol — Recommended Agentic", badge: "NEW", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "moonshotai/kimi-k3", label: "Kimi K3 — Flagship MoE Agentic Coding", badge: "NEW", thinkingType: "enabled", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "meta/muse-wonder-1.0", label: "Muse Ember / Wonder — Fast Agentic Execution", badge: "NEW", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "~anthropic/claude-fable-latest", label: "~anthropic/claude-fable-latest", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "~anthropic/claude-opus-latest", label: "~anthropic/claude-opus-latest", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "~anthropic/claude-sonnet-latest", label: "~anthropic/claude-sonnet-latest", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "~anthropic/claude-haiku-latest", label: "~anthropic/claude-haiku-latest", effort: "medium", contextWindowK: 1000, maxTokens: 128000 },
      { id: "~deepseek/deepseek-pro-latest", label: "~deepseek/deepseek-pro-latest", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "~deepseek/deepseek-flash-latest", label: "~deepseek/deepseek-flash-latest", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "~openai/gpt-astra-latest", label: "~openai/gpt-astra-latest", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "~openai/gpt-sol-latest", label: "~openai/gpt-sol-latest", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "~google/gemini-pro-latest", label: "~google/gemini-pro-latest", effort: "high", contextWindowK: 1000, maxTokens: 65536 },
      { id: "~moonshotai/kimi-latest", label: "~moonshotai/kimi-latest", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "reflection/beam-free", label: "Beam 1.0 (Free)", badge: "FREE", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "cline-free/nemotron-3.5-super-vl", label: "Nemotron 3.5 Super VL (Free)", badge: "FREE", thinkingType: "enabled", contextWindowK: 1000, maxTokens: 131072 },
      { id: "nvidia/nemotron-3.5-lightning-free", label: "Nemotron 3.5 Lightning (Free)", badge: "FREE", effort: "high", contextWindowK: 1000, maxTokens: 65000 },
    ],
  },
  {
    name: "Featherless AI",
    hint: "api.featherless.ai/v1 — Serverless Open-Weights & Uncensored Models",
    format: "openai",
    baseUrl: "https://api.featherless.ai/v1",
    model: "moonshotai/Kimi-K3.1-Pro",
    models: [
      { id: "moonshotai/Kimi-K3.1-Pro", label: "Kimi K3.1 Pro (262K ctx)", badge: "TOP", contextWindowK: 262, maxTokens: 32768 },
      { id: "moonshotai/Kimi-K3", label: "Kimi K3 (262K ctx)", contextWindowK: 262, maxTokens: 32768 },
      { id: "deepseek-ai/DeepSeek-V4.1-Flash-1017", label: "DeepSeek V4.1 Flash 1017 (262K ctx)", badge: "FAST", contextWindowK: 262, maxTokens: 32768 },
      { id: "deepseek-ai/DeepSeek-V4.1-Flash", label: "DeepSeek V4.1 Flash (262K ctx)", contextWindowK: 262, maxTokens: 32768 },
      { id: "Qwen/Qwen3.8-27B", label: "Qwen 3.8 27B (262K ctx)", contextWindowK: 262, maxTokens: 32768 },
      { id: "Qwen/Qwen3.8-Flash-Next", label: "Qwen 3.8 Flash Next (262K ctx)", contextWindowK: 262, maxTokens: 32768 },
      { id: "zai-org/GLM-5.3", label: "GLM-5.3 (262K ctx)", contextWindowK: 262, maxTokens: 32768 },
      { id: "zai-org/GLM-5.3-Flash", label: "GLM-5.3 Flash (262K ctx)", contextWindowK: 262, maxTokens: 32768 },
      { id: "MiniMaxAI/MiniMax-M3.1-Flash", label: "MiniMax M3.1 Flash (1M ctx)", contextWindowK: 1000, maxTokens: 131072 },
      { id: "openai/gpt-oss-120b", label: "OpenAI GPT-OSS 120B (131K ctx)", contextWindowK: 200, maxTokens: 32768 },
      { id: "meta-models/Muse-Glimmer-30B", label: "Muse Glimmer 30B (131K ctx)", contextWindowK: 200, maxTokens: 32768 },
      { id: "google/gemma-4-31B-it", label: "Google Gemma 4 31B IT", contextWindowK: 200, maxTokens: 16384 },
      { id: "NousResearch/Arete-27B", label: "NousResearch Arete 27B", contextWindowK: 200, maxTokens: 16384 },
      { id: "xtools-at/DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic", label: "DeepSeek V4 Pro Qwen3.5 9B Uncensored", badge: "UNCENSORED", contextWindowK: 200, maxTokens: 16384 },
      { id: "OBLITERATUS/Qwen3.8-27B-OBLITERATED", label: "Qwen 3.8 27B Obliterated (Uncensored)", badge: "UNCENSORED", contextWindowK: 200, maxTokens: 16384 },
      { id: "huihui-ai/Huihui-Qwen3.8-27B-abliterated", label: "Huihui Qwen 3.8 27B Abliterated (Uncensored)", badge: "UNCENSORED", contextWindowK: 200, maxTokens: 16384 },
    ],
  },
  {
    name: "Anthropic",
    hint: "api.anthropic.com — Official Claude Frontier Models",
    format: "anthropic",
    baseUrl: "https://api.anthropic.com",
    model: "claude-sonnet-5-5",
    models: [
      { id: "claude-sonnet-5-5", label: "Claude Sonnet 5.5 (1M ctx)", badge: "RECOMMENDED", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "claude-opus-5-5", label: "Claude Opus 5.5 (1M ctx)", badge: "FLAGSHIP", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "claude-fable-5-1", label: "Claude Fable 5.1 (1M ctx)", badge: "FRONTIER", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "claude-haiku-5-5", label: "Claude Haiku 5.5 (1M ctx)", badge: "FAST", thinkingType: "enabled", effort: "medium", contextWindowK: 1000, maxTokens: 128000 },
      { id: "claude-opus-5", label: "Claude Opus 5 (1M ctx)", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "claude-sonnet-5", label: "Claude Sonnet 5 (1M ctx)", thinkingType: "enabled", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "claude-opus-4-8", label: "Claude Opus 4.8 (1M ctx)", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "claude-sonnet-4-6", label: "Claude Sonnet 4.6 (1M ctx)", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "claude-opus-4-5", label: "Claude Opus 4.5 (200K ctx)", effort: "high", contextWindowK: 200, maxTokens: 64000 },
      { id: "claude-sonnet-4-5", label: "Claude Sonnet 4.5 (200K ctx)", thinkingType: "enabled", contextWindowK: 200, maxTokens: 64000 },
    ],
  },
  {
    name: "OpenAI",
    hint: "api.openai.com/v1 — Official GPT-6 / GPT-5 / o-Series Reasoning Models",
    format: "openai",
    baseUrl: "https://api.openai.com/v1",
    model: "gpt-6.1-sol",
    models: [
      { id: "gpt-6.1-sol", label: "GPT-6.1 Sol (1M ctx)", badge: "RECOMMENDED", effort: "high", maxTokensField: "max_completion_tokens", contextWindowK: 1000, maxTokens: 128000 },
      { id: "gpt-6-astra", label: "GPT-6 Astra (1M ctx)", badge: "FLAGSHIP", effort: "high", maxTokensField: "max_completion_tokens", contextWindowK: 1000, maxTokens: 128000 },
      { id: "gpt-6-sol", label: "GPT-6 Sol (1M ctx)", effort: "high", maxTokensField: "max_completion_tokens", contextWindowK: 1000, maxTokens: 128000 },
      { id: "gpt-6-luna", label: "GPT-6 Luna (1M ctx)", effort: "high", maxTokensField: "max_completion_tokens", contextWindowK: 1000, maxTokens: 128000 },
      { id: "gpt-5.4", label: "GPT-5.4 (1M ctx)", effort: "high", maxTokensField: "max_completion_tokens", contextWindowK: 1000, maxTokens: 128000 },
      { id: "gpt-5.2-codex", label: "GPT-5.2 Codex", effort: "high", maxTokensField: "max_completion_tokens", contextWindowK: 400, maxTokens: 128000 },
      { id: "gpt-5", label: "GPT-5", effort: "high", maxTokensField: "max_completion_tokens", contextWindowK: 400, maxTokens: 128000 },
      { id: "o3", label: "o3 Reasoning", effort: "high", maxTokensField: "max_completion_tokens", contextWindowK: 200, maxTokens: 100000 },
      { id: "o4-mini", label: "o4-mini Fast Reasoning", effort: "high", maxTokensField: "max_completion_tokens", contextWindowK: 200, maxTokens: 100000 },
    ],
  },
  {
    name: "DeepSeek",
    hint: "api.deepseek.com/v1 — DeepSeek V4 Pro, V4.1 Flash, R1 & V3",
    format: "openai",
    baseUrl: "https://api.deepseek.com/v1",
    model: "deepseek-v4-pro",
    models: [
      { id: "deepseek-v4-pro", label: "DeepSeek V4 Pro (1M ctx)", badge: "FLAGSHIP", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "deepseek-v4.1-flash-1017", label: "DeepSeek V4.1 Flash 1017 (1M ctx)", badge: "RECOMMENDED", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "deepseek-v4.1-flash", label: "DeepSeek V4.1 Flash (1M ctx)", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "deepseek-reasoner", label: "DeepSeek Reasoner (R1)", effort: "high", contextWindowK: 200, maxTokens: 64000 },
      { id: "deepseek-chat", label: "DeepSeek Chat (V3)", contextWindowK: 200, maxTokens: 64000 },
    ],
  },
  {
    name: "Moonshot (Kimi)",
    hint: "api.moonshot.ai/v1 — Official Moonshot Kimi K3.1 Pro, K3 & K2.7 Code",
    format: "openai",
    baseUrl: "https://api.moonshot.ai/v1",
    model: "kimi-k3.1-pro",
    models: [
      { id: "kimi-k3.1-pro", label: "Kimi K3.1 Pro (1M ctx)", badge: "FLAGSHIP", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "kimi-k3.1-pro-highspeed", label: "Kimi K3.1 Pro Highspeed (1M ctx)", badge: "FAST", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "kimi-k3", label: "Kimi K3 (1M ctx)", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "kimi-k2.7-code", label: "Kimi K2.7 Code (262K ctx)", contextWindowK: 262, maxTokens: 65536 },
      { id: "kimi-k2.7-code-highspeed", label: "Kimi K2.7 Code Highspeed (262K ctx)", contextWindowK: 262, maxTokens: 65536 },
      { id: "kimi-k2.6", label: "Kimi K2.6 (262K ctx)", thinkingType: "enabled", contextWindowK: 262, maxTokens: 65536 },
      { id: "kimi-latest", label: "Kimi Latest", contextWindowK: 262, maxTokens: 65536 },
    ],
  },
  {
    name: "Google Gemini",
    hint: "generativelanguage.googleapis.com/v1beta/openai — Gemini 4 Carbon, Argon & Hydrogen",
    format: "openai",
    baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
    model: "gemini-4-argon",
    models: [
      { id: "gemini-4-argon", label: "Gemini 4 Argon (1M ctx)", badge: "FLAGSHIP", effort: "high", contextWindowK: 1000, maxTokens: 65536 },
      { id: "gemini-4-carbon", label: "Gemini 4 Carbon (1M ctx)", badge: "FRONTIER", effort: "high", contextWindowK: 1000, maxTokens: 65536 },
      { id: "gemini-4-hydrogen", label: "Gemini 4 Hydrogen (1M ctx)", badge: "FAST", effort: "medium", contextWindowK: 1000, maxTokens: 65536 },
      { id: "gemini-3.8-flash", label: "Gemini 3.8 Flash (1M ctx)", effort: "high", contextWindowK: 1000, maxTokens: 65536 },
      { id: "gemini-3.7-flash", label: "Gemini 3.7 Flash (1M ctx)", effort: "high", contextWindowK: 1000, maxTokens: 65536 },
      { id: "gemini-3.1-pro-preview", label: "Gemini 3.1 Pro Preview (1M ctx)", effort: "high", contextWindowK: 1000, maxTokens: 65536 },
      { id: "gemini-2.5-pro", label: "Gemini 2.5 Pro (1M ctx)", effort: "high", contextWindowK: 1000, maxTokens: 65536 },
      { id: "gemini-2.5-flash", label: "Gemini 2.5 Flash (1M ctx)", contextWindowK: 1000, maxTokens: 65536 },
    ],
  },
  {
    name: "OpenRouter",
    hint: "openrouter.ai/api/v1 — Unified Gateway to 300+ Frontier & Free Models",
    format: "openai",
    baseUrl: "https://openrouter.ai/api/v1",
    model: "anthropic/claude-sonnet-5.5",
    models: [
      { id: "anthropic/claude-sonnet-5.5", label: "Anthropic: Claude Sonnet 5.5", badge: "TOP", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "anthropic/claude-opus-5.5", label: "Anthropic: Claude Opus 5.5", badge: "FLAGSHIP", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "openai/gpt-6.1-sol", label: "OpenAI: GPT-6.1 Sol", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "openai/gpt-6-astra", label: "OpenAI: GPT-6 Astra", effort: "high", contextWindowK: 1000, maxTokens: 128000 },
      { id: "moonshotai/kimi-k3.1-pro", label: "MoonshotAI: Kimi K3.1 Pro", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "deepseek/deepseek-v4.1-flash-1017", label: "DeepSeek: V4.1 Flash 1017", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "minimax/minimax-m3.1-flash", label: "MiniMax: M3.1 Flash", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "meta/muse-spark-open", label: "Meta: Muse Spark Open", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "reflection/beam-1.0-501b-a23b", label: "Reflection: Beam 1.0 501B", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "mistralai/mistral-large-4-0", label: "Mistral: Large 4", effort: "high", contextWindowK: 1000, maxTokens: 131072 },
      { id: "nvidia/nemotron-3.5-super-vl:free", label: "NVIDIA: Nemotron 3.5 Super VL (Free)", badge: "FREE", thinkingType: "enabled", contextWindowK: 1000, maxTokens: 131072 },
      { id: "recursive/flint-v1.0:free", label: "Recursive: Flint v1.0 (Free)", badge: "FREE", contextWindowK: 262, maxTokens: 65536 },
    ],
  },
  {
    name: "Ollama (local)",
    hint: "http://localhost:11434/v1 — Local Ollama Runtime (no API key required)",
    format: "openai",
    baseUrl: "http://localhost:11434/v1",
    model: "qwen3:32b",
    models: [
      { id: "qwen3:32b", label: "Qwen 3 32B", contextWindowK: 200, maxTokens: 32768 },
      { id: "qwen2.5-coder:32b", label: "Qwen 2.5 Coder 32B", contextWindowK: 200, maxTokens: 32768 },
      { id: "qwen2.5:14b", label: "Qwen 2.5 14B", contextWindowK: 200, maxTokens: 16384 },
      { id: "deepseek-r1:32b", label: "DeepSeek R1 32B", contextWindowK: 200, maxTokens: 32768 },
      { id: "llama3.3:70b", label: "Llama 3.3 70B", contextWindowK: 200, maxTokens: 32768 },
      { id: "gemma3:27b", label: "Gemma 3 27B", contextWindowK: 200, maxTokens: 16384 },
    ],
  },
  {
    name: "LM Studio (local)",
    hint: "http://localhost:1234/v1 — Local LM Studio OpenAI Server",
    format: "openai",
    baseUrl: "http://localhost:1234/v1",
    model: "qwen3-30b-a3b-abliterated",
    models: [
      { id: "qwen3-30b-a3b-abliterated", label: "Qwen 3 30B A3B Abliterated", contextWindowK: 200, maxTokens: 32768 },
      { id: "openai/gpt-oss-20b", label: "OpenAI GPT-OSS 20B", contextWindowK: 200, maxTokens: 32768 },
      { id: "deepseek-r1-distill-qwen-32b", label: "DeepSeek R1 Distill Qwen 32B", contextWindowK: 200, maxTokens: 32768 },
    ],
  },
  {
    name: "vLLM (local)",
    hint: "http://localhost:8000/v1 — Self-Hosted vLLM OpenAI Server",
    format: "openai",
    baseUrl: "http://localhost:8000/v1",
    model: "Qwen/Qwen3.8-27B",
    models: [
      { id: "Qwen/Qwen3.8-27B", label: "Qwen/Qwen3.8-27B", contextWindowK: 200, maxTokens: 32768 },
      { id: "deepseek-ai/DeepSeek-V4.1-Flash", label: "deepseek-ai/DeepSeek-V4.1-Flash", contextWindowK: 200, maxTokens: 32768 },
      { id: "meta-llama/Llama-3.3-70B-Instruct", label: "meta-llama/Llama-3.3-70B-Instruct", contextWindowK: 200, maxTokens: 32768 },
    ],
  },
];
