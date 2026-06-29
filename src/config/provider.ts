import { loadConfig, tryLoadConfig } from "./load";
import { isOpenAiKeyPresent, loadDotEnv, readEnvModel, readEnvProvider } from "./env";
import { ProviderError } from "./provider-errors";
import type { ResolvedProvider, SwarmProvider } from "./types";

const PROVIDERS = new Set<SwarmProvider>(["openai", "mock", "local"]);
const DEFAULT_MODEL = "gpt-5-mini";
const DEFAULT_PROVIDER: SwarmProvider = "mock";

export interface ProviderOverrides {
  provider?: SwarmProvider;
  model?: string;
}

export type { ResolvedProvider } from "./types";

function parseProvider(value: string | undefined): SwarmProvider | undefined {
  if (!value) {
    return undefined;
  }
  if (PROVIDERS.has(value as SwarmProvider)) {
    return value as SwarmProvider;
  }
  throw new ProviderError(
    `Invalid provider "${value}". Expected one of: ${[...PROVIDERS].join(", ")}`,
  );
}

export function resolveProvider(root: string, overrides: ProviderOverrides = {}): ResolvedProvider {
  loadDotEnv(root);

  const config = tryLoadConfig(root);
  const overrideProvider = parseProvider(overrides.provider);
  const envProvider = parseProvider(readEnvProvider());

  let provider: SwarmProvider = DEFAULT_PROVIDER;
  let providerSource: ResolvedProvider["sources"]["provider"] = "default";

  if (overrideProvider) {
    provider = overrideProvider;
    providerSource = "cli";
  } else if (config?.provider) {
    provider = config.provider;
    providerSource = "config";
  } else if (envProvider) {
    provider = envProvider;
    providerSource = "env";
  }

  let model = DEFAULT_MODEL;
  let modelSource: ResolvedProvider["sources"]["model"] = "default";

  if (overrides.model?.trim()) {
    model = overrides.model.trim();
    modelSource = "cli";
  } else if (config?.model?.trim()) {
    model = config.model.trim();
    modelSource = "config";
  } else if (readEnvModel()) {
    model = readEnvModel()!;
    modelSource = "env";
  }

  return {
    provider,
    model,
    openaiKeyPresent: isOpenAiKeyPresent(),
    sources: {
      provider: providerSource,
      model: modelSource,
    },
  };
}

export function assertProviderReady(resolved: ResolvedProvider): void {
  if (resolved.provider === "openai" && !resolved.openaiKeyPresent) {
    throw new ProviderError(
      "OPENAI_API_KEY is missing. Add it to .env or run with --provider mock.",
    );
  }

  if (resolved.provider === "local") {
    throw new ProviderError(
      "Local provider is not implemented yet. Use --provider mock or --provider openai.",
    );
  }
}
