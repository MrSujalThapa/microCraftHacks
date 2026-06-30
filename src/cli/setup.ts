import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { resolve } from "node:path";

import { ENV_RELATIVE_PATH, loadDotEnv, upsertDotEnvValues } from "../config/env";
import { initProject } from "../config/init";
import { loadConfig } from "../config/load";
import { getConfigPath } from "../config/paths";
import { getDoctorConfigStatus } from "../config/status";
import type { SwarmConfig, SwarmProvider } from "../config/types";
import { buildSkillsIndex } from "../skills/indexer";
import { syncSkills } from "../skills/sync";
import { printCliError } from "./errors";

const DEFAULT_PROVIDER: SwarmProvider = "openai";
const DEFAULT_MODEL = "gpt-5-mini";
const PROVIDERS = new Set<SwarmProvider>(["openai", "mock", "local"]);

export interface SetupOptions {
  provider?: string;
  model?: string;
  apiKey?: string;
  skipSkillsSync?: boolean;
  skipSkillsIndex?: boolean;
  yes?: boolean;
}

export interface SetupPrompter {
  text(question: string, defaultValue: string): Promise<string>;
  secret(question: string): Promise<string>;
  confirm(question: string, defaultValue: boolean): Promise<boolean>;
}

export interface SetupDependencies {
  prompter?: SetupPrompter;
  log?: (message: string) => void;
  warn?: (message: string) => void;
  sync?: typeof syncSkills;
  index?: typeof buildSkillsIndex;
}

function parseProvider(value: string): SwarmProvider {
  const normalized = value.trim().toLowerCase();
  if (PROVIDERS.has(normalized as SwarmProvider)) {
    return normalized as SwarmProvider;
  }
  throw new Error(`Invalid provider "${value}". Expected one of: openai, mock, local`);
}

export function maskApiKey(key: string): string {
  const trimmed = key.trim();
  if (!trimmed) {
    return "missing";
  }
  if (trimmed.startsWith("sk-") && trimmed.length > 7) {
    return `sk-...${trimmed.slice(-4)}`;
  }
  return `...${trimmed.slice(-4)}`;
}

function getOpenAiKeyFromEnvironment(root: string): string | undefined {
  loadDotEnv(root);
  const value = process.env.OPENAI_API_KEY?.trim();
  return value || undefined;
}

function writeConfig(config: SwarmConfig, root: string): void {
  writeFileSync(getConfigPath(root), `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function createTerminalPrompter(): SetupPrompter {
  async function askText(question: string): Promise<string> {
    const rl = createInterface({ input, output });
    try {
      return await rl.question(question);
    } finally {
      rl.close();
    }
  }

  return {
    async text(question: string, defaultValue: string): Promise<string> {
      const answer = await askText(`${question} (${defaultValue}): `);
      return answer.trim() || defaultValue;
    },
    async confirm(question: string, defaultValue: boolean): Promise<boolean> {
      const suffix = defaultValue ? "Y/n" : "y/N";
      const answer = (await askText(`${question} (${suffix}): `)).trim().toLowerCase();
      if (!answer) {
        return defaultValue;
      }
      return answer === "y" || answer === "yes";
    },
    async secret(question: string): Promise<string> {
      if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== "function") {
        return (await askText(`${question}: `)).trim();
      }

      return await new Promise<string>((resolveSecret) => {
        let value = "";
        output.write(`${question}: `);
        input.setRawMode(true);
        input.resume();
        input.setEncoding("utf8");

        const onData = (chunk: string) => {
          for (const char of chunk) {
            if (char === "\r" || char === "\n") {
              cleanup();
              output.write("\n");
              resolveSecret(value.trim());
              return;
            }
            if (char === "\u0003") {
              cleanup();
              output.write("\n");
              process.kill(process.pid, "SIGINT");
              return;
            }
            if (char === "\b" || char === "\u007f") {
              value = value.slice(0, -1);
              continue;
            }
            value += char;
          }
        };

        const cleanup = () => {
          input.off("data", onData);
          input.setRawMode(false);
          input.pause();
        };

        input.on("data", onData);
      });
    },
  };
}

function ensureGitIgnoreContainsEnv(root: string, log: (message: string) => void): void {
  for (const filename of [".gitignore", ".npmignore"]) {
    const path = resolve(root, filename);
    const content = existsSync(path) ? readFileSync(path, "utf8") : "";
    const hasEnv = content
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .includes(".env");

    if (!hasEnv) {
      const prefix = content.length > 0 && !/\r?\n$/u.test(content) ? "\n" : "";
      writeFileSync(path, `${content}${prefix}.env\n`, "utf8");
      log(`Added .env to ${filename}`);
    }
  }
}

function shouldPrompt(options: SetupOptions): boolean {
  return options.yes !== true;
}

export async function runSetup(
  options: SetupOptions = {},
  root = process.cwd(),
  dependencies: SetupDependencies = {},
): Promise<void> {
  const log = dependencies.log ?? console.log;
  const warn = dependencies.warn ?? console.warn;
  const prompter = dependencies.prompter ?? createTerminalPrompter();
  const sync = dependencies.sync ?? syncSkills;
  const index = dependencies.index ?? buildSkillsIndex;
  const prompt = shouldPrompt(options);

  const initResult = initProject(root);
  if (initResult.configCreated) {
    log("Created .swarm/config.json");
  } else {
    log("Using existing .swarm/config.json");
  }

  const existingConfig = loadConfig(root);
  const providerInput =
    options.provider ??
    (prompt ? await prompter.text("Provider", existingConfig.provider || DEFAULT_PROVIDER) : undefined) ??
    existingConfig.provider ??
    DEFAULT_PROVIDER;
  const provider = parseProvider(providerInput);

  const model =
    options.model ??
    (prompt ? await prompter.text("Model", existingConfig.model || DEFAULT_MODEL) : undefined) ??
    existingConfig.model ??
    DEFAULT_MODEL;

  const config: SwarmConfig = {
    ...existingConfig,
    provider,
    model,
  };
  writeConfig(config, root);
  log(`Configured provider ${provider}`);
  log(`Configured model ${model}`);

  ensureGitIgnoreContainsEnv(root, log);

  const existingKey = getOpenAiKeyFromEnvironment(root);
  const providedKey = options.apiKey?.trim();

  if (provider === "openai") {
    if (providedKey) {
      upsertDotEnvValues(root, { OPENAI_API_KEY: providedKey });
      log(`Saved OpenAI API key to ${ENV_RELATIVE_PATH} (${maskApiKey(providedKey)})`);
    } else if (existingKey) {
      log(`OpenAI API key already found (${maskApiKey(existingKey)})`);
    } else if (prompt) {
      const apiKey = await prompter.secret("OpenAI API key");
      if (!apiKey) {
        throw new Error("OPENAI_API_KEY is required for the openai provider.");
      }
      upsertDotEnvValues(root, { OPENAI_API_KEY: apiKey });
      log(`Saved OpenAI API key to ${ENV_RELATIVE_PATH} (${maskApiKey(apiKey)})`);
    } else {
      throw new Error("OPENAI_API_KEY is required for the openai provider. Pass --api-key or set it in .env.");
    }
  } else if (providedKey) {
    warn("Ignoring --api-key because provider is not openai.");
  }

  const syncSkillsNow =
    !options.skipSkillsSync &&
    (prompt ? await prompter.confirm("Sync skills now", true) : true);
  const indexSkillsNow =
    !options.skipSkillsIndex &&
    (prompt ? await prompter.confirm("Build skills index now", true) : true);

  if (syncSkillsNow) {
    const syncResult = sync(root, config);
    log("Skills sync complete.");
    log(`Lockfile: ${syncResult.lockfilePath}`);
  } else {
    log("Skipped skills sync.");
  }

  if (indexSkillsNow) {
    const indexResult = index(root, config);
    log("Skills index complete.");
    log(`Indexed: ${indexResult.index.count} skills`);
  } else {
    log("Skipped skills index.");
  }

  const doctor = getDoctorConfigStatus(root);
  log("Doctor summary:");
  log(`Config: ${doctor.valid ? "ok" : doctor.message}`);
  if (doctor.provider) {
    log(`Provider: ${doctor.provider.provider}`);
    log(`Model: ${doctor.provider.model}`);
    log(`OpenAI key: ${doctor.provider.openaiKeyPresent ? "found" : "missing"}`);
  }

  log("Next commands:");
  log("  swarm doctor");
  log("  swarm skills list");
  log(`  swarm demo <target> --provider ${provider} --model ${model}`);
}

export async function runSetupCommand(options: SetupOptions): Promise<void> {
  try {
    await runSetup(options, resolve(process.cwd()));
  } catch (error) {
    printCliError(error);
    process.exitCode = 1;
  }
}
