import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { resolve } from "node:path";

import { loadDotEnv, upsertDotEnvValues } from "../config/env";
import { initProject } from "../config/init";
import { loadConfig } from "../config/load";
import { getConfigPath } from "../config/paths";
import { getDoctorConfigStatus } from "../config/status";
import type { SwarmConfig, SwarmProvider } from "../config/types";
import { containsRawSecret } from "../shared/redaction";
import { buildSkillsIndex } from "../skills/indexer";
import { syncSkills } from "../skills/sync";
import { printCliError } from "./errors";

const DEFAULT_PROVIDER: SwarmProvider = "openai";
const DEFAULT_MODEL = "gpt-5-mini";
const PROVIDERS = new Set<SwarmProvider>(["openai", "mock", "local"]);

const NON_TTY_SECRET_ERROR =
  "Interactive API key entry requires a TTY so the key can stay hidden. Set OPENAI_API_KEY in .env, or use --api-key only for automation.";

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

interface SecretInput {
  isTTY?: boolean;
  isRaw?: boolean;
  readableEncoding?: BufferEncoding | null;
  setRawMode?: (mode: boolean) => unknown;
  resume: () => unknown;
  pause: () => unknown;
  setEncoding: (encoding: BufferEncoding) => unknown;
  on: {
    (event: "data", listener: (chunk: Buffer | string) => void): unknown;
    (event: "error", listener: (error: Error) => void): unknown;
  };
  off: {
    (event: "data", listener: (chunk: Buffer | string) => void): unknown;
    (event: "error", listener: (error: Error) => void): unknown;
  };
}

interface SecretOutput {
  isTTY?: boolean;
  write: (chunk: string) => unknown;
}

function parseProvider(value: string): SwarmProvider {
  const normalized = value.trim().toLowerCase();
  if (containsRawSecret(value)) {
    throw new Error("Provider value looks like a secret. Press Enter for openai; the API key prompt comes later.");
  }
  if (PROVIDERS.has(normalized as SwarmProvider)) {
    return normalized as SwarmProvider;
  }
  throw new Error("Invalid provider. Expected one of: openai, mock, local");
}

function normalizeModel(value: string): string {
  const model = value.trim();
  if (containsRawSecret(model)) {
    throw new Error("Model value looks like a secret. The API key prompt comes later.");
  }
  if (!model) {
    return DEFAULT_MODEL;
  }
  return model;
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

export async function readMaskedInput(
  secretInput: SecretInput,
  secretOutput: SecretOutput,
  question: string,
): Promise<string> {
  if (!secretInput.isTTY || !secretOutput.isTTY || typeof secretInput.setRawMode !== "function") {
    throw new Error(NON_TTY_SECRET_ERROR);
  }

  const setRawMode = secretInput.setRawMode;
  const wasRaw = typeof secretInput.isRaw === "boolean" ? secretInput.isRaw : false;
  const previousEncoding = secretInput.readableEncoding;

  return await new Promise<string>((resolveSecret, rejectSecret) => {
    let value = "";
    let settled = false;

    const cleanup = () => {
      secretInput.off("data", onData);
      secretInput.off("error", onError);
      try {
        setRawMode(wasRaw);
      } finally {
        if (previousEncoding) {
          secretInput.setEncoding(previousEncoding);
        }
        secretInput.pause();
      }
    };

    const finish = (error?: Error) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      secretOutput.write("\n");
      if (error) {
        rejectSecret(error);
      } else {
        resolveSecret(value.trim());
      }
    };

    const onError = (error: Error) => {
      finish(error);
    };

    const onData = (chunk: Buffer | string) => {
      const text = chunk.toString("utf8");
      for (const char of text) {
        if (char === "\r" || char === "\n") {
          finish();
          return;
        }
        if (char === "\u0003") {
          finish(new Error("Setup cancelled."));
          return;
        }
        if (char === "\b" || char === "\u007f") {
          value = value.slice(0, -1);
          continue;
        }
        if (char >= " ") {
          value += char;
        }
      }
    };

    secretOutput.write(`${question}: `);
    setRawMode(true);
    secretInput.resume();
    secretInput.setEncoding("utf8");
    secretInput.on("data", onData);
    secretInput.on("error", onError);
  });
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
      const answer = await askText(`${question} [default: ${defaultValue}]: `);
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
      return await readMaskedInput(input, output, question);
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
    existingConfig.provider ??
    DEFAULT_PROVIDER;
  const provider = parseProvider(providerInput);

  const modelInput =
    options.model ??
    existingConfig.model ??
    DEFAULT_MODEL;
  const model = normalizeModel(modelInput);

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
      log(`OpenAI API key saved: ${maskApiKey(providedKey)}`);
    } else if (existingKey) {
      log(`OpenAI API key already found: ${maskApiKey(existingKey)}`);
    } else if (prompt) {
      const apiKey = await prompter.secret("OpenAI API key (input hidden)");
      if (!apiKey) {
        throw new Error("OPENAI_API_KEY is required for the openai provider.");
      }
      upsertDotEnvValues(root, { OPENAI_API_KEY: apiKey });
      log(`OpenAI API key saved: ${maskApiKey(apiKey)}`);
    } else {
      throw new Error(
        "OPENAI_API_KEY is required for the openai provider. Set it in .env, or use --api-key only for automation.",
      );
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
