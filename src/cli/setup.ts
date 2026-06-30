import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { emitKeypressEvents } from "node:readline";
import { stdin as input, stdout as output } from "node:process";
import { dirname, join, resolve } from "node:path";

import { loadDotEnv, upsertDotEnvValues } from "../config/env";
import { createDefaultConfig } from "../config/defaults";
import { loadConfig, tryLoadConfig } from "../config/load";
import { getConfigPath, getManagedDirectories } from "../config/paths";
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

const RAW_MODE_SECRET_ERROR =
  "This terminal cannot enable hidden API key input. Set OPENAI_API_KEY in .env, or use --api-key only for automation.";

export interface SetupOptions {
  provider?: string;
  model?: string;
  apiKey?: string;
  skipSkillsSync?: boolean;
  skipSkillsIndex?: boolean;
  editor?: boolean;
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
  openEditor?: (root: string, envPath: string) => void;
}

interface SecretInput {
  isTTY?: boolean;
  isRaw?: boolean;
  readableEncoding?: BufferEncoding | null;
  setRawMode?: (mode: boolean) => unknown;
  resume: () => unknown;
  pause: () => unknown;
  on: {
    (event: "keypress", listener: (text: string, key: KeypressInfo) => void): unknown;
    (event: "error", listener: (error: Error) => void): unknown;
  };
  off: {
    (event: "keypress", listener: (text: string, key: KeypressInfo) => void): unknown;
    (event: "error", listener: (error: Error) => void): unknown;
  };
}

interface SecretOutput {
  isTTY?: boolean;
  write: (chunk: string) => unknown;
}

interface KeypressInfo {
  name?: string;
  ctrl?: boolean;
  sequence?: string;
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
  const configPath = getConfigPath(root);
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function ensureManagedDirectories(root: string, config: SwarmConfig): void {
  for (const relativePath of getManagedDirectories(config)) {
    mkdirSync(join(root, relativePath), { recursive: true });
  }
}

function readDotEnvValue(root: string, keyName: string): string | undefined {
  const envPath = join(root, ".env");
  if (!existsSync(envPath)) {
    return undefined;
  }

  const content = readFileSync(envPath, "utf8");
  for (const rawLine of content.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const separator = line.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const key = line.slice(0, separator).trim();
    if (key !== keyName) {
      continue;
    }
    let value = line.slice(separator + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    return value || undefined;
  }
  return undefined;
}

function ensureEnvForEditor(root: string): string {
  const envPath = join(root, ".env");
  if (!existsSync(envPath)) {
    writeFileSync(envPath, "OPENAI_API_KEY=\n", "utf8");
    return envPath;
  }

  const content = readFileSync(envPath, "utf8");
  const hasOpenAiKey = content
    .split(/\r?\n/u)
    .some((line) => line.trim().startsWith("OPENAI_API_KEY="));
  if (!hasOpenAiKey) {
    const prefix = content.length > 0 && !/\r?\n$/u.test(content) ? "\n" : "";
    writeFileSync(envPath, `${content}${prefix}OPENAI_API_KEY=\n`, "utf8");
  }
  return envPath;
}

export function getDefaultEditorCommand(): { command: string; args: string[] } {
  if (process.platform === "win32") {
    return { command: "notepad", args: [] };
  }
  const editor = process.env.VISUAL || process.env.EDITOR || "vi";
  return { command: editor, args: [] };
}

function openEnvEditor(root: string, envPath: string): void {
  const editor = getDefaultEditorCommand();
  const result = spawnSync(editor.command, [...editor.args, envPath], {
    cwd: root,
    stdio: "inherit",
    shell: process.platform === "win32",
  });

  if (result.error) {
    throw new Error(`Failed to open editor: ${result.error.message}`);
  }
  if (typeof result.status === "number" && result.status !== 0) {
    throw new Error(`Editor exited with code ${result.status}`);
  }
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
  let rawModeEnabled = false;

  return await new Promise<string>((resolveSecret, rejectSecret) => {
    let value = "";
    let settled = false;

    const cleanup = () => {
      secretInput.off("keypress", onKeypress);
      secretInput.off("error", onError);
      if (rawModeEnabled) {
        try {
          setRawMode(wasRaw);
        } catch {
          /* terminal is already leaving setup; keep original error/result */
        }
      }
      secretInput.pause();
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

    const onKeypress = (text: string, key: KeypressInfo) => {
      if (key.ctrl && key.name === "c") {
        finish(new Error("Setup cancelled."));
        return;
      }
      if (key.name === "return" || key.name === "enter") {
        finish();
        return;
      }
      if (key.name === "backspace") {
        value = value.slice(0, -1);
        return;
      }
      if (text && text >= " " && !key.ctrl) {
        value += text;
      }
    };

    secretOutput.write(`${question}: `);
    try {
      emitKeypressEvents(secretInput as NodeJS.ReadableStream);
      secretInput.resume();
      setRawMode(true);
      rawModeEnabled = true;
      secretInput.on("keypress", onKeypress);
      secretInput.on("error", onError);
    } catch {
      cleanup();
      secretOutput.write("\n");
      rejectSecret(new Error(RAW_MODE_SECRET_ERROR));
    }
  });
}

async function collectOpenAiKey(
  root: string,
  options: SetupOptions,
  prompter: SetupPrompter,
  log: (message: string) => void,
  openEditor: (root: string, envPath: string) => void,
  prompt: boolean,
): Promise<{ key?: string; source: "provided" | "existing" | "entered" | "editor" | "missing" }> {
  const providedKey = options.apiKey?.trim();
  if (providedKey) {
    return { key: providedKey, source: "provided" };
  }

  const existingKey = getOpenAiKeyFromEnvironment(root);
  if (existingKey) {
    if (!prompt) {
      return { key: existingKey, source: "existing" };
    }
    log(`OpenAI API key found: ${maskApiKey(existingKey)}`);
    const keepExisting = await prompter.confirm("Keep existing OpenAI API key", true);
    if (keepExisting) {
      return { key: existingKey, source: "existing" };
    }
  }

  if (!prompt) {
    return { source: "missing" };
  }

  if (!options.editor) {
    try {
      const enteredKey = await prompter.secret("OpenAI API key (input hidden)");
      if (enteredKey) {
        return { key: enteredKey, source: "entered" };
      }
    } catch (error) {
      if (!(error instanceof Error) || (!error.message.includes("hidden API key input") && !error.message.includes("hidden input"))) {
        throw error;
      }
    }
  }

  log("Hidden input is unavailable in this terminal.");
  log("Opening .env in your editor so you can paste the key safely.");
  const envPath = ensureEnvForEditor(root);
  openEditor(root, envPath);

  delete process.env.OPENAI_API_KEY;
  const editedKey = readDotEnvValue(root, "OPENAI_API_KEY") ?? getOpenAiKeyFromEnvironment(root);
  if (!editedKey) {
    throw new Error("OPENAI_API_KEY was not found in .env after editor closed.");
  }
  process.env.OPENAI_API_KEY = editedKey;
  return { key: editedKey, source: "editor" };
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
  const openEditor = dependencies.openEditor ?? openEnvEditor;
  const prompt = shouldPrompt(options);

  if (prompt) {
    log("Cyber Swarm setup");
    log("Press Enter to accept defaults.");
  }

  const configPath = getConfigPath(root);
  const configExists = existsSync(configPath);
  const existingConfig = tryLoadConfig(root) ?? createDefaultConfig(root);
  const providerInput =
    options.provider ??
    (prompt ? await prompter.text("Provider", existingConfig.provider || DEFAULT_PROVIDER) : undefined) ??
    existingConfig.provider ??
    DEFAULT_PROVIDER;
  const provider = parseProvider(providerInput);

  const modelInput =
    options.model ??
    (prompt ? await prompter.text("Model", existingConfig.model || DEFAULT_MODEL) : undefined) ??
    existingConfig.model ??
    DEFAULT_MODEL;
  const model = normalizeModel(modelInput);

  const keyResult =
    provider === "openai"
      ? await collectOpenAiKey(root, options, prompter, log, openEditor, prompt)
      : { source: "missing" as const };

  if (provider === "openai" && !keyResult.key) {
    throw new Error(
      "OPENAI_API_KEY is required for the openai provider. Set it in .env, or pass --api-key for CI/automation.",
    );
  }

  const config: SwarmConfig = {
    ...existingConfig,
    provider,
    model,
  };
  writeConfig(config, root);
  ensureManagedDirectories(root, config);
  log(configExists ? "Using existing .swarm/config.json" : "Created .swarm/config.json");
  log(`Configured provider: ${provider}`);
  log(`Configured model: ${model}`);

  ensureGitIgnoreContainsEnv(root, log);

  if (provider === "openai") {
    if (keyResult.source === "provided" || keyResult.source === "entered") {
      upsertDotEnvValues(root, { OPENAI_API_KEY: keyResult.key });
    }
    log("OpenAI API key: found");
  } else if (options.apiKey?.trim()) {
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
