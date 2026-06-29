import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

import { loadDotEnv } from "../config/env";
import { assertProviderReady, resolveProvider } from "../config/provider";
import type { SwarmProvider } from "../config/types";

const DEFAULT_RUNTIME_ROOT = "agent_runtime";
const DEFAULT_PYTHON_COMMAND = "python";
const DEFAULT_ROUTED_SKILLS_RELATIVE = join(".swarm", "cache", "routed-skills.json");

export interface AgentRunOptions {
  reportPath: string;
  routedSkillsPath?: string;
  outputPath?: string;
  provider?: SwarmProvider;
  model?: string;
  mode?: string;
  fromCache?: boolean;
  root?: string;
  pythonCommand?: string;
  runtimeRoot?: string;
}

export interface AgentRunResult {
  outputPath: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  provider: SwarmProvider;
  model: string;
  runtimeMetrics?: {
    elapsedMs?: number;
    providerCalls?: Array<Record<string, unknown>>;
    mode?: string;
    cache?: {
      scanHash?: string;
      hit?: boolean;
    };
  };
}

export class AgentRuntimeError extends Error {
  constructor(
    message: string,
    readonly exitCode: number,
    readonly stdout: string,
    readonly stderr: string,
  ) {
    super(message);
    this.name = "AgentRuntimeError";
  }
}

export function deriveFindingsOutputPath(reportPath: string): string {
  const base = basename(reportPath, ".json");
  return join(dirname(reportPath), `${base}-findings.json`);
}

export function resolveAgentRuntimePaths(
  root: string,
  options: AgentRunOptions,
): {
  runtimeRoot: string;
  reportPath: string;
  routedSkillsPath: string;
  outputPath: string;
} {
  const reportPath = resolve(root, options.reportPath);
  const routedSkillsPath = resolve(
    root,
    options.routedSkillsPath ?? DEFAULT_ROUTED_SKILLS_RELATIVE,
  );
  const outputPath = resolve(root, options.outputPath ?? deriveFindingsOutputPath(reportPath));

  return {
    runtimeRoot: resolve(root, options.runtimeRoot ?? DEFAULT_RUNTIME_ROOT),
    reportPath,
    routedSkillsPath,
    outputPath,
  };
}

function readRuntimeMetrics(outputPath: string): AgentRunResult["runtimeMetrics"] {
  try {
    const payload = JSON.parse(readFileSync(outputPath, "utf8")) as {
      metrics?: {
        runtime?: {
          elapsedMs?: number;
          providerCalls?: Array<Record<string, unknown>>;
          mode?: string;
          cache?: {
            scanHash?: string;
            hit?: boolean;
          };
        };
      };
    };
    return payload.metrics?.runtime;
  } catch {
    return undefined;
  }
}

export function runAgentRuntime(options: AgentRunOptions): AgentRunResult {
  const root = resolve(options.root ?? process.cwd());
  loadDotEnv(root);
  const resolvedProvider = resolveProvider(root, {
    provider: options.provider,
    model: options.model,
  });
  assertProviderReady(resolvedProvider);

  const pythonCommand = options.pythonCommand ?? DEFAULT_PYTHON_COMMAND;
  const paths = resolveAgentRuntimePaths(root, options);

  if (!existsSync(paths.runtimeRoot)) {
    throw new AgentRuntimeError(
      `Python runtime root not found: ${paths.runtimeRoot}`,
      1,
      "",
      "",
    );
  }

  if (!existsSync(paths.reportPath)) {
    throw new AgentRuntimeError(`Scan report not found: ${paths.reportPath}`, 1, "", "");
  }

  if (!existsSync(paths.routedSkillsPath)) {
    throw new AgentRuntimeError(
      `Routed skills file not found: ${paths.routedSkillsPath}`,
      1,
      "",
      "",
    );
  }

  const spawnEnv = { ...process.env };
  if (resolvedProvider.provider === "openai" && process.env.OPENAI_API_KEY) {
    spawnEnv.OPENAI_API_KEY = process.env.OPENAI_API_KEY;
  }

  const mode = options.mode ?? "full";
  const fromCache = options.fromCache ?? false;
  const demoMode = mode === "demo" || mode === "fast";
  const maxSelectedContext = demoMode ? "4" : "8";
  const maxDraftFindings = demoMode ? "2" : "3";

  const result = spawnSync(
    pythonCommand,
    [
      "-m",
      "cyber_swarm.runner",
      "--scan-report",
      paths.reportPath,
      "--routed-skills",
      paths.routedSkillsPath,
      "--output",
      paths.outputPath,
      "--provider",
      resolvedProvider.provider,
      "--model",
      resolvedProvider.model,
      "--max-selected-context",
      maxSelectedContext,
      "--max-draft-findings",
      maxDraftFindings,
      "--call-timeout",
      "60",
      "--mode",
      mode,
      ...(fromCache ? ["--from-cache"] : []),
    ],
    {
      cwd: paths.runtimeRoot,
      encoding: "utf8",
      env: spawnEnv,
    },
  );

  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  const exitCode = result.status ?? 1;

  if (exitCode !== 0) {
    throw new AgentRuntimeError(
      `Python agent runtime failed with exit code ${exitCode}`,
      exitCode,
      stdout,
      stderr,
    );
  }

  if (!existsSync(paths.outputPath)) {
    throw new AgentRuntimeError(
      `Python agent runtime did not write output: ${paths.outputPath}`,
      exitCode,
      stdout,
      stderr,
    );
  }

  return {
    outputPath: paths.outputPath,
    exitCode,
    stdout,
    stderr,
    provider: resolvedProvider.provider,
    model: resolvedProvider.model,
    runtimeMetrics: readRuntimeMetrics(paths.outputPath),
  };
}
