import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

const DEFAULT_RUNTIME_ROOT = "agent_runtime";
const DEFAULT_PYTHON_COMMAND = "python";
const DEFAULT_ROUTED_SKILLS_RELATIVE = join(".swarm", "cache", "routed-skills.json");

export interface AgentRunOptions {
  reportPath: string;
  routedSkillsPath?: string;
  outputPath?: string;
  root?: string;
  pythonCommand?: string;
  runtimeRoot?: string;
}

export interface AgentRunResult {
  outputPath: string;
  exitCode: number;
  stdout: string;
  stderr: string;
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

export function runAgentRuntime(options: AgentRunOptions): AgentRunResult {
  const root = resolve(options.root ?? process.cwd());
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
    ],
    {
      cwd: paths.runtimeRoot,
      encoding: "utf8",
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
  };
}
