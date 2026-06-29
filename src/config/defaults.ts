import { basename } from "node:path";

import { DEFAULT_PATHS } from "./paths";
import type { SwarmConfig } from "./types";

export function createDefaultConfig(root = process.cwd()): SwarmConfig {
  return {
    projectName: basename(root),
    mode: "static",
    provider: "openai",
    model: "gpt-5-mini",
    riskLevel: "passive",
    allowedTargets: [{ type: "local" }],
    appCommand: null,
    appUrl: null,
    skills: {
      externalRepo: "https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git",
      externalRoot: DEFAULT_PATHS.skillsExternal,
      localApprovedRoot: DEFAULT_PATHS.skillsLocalApproved,
      draftRoot: DEFAULT_PATHS.skillsDrafts,
      rejectedRoot: DEFAULT_PATHS.skillsRejected,
      lockfile: DEFAULT_PATHS.lockfile,
      autoReindex: true,
    },
    cacheDir: DEFAULT_PATHS.cache,
    outputDir: DEFAULT_PATHS.reports,
  };
}
