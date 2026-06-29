import { join } from "node:path";

export const CONFIG_RELATIVE_PATH = join(".swarm", "config.json");

export const DEFAULT_PATHS = {
  skillsExternal: "skills/external",
  skillsLocalApproved: "skills/local-approved",
  skillsDrafts: "skills/drafts",
  skillsRejected: "skills/rejected",
  cache: ".swarm/cache",
  reports: ".swarm/reports",
  lockfile: ".swarm/skills.lock.json",
} as const;

export function getConfigPath(root = process.cwd()): string {
  return join(root, CONFIG_RELATIVE_PATH);
}

export function getManagedDirectories(config: {
  skills: Pick<
    import("./types").SkillsConfig,
    "externalRoot" | "localApprovedRoot" | "draftRoot" | "rejectedRoot"
  >;
  cacheDir: string;
  outputDir: string;
}): string[] {
  return [
    config.skills.externalRoot,
    config.skills.localApprovedRoot,
    config.skills.draftRoot,
    config.skills.rejectedRoot,
    config.cacheDir,
    config.outputDir,
  ];
}
