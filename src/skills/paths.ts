import { join } from "node:path";

import type { SwarmConfig } from "../config/types";

export const EXTERNAL_REPO_DIR_NAME = "Anthropic-Cybersecurity-Skills";

export function getExternalRepoPath(root: string): string {
  return join(root, "skills/external", EXTERNAL_REPO_DIR_NAME);
}

export function getExternalSkillsRoot(root: string): string {
  return join(getExternalRepoPath(root), "skills");
}

export function getSkillsIndexPath(root: string, config: SwarmConfig): string {
  return join(root, config.cacheDir, "skills-index.json");
}

export function getRoutedSkillsPath(root: string, config: SwarmConfig): string {
  return join(root, config.cacheDir, "routed-skills.json");
}

export function getLockfilePath(root: string, config: SwarmConfig): string {
  return join(root, config.skills.lockfile);
}
