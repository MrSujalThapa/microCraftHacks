import { resolve } from "node:path";

import { loadConfig } from "../config/load";
import { printCliError } from "./errors";
import { buildSkillsIndex, printSkillsList, readSkillsIndex } from "../skills/indexer";
import { syncSkills } from "../skills/sync";

export function runSkillsSyncCommand(options: { repo?: string; ref?: string } = {}): void {
  const root = resolve(process.cwd());
  const config = loadConfig(root);

  const result = syncSkills(root, config, {
    repoUrl: options.repo,
    ref: options.ref,
  });

  console.log("Skills sync complete.");
  if (result.cloned) {
    console.log("Cloned external skills repo.");
  } else {
    console.log("External skills repo already present — skipped clone.");
  }
  if (result.overlayDirs.length > 0) {
    console.log(`Created overlay folders: ${result.overlayDirs.join(", ")}`);
  }
  console.log(`Lockfile: ${result.lockfilePath}`);
  console.log(`Commit: ${result.lockfile.commit}`);
  console.log(`Skills root: ${result.lockfile.skillsRoot}`);
}

export function runSkillsIndexCommand(): void {
  const root = resolve(process.cwd());
  const config = loadConfig(root);

  const result = buildSkillsIndex(root, config);

  console.log("Skills index complete.");
  console.log(`Indexed: ${result.index.count} skills`);
  for (const warning of result.skipped) {
    console.warn(`Warning: ${warning}`);
  }
  console.log(`Index: ${result.indexPath}`);
}

export function runSkillsListCommand(): void {
  const root = resolve(process.cwd());
  const config = loadConfig(root);

  const index = readSkillsIndex(root, config);
  printSkillsList(index);
}

export function runSkillsCommand(action: () => void): void {
  try {
    action();
  } catch (error) {
    printCliError(error);
    process.exitCode = 1;
  }
}
