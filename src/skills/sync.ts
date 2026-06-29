import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { SwarmConfig } from "../config/types";
import { SkillsError } from "./errors";
import { cloneRepo, resolveHeadCommit } from "./git";
import { getExternalRepoPath, getExternalSkillsRoot, getLockfilePath } from "./paths";
import type { SkillsLockfile, SyncResult } from "./types";

function ensureOverlayDirectories(root: string, config: SwarmConfig): string[] {
  const overlayDirs = [
    config.skills.localApprovedRoot,
    config.skills.draftRoot,
    config.skills.rejectedRoot,
  ];
  const created: string[] = [];

  for (const relativePath of overlayDirs) {
    const target = join(root, relativePath);
    if (!existsSync(target)) {
      mkdirSync(target, { recursive: true });
      created.push(relativePath);
    }
  }

  return created;
}

export function writeSkillsLockfile(
  root: string,
  config: SwarmConfig,
  lockfile: SkillsLockfile,
): string {
  const lockfilePath = getLockfilePath(root, config);
  mkdirSync(join(root, ".swarm"), { recursive: true });
  writeFileSync(lockfilePath, `${JSON.stringify(lockfile, null, 2)}\n`, "utf8");
  return lockfilePath;
}

export function readSkillsLockfile(root: string, config: SwarmConfig): SkillsLockfile | null {
  const lockfilePath = getLockfilePath(root, config);
  if (!existsSync(lockfilePath)) {
    return null;
  }

  return JSON.parse(readFileSync(lockfilePath, "utf8")) as SkillsLockfile;
}

export interface SyncOptions {
  repoUrl?: string;
  ref?: string;
}

export function syncSkills(root: string, config: SwarmConfig, options: SyncOptions = {}): SyncResult {
  const repoUrl = options.repoUrl ?? config.skills.externalRepo;
  const ref = options.ref ?? config.skills.externalRef;
  const repoPath = getExternalRepoPath(root);
  const skillsRootRelative = join("skills/external", "Anthropic-Cybersecurity-Skills", "skills").replace(
    /\\/g,
    "/",
  );

  let cloned = false;

  if (!existsSync(join(repoPath, ".git"))) {
    try {
      mkdirSync(join(root, "skills/external"), { recursive: true });
      cloneRepo(repoUrl, repoPath, ref);
      cloned = true;
    } catch (error) {
      const detail = error instanceof Error ? error.message : "git clone failed";
      throw new SkillsError(`Failed to clone skills repo: ${detail}`, "SYNC_FAILED");
    }
  }

  let commit: string;
  try {
    commit = resolveHeadCommit(repoPath);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "git rev-parse failed";
    throw new SkillsError(`Failed to read skills repo commit: ${detail}`, "SYNC_FAILED");
  }

  const overlayDirs = ensureOverlayDirectories(root, config);

  const lockfile: SkillsLockfile = {
    version: 1,
    source: repoUrl,
    commit,
    syncedAt: new Date().toISOString(),
    skillsRoot: skillsRootRelative,
    localApprovedRoot: config.skills.localApprovedRoot,
    draftRoot: config.skills.draftRoot,
    rejectedRoot: config.skills.rejectedRoot,
  };

  const lockfilePath = writeSkillsLockfile(root, config, lockfile);

  return {
    lockfilePath,
    lockfile,
    cloned,
    overlayDirs,
  };
}

export function resolveSkillsRoot(root: string, config: SwarmConfig): string {
  const lockfile = readSkillsLockfile(root, config);
  if (lockfile?.skillsRoot) {
    return join(root, lockfile.skillsRoot);
  }
  return getExternalSkillsRoot(root);
}
