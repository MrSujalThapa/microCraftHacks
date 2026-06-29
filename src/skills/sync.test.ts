import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createDefaultConfig } from "../config/defaults";
import { runGit } from "./git";
import { getExternalRepoPath } from "./paths";
import { readSkillsLockfile, syncSkills } from "./sync";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-skills-sync-"));
  tempRoots.push(root);
  return root;
}

function initBareRepoWithCommit(): string {
  const repo = makeTempRoot();
  writeFileSync(join(repo, "README.md"), "# skills\n", "utf8");
  mkdirSync(join(repo, "skills", "example"), { recursive: true });
  writeFileSync(join(repo, "skills", "example", "SKILL.md"), "---\nname: example\n---\n", "utf8");
  runGit(["init"], repo);
  runGit(["add", "."], repo);
  runGit(["commit", "-m", "init"], repo);
  return repo;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("syncSkills", () => {
  it("clones external repo and writes lockfile", () => {
    const root = makeTempRoot();
    const bareRepo = initBareRepoWithCommit();
    const config = createDefaultConfig(root);

    const result = syncSkills(root, config, { repoUrl: bareRepo });

    expect(result.cloned).toBe(true);
    expect(existsSync(getExternalRepoPath(root))).toBe(true);
    expect(existsSync(join(root, config.skills.localApprovedRoot))).toBe(true);
    expect(existsSync(join(root, config.skills.draftRoot))).toBe(true);
    expect(existsSync(join(root, config.skills.rejectedRoot))).toBe(true);

    const lockfile = readSkillsLockfile(root, config);
    expect(lockfile).toMatchObject({
      version: 1,
      source: bareRepo,
      skillsRoot: "skills/external/Anthropic-Cybersecurity-Skills/skills",
    });
    expect(lockfile?.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(lockfile?.syncedAt).toBeTruthy();

    expect(readFileSync(result.lockfilePath, "utf8")).toContain('"skillsRoot"');
  });

  it("is idempotent and does not reclone when repo exists", () => {
    const root = makeTempRoot();
    const bareRepo = initBareRepoWithCommit();
    const config = createDefaultConfig(root);

    const first = syncSkills(root, config, { repoUrl: bareRepo });
    writeFileSync(join(getExternalRepoPath(root), "marker.txt"), "keep\n", "utf8");

    const second = syncSkills(root, config, { repoUrl: bareRepo });

    expect(first.cloned).toBe(true);
    expect(second.cloned).toBe(false);
    expect(existsSync(join(getExternalRepoPath(root), "marker.txt"))).toBe(true);
  });
});
