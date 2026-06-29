import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

import type { SwarmConfig } from "../config/types";
import { getPackageVersion } from "../shared/version";
import { SkillsError } from "./errors";
import { parseSkillFrontmatter } from "./frontmatter";
import { getSkillsIndexPath } from "./paths";
import { readSkillsLockfile, resolveSkillsRoot } from "./sync";
import type { IndexResult, SkillIndexEntry, SkillsIndex } from "./types";

function walkSkillFiles(rootDir: string): string[] {
  const files: string[] = [];

  function walk(current: string): void {
    if (!existsSync(current)) {
      return;
    }

    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && entry.name === "SKILL.md") {
        files.push(fullPath);
      }
    }
  }

  walk(rootDir);
  return files.sort((a, b) => a.localeCompare(b));
}

function indexSkillFile(
  projectRoot: string,
  filePath: string,
  sourceType: SkillIndexEntry["sourceType"],
): { entry: SkillIndexEntry | null; warning?: string } {
  const content = readFileSync(filePath, "utf8");
  const frontmatter = parseSkillFrontmatter(content);

  if (!frontmatter) {
    return {
      entry: null,
      warning: `Skipped malformed skill (missing frontmatter): ${relative(projectRoot, filePath).replace(/\\/g, "/")}`,
    };
  }

  return {
    entry: {
      ...frontmatter,
      path: relative(projectRoot, filePath).replace(/\\/g, "/"),
      sourceType,
    },
  };
}

export function buildSkillsIndex(root: string, config: SwarmConfig): IndexResult {
  const lockfile = readSkillsLockfile(root, config);
  const externalRoot = lockfile ? join(root, lockfile.skillsRoot) : resolveSkillsRoot(root, config);
  const localRoot = join(root, config.skills.localApprovedRoot);

  const skipped: string[] = [];
  const skills: SkillIndexEntry[] = [];

  const sources: Array<{ dir: string; sourceType: SkillIndexEntry["sourceType"] }> = [
    { dir: externalRoot, sourceType: "external" },
    { dir: localRoot, sourceType: "local-approved" },
  ];

  for (const source of sources) {
    for (const filePath of walkSkillFiles(source.dir)) {
      const result = indexSkillFile(root, filePath, source.sourceType);
      if (result.entry) {
        skills.push(result.entry);
      } else if (result.warning) {
        skipped.push(result.warning);
      }
    }
  }

  skills.sort((a, b) => a.name.localeCompare(b.name));

  const index: SkillsIndex = {
    version: getPackageVersion(),
    indexedAt: new Date().toISOString(),
    count: skills.length,
    skills,
  };

  const indexPath = getSkillsIndexPath(root, config);
  mkdirSync(join(root, config.cacheDir), { recursive: true });
  writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8");

  return { indexPath, index, skipped };
}

export function readSkillsIndex(root: string, config: SwarmConfig): SkillsIndex {
  const indexPath = getSkillsIndexPath(root, config);
  if (!existsSync(indexPath)) {
    throw new SkillsError(
      `Skills index not found at ${indexPath}. Run ` + "`swarm skills index`" + ` first.`,
      "MISSING_INDEX",
    );
  }

  return JSON.parse(readFileSync(indexPath, "utf8")) as SkillsIndex;
}

export function printSkillsList(index: SkillsIndex, limit = 10): void {
  console.log(`Skills indexed: ${index.count}`);
  if (index.count === 0) {
    console.log("No skills found. Run `swarm skills sync` then `swarm skills index`.");
    return;
  }

  const top = index.skills.slice(0, limit);
  console.log(`Top ${top.length} skills:`);
  for (const skill of top) {
    const tags = skill.tags.length > 0 ? ` [${skill.tags.join(", ")}]` : "";
    console.log(`  ${skill.name} (${skill.sourceType})${tags}`);
  }
  if (index.count > limit) {
    console.log(`  … and ${index.count - limit} more`);
  }
}
