import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createDefaultConfig } from "../config/defaults";
import { buildSkillsIndex, readSkillsIndex } from "./indexer";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-skills-index-"));
  tempRoots.push(root);
  return root;
}

function writeSkill(dir: string, name: string, frontmatter: string, body = "# Skill\n"): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "SKILL.md"), `---\n${frontmatter}\n---\n${body}`, "utf8");
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("buildSkillsIndex", () => {
  it("indexes external and local-approved skills from frontmatter only", () => {
    const root = makeTempRoot();
    const config = createDefaultConfig(root);

    writeSkill(
      join(root, "skills/external/Anthropic-Cybersecurity-Skills/skills/auth"),
      "auth-skill",
      "name: auth-skill\ndescription: Auth checks\ntags: [auth]",
    );
    writeSkill(
      join(root, config.skills.localApprovedRoot, "custom"),
      "local-skill",
      "name: local-skill\ndescription: Local overlay\ntags: [api]",
    );
    writeSkill(
      join(root, "skills/external/Anthropic-Cybersecurity-Skills/skills/broken"),
      "broken",
      "description: missing name",
    );

    const result = buildSkillsIndex(root, config);

    expect(result.index.count).toBe(2);
    expect(result.index.skills.map((s) => s.name)).toEqual(["auth-skill", "local-skill"]);
    expect(existsSync(result.indexPath)).toBe(true);
    expect(result.skipped.length).toBe(1);
    expect(result.skipped[0]).toContain("malformed");

    const cached = readSkillsIndex(root, config);
    expect(cached.count).toBe(2);
  });

  it("writes compact index without skill bodies", () => {
    const root = makeTempRoot();
    const config = createDefaultConfig(root);

    writeSkill(
      join(root, "skills/external/Anthropic-Cybersecurity-Skills/skills/demo"),
      "demo",
      "name: demo-skill\ndescription: Demo",
      "Sensitive full body content should not appear in index.",
    );

    const result = buildSkillsIndex(root, config);
    const raw = readFileSync(result.indexPath, "utf8");
    expect(raw).not.toContain("Sensitive full body");
    expect(result.index.skills[0].description).toBe("Demo");
  });
});
