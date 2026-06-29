import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createDefaultConfig } from "./defaults";
import { ConfigError } from "./errors";
import { initProject } from "./init";
import { loadConfig } from "./load";
import { DEFAULT_PATHS, getConfigPath, getManagedDirectories } from "./paths";
import { validateConfig } from "./validate";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-config-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("createDefaultConfig", () => {
  it("uses safe defaults and expected paths", () => {
    const root = makeTempRoot();
    const config = createDefaultConfig(root);

    expect(config.mode).toBe("static");
    expect(config.provider).toBe("openai");
    expect(config.model).toBe("gpt-5-mini");
    expect(config.riskLevel).toBe("passive");
    expect(config.skills.externalRoot).toBe(DEFAULT_PATHS.skillsExternal);
    expect(config.skills.localApprovedRoot).toBe(DEFAULT_PATHS.skillsLocalApproved);
    expect(config.skills.draftRoot).toBe(DEFAULT_PATHS.skillsDrafts);
    expect(config.skills.rejectedRoot).toBe(DEFAULT_PATHS.skillsRejected);
    expect(config.cacheDir).toBe(DEFAULT_PATHS.cache);
    expect(config.outputDir).toBe(DEFAULT_PATHS.reports);
  });
});

describe("initProject", () => {
  it("creates config and managed folders on first run", () => {
    const root = makeTempRoot();
    const result = initProject(root);

    expect(result.configCreated).toBe(true);
    expect(readFileSync(getConfigPath(root), "utf8")).toContain('"riskLevel": "passive"');

    for (const dir of getManagedDirectories(createDefaultConfig(root))) {
      expect(existsSync(join(root, dir))).toBe(true);
    }
  });

  it("does not overwrite existing config on re-run", () => {
    const root = makeTempRoot();
    initProject(root);

    writeFileSync(getConfigPath(root), '{"broken": true}\n', "utf8");

    const result = initProject(root);
    expect(result.configCreated).toBe(false);
    expect(readFileSync(getConfigPath(root), "utf8")).toBe('{"broken": true}\n');
  });
});

describe("loadConfig", () => {
  it("throws a missing-config error with init guidance", () => {
    const root = makeTempRoot();

    expect(() => loadConfig(root)).toThrow(ConfigError);
    try {
      loadConfig(root);
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as ConfigError).code).toBe("MISSING");
      expect((error as ConfigError).message).toContain("Config not found");
    }
  });

  it("throws an invalid-config error for malformed JSON", () => {
    const root = makeTempRoot();
    initProject(root);
    writeFileSync(getConfigPath(root), "{not-json", "utf8");

    expect(() => loadConfig(root)).toThrow(ConfigError);
    try {
      loadConfig(root);
    } catch (error) {
      expect((error as ConfigError).code).toBe("PARSE");
    }
  });

  it("throws an invalid-config error for schema violations", () => {
    const root = makeTempRoot();
    initProject(root);
    writeFileSync(
      getConfigPath(root),
      `${JSON.stringify({ ...createDefaultConfig(root), provider: "bad-provider" })}\n`,
      "utf8",
    );

    expect(() => loadConfig(root)).toThrow(ConfigError);
    try {
      loadConfig(root);
    } catch (error) {
      expect((error as ConfigError).code).toBe("INVALID");
      expect((error as ConfigError).message).toContain("provider must be one of");
    }
  });
});

describe("validateConfig", () => {
  it("accepts the default config shape", () => {
    const root = makeTempRoot();
    expect(validateConfig(createDefaultConfig(root))).toMatchObject({
      provider: "openai",
      riskLevel: "passive",
    });
  });
});
