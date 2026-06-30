import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { loadConfig } from "../config/load";
import { getConfigPath } from "../config/paths";
import { getDoctorConfigStatus } from "../config/status";
import type { SwarmConfig } from "../config/types";
import { runSetup, type SetupPrompter } from "./setup";

const tempRoots: string[] = [];
const originalOpenAiKey = process.env.OPENAI_API_KEY;

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-setup-"));
  tempRoots.push(root);
  return root;
}

function throwingPrompter(): SetupPrompter {
  return {
    async text(): Promise<string> {
      throw new Error("unexpected prompt");
    },
    async secret(): Promise<string> {
      throw new Error("unexpected prompt");
    },
    async confirm(): Promise<boolean> {
      throw new Error("unexpected prompt");
    },
  };
}

function fakeSync(root: string, config: SwarmConfig) {
  return {
    lockfilePath: join(root, config.skills.lockfile),
    lockfile: {
      version: 1 as const,
      source: config.skills.externalRepo,
      commit: "0".repeat(40),
      syncedAt: "2026-06-30T00:00:00.000Z",
      skillsRoot: "skills/external/Anthropic-Cybersecurity-Skills/skills",
      localApprovedRoot: config.skills.localApprovedRoot,
      draftRoot: config.skills.draftRoot,
      rejectedRoot: config.skills.rejectedRoot,
    },
    cloned: false,
    overlayDirs: [],
  };
}

function fakeIndex(root: string, config: SwarmConfig) {
  return {
    indexPath: join(root, config.cacheDir, "skills.index.json"),
    index: {
      version: "0.1.0",
      indexedAt: "2026-06-30T00:00:00.000Z",
      count: 0,
      skills: [],
    },
    skipped: [],
  };
}

beforeEach(() => {
  delete process.env.OPENAI_API_KEY;
});

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }

  if (originalOpenAiKey === undefined) {
    delete process.env.OPENAI_API_KEY;
  } else {
    process.env.OPENAI_API_KEY = originalOpenAiKey;
  }
});

describe("runSetup", () => {
  it("creates .swarm/config.json", async () => {
    const root = makeTempRoot();

    await runSetup(
      {
        provider: "mock",
        model: "gpt-5-mini",
        skipSkillsSync: true,
        skipSkillsIndex: true,
        yes: true,
      },
      root,
      { prompter: throwingPrompter(), log: () => undefined },
    );

    expect(existsSync(getConfigPath(root))).toBe(true);
    expect(loadConfig(root)).toMatchObject({
      provider: "mock",
      model: "gpt-5-mini",
    });
  });

  it("writes OPENAI_API_KEY without printing the raw key", async () => {
    const root = makeTempRoot();
    const lines: string[] = [];
    const apiKey = "sk-test-secret-abcdef1234";

    await runSetup(
      {
        provider: "openai",
        model: "gpt-5-mini",
        apiKey,
        skipSkillsSync: true,
        skipSkillsIndex: true,
        yes: true,
      },
      root,
      { prompter: throwingPrompter(), log: (message) => lines.push(message) },
    );

    expect(readFileSync(join(root, ".env"), "utf8")).toContain(`OPENAI_API_KEY=${apiKey}`);
    expect(lines.join("\n")).not.toContain(apiKey);
    expect(lines.join("\n")).toContain("sk-...1234");
  });

  it("preserves existing .env lines", async () => {
    const root = makeTempRoot();
    writeFileSync(join(root, ".env"), "KEEP_ME=true\nOPENAI_API_KEY=old\n", "utf8");

    await runSetup(
      {
        provider: "openai",
        model: "gpt-5-mini",
        apiKey: "sk-new-secret-9999",
        skipSkillsSync: true,
        skipSkillsIndex: true,
        yes: true,
      },
      root,
      { prompter: throwingPrompter(), log: () => undefined },
    );

    const env = readFileSync(join(root, ".env"), "utf8");
    expect(env).toContain("KEEP_ME=true");
    expect(env).toContain("OPENAI_API_KEY=sk-new-secret-9999");
    expect(env).not.toContain("OPENAI_API_KEY=old");
  });

  it("can skip skills sync and index", async () => {
    const root = makeTempRoot();
    let syncCalls = 0;
    let indexCalls = 0;

    await runSetup(
      {
        provider: "mock",
        model: "gpt-5-mini",
        skipSkillsSync: true,
        skipSkillsIndex: true,
        yes: true,
      },
      root,
      {
        prompter: throwingPrompter(),
        log: () => undefined,
        sync: (...args) => {
          syncCalls += 1;
          return fakeSync(...args);
        },
        index: (...args) => {
          indexCalls += 1;
          return fakeIndex(...args);
        },
      },
    );

    expect(syncCalls).toBe(0);
    expect(indexCalls).toBe(0);
  });

  it("can run non-interactively with --yes", async () => {
    const root = makeTempRoot();
    let syncCalls = 0;
    let indexCalls = 0;

    await runSetup(
      {
        provider: "openai",
        model: "gpt-5-mini",
        apiKey: "sk-noninteractive-1234",
        yes: true,
      },
      root,
      {
        prompter: throwingPrompter(),
        log: () => undefined,
        sync: (...args) => {
          syncCalls += 1;
          return fakeSync(...args);
        },
        index: (...args) => {
          indexCalls += 1;
          return fakeIndex(...args);
        },
      },
    );

    expect(syncCalls).toBe(1);
    expect(indexCalls).toBe(1);
  });

  it("doctor sees configured provider, model, and key after setup", async () => {
    const root = makeTempRoot();

    await runSetup(
      {
        provider: "openai",
        model: "gpt-5-mini",
        apiKey: "sk-doctor-secret-1234",
        skipSkillsSync: true,
        skipSkillsIndex: true,
        yes: true,
      },
      root,
      { prompter: throwingPrompter(), log: () => undefined },
    );

    expect(getDoctorConfigStatus(root).provider).toMatchObject({
      provider: "openai",
      model: "gpt-5-mini",
      openaiKeyPresent: true,
    });
  });
});
