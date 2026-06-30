import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { loadConfig } from "../config/load";
import { getConfigPath } from "../config/paths";
import { getDoctorConfigStatus } from "../config/status";
import type { SwarmConfig } from "../config/types";
import { getDefaultEditorCommand, readMaskedInput, runSetup, type SetupPrompter } from "./setup";

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

function interactivePrompter(apiKey: string): SetupPrompter {
  return {
    async text(_question: string, defaultValue: string): Promise<string> {
      return defaultValue;
    },
    async secret(): Promise<string> {
      return apiKey;
    },
    async confirm(): Promise<boolean> {
      return false;
    },
  };
}

function editorFallbackPrompter(): SetupPrompter {
  return {
    async text(_question: string, defaultValue: string): Promise<string> {
      return defaultValue;
    },
    async secret(): Promise<string> {
      throw new Error("This terminal cannot enable hidden API key input.");
    },
    async confirm(): Promise<boolean> {
      return false;
    },
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
    expect(lines.join("\n")).toContain("OpenAI API key: found");
  });

  it("interactive setup does not write the raw key to output", async () => {
    const root = makeTempRoot();
    const outputLines: string[] = [];
    const warningLines: string[] = [];
    const apiKey = "sk-interactive-secret-1234";

    await runSetup(
      {
        provider: "openai",
        model: "gpt-5-mini",
      },
      root,
      {
        prompter: interactivePrompter(apiKey),
        log: (message) => outputLines.push(message),
        warn: (message) => warningLines.push(message),
      },
    );

    expect(readFileSync(join(root, ".env"), "utf8")).toContain(`OPENAI_API_KEY=${apiKey}`);
    expect(outputLines.join("\n")).not.toContain(apiKey);
    expect(warningLines.join("\n")).not.toContain(apiKey);
    expect(outputLines.join("\n")).toContain("OpenAI API key: found");
  });

  it("interactive setup uses provider/model defaults before hidden key entry", async () => {
    const root = makeTempRoot();
    const apiKey = "sk-default-flow-secret-1234";

    await runSetup(
      {
        skipSkillsSync: true,
        skipSkillsIndex: true,
      },
      root,
      {
        prompter: interactivePrompter(apiKey),
        log: () => undefined,
      },
    );

    expect(loadConfig(root)).toMatchObject({
      provider: "openai",
      model: "gpt-5-mini",
    });
    expect(readFileSync(join(root, ".env"), "utf8")).toContain(`OPENAI_API_KEY=${apiKey}`);
  });

  it("asks provider and model before writing config", async () => {
    const root = makeTempRoot();
    const prompts: string[] = [];
    const prompter: SetupPrompter = {
      async text(question: string, defaultValue: string): Promise<string> {
        expect(existsSync(getConfigPath(root))).toBe(false);
        prompts.push(question);
        return defaultValue;
      },
      async secret(): Promise<string> {
        expect(prompts).toEqual(["Provider", "Model"]);
        expect(existsSync(getConfigPath(root))).toBe(false);
        return "sk-before-write-secret-1234";
      },
      async confirm(): Promise<boolean> {
        return false;
      },
    };

    await runSetup(
      {
        skipSkillsSync: true,
        skipSkillsIndex: true,
      },
      root,
      { prompter, log: () => undefined },
    );

    expect(existsSync(getConfigPath(root))).toBe(true);
  });

  it("masked prompt handles an existing key by showing only the masked key", async () => {
    const root = makeTempRoot();
    const lines: string[] = [];
    const apiKey = "sk-existing-secret-abcd";
    writeFileSync(join(root, ".env"), `OPENAI_API_KEY=${apiKey}\n`, "utf8");

    await runSetup(
      {
        provider: "openai",
        model: "gpt-5-mini",
        skipSkillsSync: true,
        skipSkillsIndex: true,
      },
      root,
      {
        prompter: {
          async text(_question: string, defaultValue: string): Promise<string> {
            return defaultValue;
          },
          async secret(): Promise<string> {
            throw new Error("unexpected secret prompt");
          },
          async confirm(): Promise<boolean> {
            return true;
          },
        },
        log: (message) => lines.push(message),
      },
    );

    const output = lines.join("\n");
    expect(output).toContain("OpenAI API key found: sk-...abcd");
    expect(output).toContain("OpenAI API key: found");
    expect(output).not.toContain(apiKey);
  });

  it("does not echo a key accidentally entered as provider", async () => {
    const root = makeTempRoot();
    const pastedKey = "sk-1234567890provider";

    await expect(
      runSetup(
        {
          provider: pastedKey,
          model: "gpt-5-mini",
          skipSkillsSync: true,
          skipSkillsIndex: true,
          yes: true,
        },
        root,
        { prompter: throwingPrompter(), log: () => undefined },
      ),
    ).rejects.toThrow("Provider value looks like a secret");

    await expect(
      runSetup(
        {
          provider: pastedKey,
          model: "gpt-5-mini",
          skipSkillsSync: true,
          skipSkillsIndex: true,
          yes: true,
        },
        root,
        { prompter: throwingPrompter(), log: () => undefined },
      ),
    ).rejects.not.toThrow(pastedKey);
  });

  it("does not save or echo a key accidentally entered as model", async () => {
    const root = makeTempRoot();
    const pastedKey = "sk-1234567890model";

    await expect(
      runSetup(
        {
          provider: "openai",
          model: pastedKey,
          skipSkillsSync: true,
          skipSkillsIndex: true,
          yes: true,
        },
        root,
        { prompter: throwingPrompter(), log: () => undefined },
      ),
    ).rejects.toThrow("Model value looks like a secret");

    if (existsSync(getConfigPath(root))) {
      expect(readFileSync(getConfigPath(root), "utf8")).not.toContain(pastedKey);
    }
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

  it("when hidden input is unavailable, setup falls back to editor flow", async () => {
    const root = makeTempRoot();
    const lines: string[] = [];
    let openedEnvPath = "";

    await runSetup(
      {
        skipSkillsSync: true,
        skipSkillsIndex: true,
      },
      root,
      {
        prompter: editorFallbackPrompter(),
        log: (message) => lines.push(message),
        openEditor: (_root, envPath) => {
          openedEnvPath = envPath;
          writeFileSync(envPath, "OPENAI_API_KEY=sk-editor-secret-1234\n", "utf8");
        },
      },
    );

    expect(openedEnvPath).toBe(join(root, ".env"));
    expect(readFileSync(join(root, ".env"), "utf8")).toContain("OPENAI_API_KEY=sk-editor-secret-1234");
    expect(lines.join("\n")).toContain("Hidden input is unavailable in this terminal.");
    expect(lines.join("\n")).toContain("OpenAI API key: found");
    expect(lines.join("\n")).not.toContain("sk-editor-secret-1234");
  });

  it("non-interactive setup without key fails clearly", async () => {
    const root = makeTempRoot();

    await expect(
      runSetup(
        {
          provider: "openai",
          model: "gpt-5-mini",
          skipSkillsSync: true,
          skipSkillsIndex: true,
          yes: true,
        },
        root,
        { log: () => undefined },
      ),
    ).rejects.toThrow("OPENAI_API_KEY is required");
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

describe("editor fallback", () => {
  it("uses notepad as the default editor on Windows", () => {
    if (process.platform === "win32") {
      expect(getDefaultEditorCommand()).toMatchObject({ command: "notepad" });
    }
  });
});

describe("readMaskedInput", () => {
  it("does not use private stdin handle fields", () => {
    const privateField = `_${"handle"}`;
    expect(readFileSync(join(__dirname, "setup.ts"), "utf8")).not.toContain(privateField);
  });

  it("does not echo raw typed characters and restores raw mode", async () => {
    const input = new EventEmitter() as EventEmitter & {
      isTTY: boolean;
      isRaw: boolean;
      setRawMode: (mode: boolean) => void;
      resume: () => void;
      pause: () => void;
    };
    const writes: string[] = [];
    const output = {
      isTTY: true,
      write(chunk: string) {
        writes.push(chunk);
        return true;
      },
    };
    const rawModes: boolean[] = [];

    input.isTTY = true;
    input.isRaw = false;
    input.setRawMode = (mode: boolean) => {
      rawModes.push(mode);
      input.isRaw = mode;
    };
    input.resume = () => undefined;
    input.pause = () => undefined;

    const promise = readMaskedInput(input, output as never, "OpenAI API key");
    input.emit("keypress", "sk-visible-secret-1234", {});
    input.emit("keypress", "\r", { name: "return" });

    await expect(promise).resolves.toBe("sk-visible-secret-1234");
    expect(writes.join("")).toBe("OpenAI API key: \n");
    expect(writes.join("")).not.toContain("sk-visible-secret-1234");
    expect(rawModes).toEqual([true, false]);
  });

  it("handles Backspace", async () => {
    const input = new EventEmitter() as EventEmitter & {
      isTTY: boolean;
      isRaw: boolean;
      setRawMode: (mode: boolean) => void;
      resume: () => void;
      pause: () => void;
    };
    const output = {
      isTTY: true,
      write() {
        return true;
      },
    };

    input.isTTY = true;
    input.isRaw = false;
    input.setRawMode = (mode: boolean) => {
      input.isRaw = mode;
    };
    input.resume = () => undefined;
    input.pause = () => undefined;

    const promise = readMaskedInput(input, output as never, "OpenAI API key");
    input.emit("keypress", "sk-old", {});
    input.emit("keypress", "", { name: "backspace" });
    input.emit("keypress", "", { name: "backspace" });
    input.emit("keypress", "", { name: "backspace" });
    input.emit("keypress", "new", {});
    input.emit("keypress", "\r", { name: "return" });

    await expect(promise).resolves.toBe("sk-new");
    expect(input.isRaw).toBe(false);
  });

  it("restores raw mode and rejects safely on Ctrl+C", async () => {
    const input = new EventEmitter() as EventEmitter & {
      isTTY: boolean;
      isRaw: boolean;
      setRawMode: (mode: boolean) => void;
      resume: () => void;
      pause: () => void;
    };
    const rawModes: boolean[] = [];
    let paused = false;
    const output = {
      isTTY: true,
      write() {
        return true;
      },
    };

    input.isTTY = true;
    input.isRaw = false;
    input.setRawMode = (mode: boolean) => {
      rawModes.push(mode);
      input.isRaw = mode;
    };
    input.resume = () => undefined;
    input.pause = () => {
      paused = true;
    };

    const promise = readMaskedInput(input, output as never, "OpenAI API key");
    input.emit("keypress", "\u0003", { name: "c", ctrl: true });

    await expect(promise).rejects.toThrow("Setup cancelled");
    expect(rawModes).toEqual([true, false]);
    expect(paused).toBe(true);
  });

  it("converts raw mode failures into a clear setup error", async () => {
    const input = new EventEmitter() as EventEmitter & {
      isTTY: boolean;
      isRaw: boolean;
      setRawMode: (mode: boolean) => void;
      resume: () => void;
      pause: () => void;
    };
    let paused = false;
    const output = {
      isTTY: true,
      write() {
        return true;
      },
    };

    input.isTTY = true;
    input.isRaw = false;
    input.setRawMode = () => {
      throw new Error("Cannot read properties of undefined");
    };
    input.resume = () => undefined;
    input.pause = () => {
      paused = true;
    };

    await expect(readMaskedInput(input, output as never, "OpenAI API key")).rejects.toThrow(
      "This terminal cannot enable hidden API key input",
    );
    expect(paused).toBe(true);
  });
});
