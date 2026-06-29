import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createDefaultConfig } from "./defaults";
import { loadDotEnv } from "./env";
import { initProject } from "./init";
import { getConfigPath } from "./paths";
import { assertProviderReady, resolveProvider } from "./provider";
import { ProviderError } from "./provider-errors";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-env-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  delete process.env.OPENAI_API_KEY;
  delete process.env.SWARM_PROVIDER;
  delete process.env.SWARM_MODEL;
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("loadDotEnv", () => {
  it("loads env vars without overwriting existing process env", () => {
    const root = makeTempRoot();
    writeFileSync(
      join(root, ".env"),
      "SWARM_PROVIDER=openai\nOPENAI_API_KEY=from-dotenv\n",
      "utf8",
    );
    process.env.OPENAI_API_KEY = "existing";

    loadDotEnv(root);

    expect(process.env.OPENAI_API_KEY).toBe("existing");
    expect(process.env.SWARM_PROVIDER).toBe("openai");
  });
});

describe("resolveProvider", () => {
  it("prefers cli overrides over config and env", () => {
    const root = makeTempRoot();
    initProject(root);
    writeFileSync(join(root, ".env"), "SWARM_PROVIDER=openai\nSWARM_MODEL=env-model\n", "utf8");

    const resolved = resolveProvider(root, { provider: "mock", model: "cli-model" });

    expect(resolved.provider).toBe("mock");
    expect(resolved.model).toBe("cli-model");
    expect(resolved.sources.provider).toBe("cli");
    expect(resolved.sources.model).toBe("cli");
  });

  it("uses config values when cli overrides are absent", () => {
    const root = makeTempRoot();
    initProject(root);

    const resolved = resolveProvider(root);

    expect(resolved.provider).toBe("openai");
    expect(resolved.model).toBe("gpt-5-mini");
    expect(resolved.sources.provider).toBe("config");
    expect(resolved.sources.model).toBe("config");
  });

  it("uses env model when config is missing", () => {
    const root = makeTempRoot();
    writeFileSync(join(root, ".env"), "SWARM_MODEL=env-model\n", "utf8");

    const resolved = resolveProvider(root);

    expect(resolved.provider).toBe("mock");
    expect(resolved.model).toBe("env-model");
    expect(resolved.sources.provider).toBe("default");
    expect(resolved.sources.model).toBe("env");
  });

  it("uses env provider when config overrides provider to mock", () => {
    const root = makeTempRoot();
    initProject(root);
    writeFileSync(
      getConfigPath(root),
      `${JSON.stringify({ ...createDefaultConfig(root), provider: "mock" }, null, 2)}\n`,
      "utf8",
    );
    writeFileSync(join(root, ".env"), "SWARM_PROVIDER=openai\n", "utf8");

    const resolved = resolveProvider(root);

    expect(resolved.provider).toBe("mock");
    expect(resolved.sources.provider).toBe("config");
  });

  it("requires OpenAI key only when provider is openai", () => {
    const root = makeTempRoot();
    const missingKey = resolveProvider(root, { provider: "openai" });
    expect(() => assertProviderReady(missingKey)).toThrow(ProviderError);

    process.env.OPENAI_API_KEY = "test-key";
    const withKey = resolveProvider(root, { provider: "openai" });
    expect(() => assertProviderReady(withKey)).not.toThrow();

    const mockResolved = resolveProvider(root, { provider: "mock" });
    delete process.env.OPENAI_API_KEY;
    expect(() => assertProviderReady(mockResolved)).not.toThrow();
  });
});
