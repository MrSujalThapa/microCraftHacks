import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  categorizeFile,
  IGNORE_DIR_NAMES,
  walkRepo,
} from "./inventory";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-inventory-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("categorizeFile", () => {
  it("maps common extensions and config filenames", () => {
    expect(categorizeFile("src/index.ts")).toBe("typescript");
    expect(categorizeFile("src/scanner/surfaces.test.ts")).toBe("test");
    expect(categorizeFile("src/App.tsx")).toBe("typescript");
    expect(categorizeFile("lib/util.js")).toBe("javascript");
    expect(categorizeFile("app/main.py")).toBe("python");
    expect(categorizeFile("package.json")).toBe("config");
    expect(categorizeFile("tsconfig.json")).toBe("config");
    expect(categorizeFile("Dockerfile")).toBe("docker");
    expect(categorizeFile(".env.local")).toBe("config");
  });
});

describe("walkRepo", () => {
  it("skips ignored directories and binary files", () => {
    const root = makeTempRoot();

    mkdirSync(join(root, "src"), { recursive: true });
    writeFileSync(join(root, "src", "index.ts"), "export {};\n", "utf8");
    writeFileSync(join(root, "package.json"), "{}", "utf8");

    mkdirSync(join(root, "node_modules", "pkg"), { recursive: true });
    writeFileSync(join(root, "node_modules", "pkg", "index.js"), "module.exports = {};\n", "utf8");

    mkdirSync(join(root, ".git"), { recursive: true });
    writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");

    writeFileSync(join(root, "logo.png"), "binary", "utf8");

    mkdirSync(join(root, ".swarm", "cache"), { recursive: true });
    writeFileSync(join(root, ".swarm", "cache", "tmp.json"), "{}", "utf8");
    writeFileSync(join(root, ".swarm", "config.json"), "{}", "utf8");

    const inventory = walkRepo(root);

    expect(inventory.files.map((f) => f.path)).toEqual([
      ".swarm/config.json",
      "package.json",
      "src/index.ts",
    ]);
    expect(inventory.totalFiles).toBe(3);
    expect(inventory.byCategory.typescript).toBe(1);
    expect(inventory.byCategory.config).toBe(1);
    expect(inventory.byCategory.json).toBe(1);
  });

  it("ignores all standard skip directories", () => {
    const root = makeTempRoot();

    for (const dir of IGNORE_DIR_NAMES) {
      mkdirSync(join(root, dir, "nested"), { recursive: true });
      writeFileSync(join(root, dir, "nested", "file.ts"), "x", "utf8");
    }

    mkdirSync(join(root, "backend", ".venv", "Lib", "site-packages", "pkg"), {
      recursive: true,
    });
    writeFileSync(
      join(root, "backend", ".venv", "Lib", "site-packages", "pkg", "index.py"),
      "x",
      "utf8",
    );

    const inventory = walkRepo(root);
    expect(inventory.totalFiles).toBe(0);
  });
});

describe("walkRepo on project root", () => {
  it("includes source and config files from this repo", () => {
    const projectRoot = join(__dirname, "..", "..");
    if (!existsSync(join(projectRoot, "package.json"))) {
      return;
    }

    const inventory = walkRepo(projectRoot);
    expect(inventory.totalFiles).toBeGreaterThan(0);
    expect(inventory.files.some((f) => f.path === "package.json")).toBe(true);
    expect(inventory.files.some((f) => f.path.startsWith("src/"))).toBe(true);
    expect(inventory.files.some((f) => f.path.includes("node_modules"))).toBe(false);
  });
});
