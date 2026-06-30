import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { shouldIgnoreScannedPath } from "./ignore";
import { mapSurfaces } from "./surfaces";
import { walkRepo } from "./inventory";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-ignore-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("shouldIgnoreScannedPath", () => {
  it("matches nested dependency artifact segments", () => {
    expect(shouldIgnoreScannedPath("backend/.venv/Lib/site-packages/flask/auth.py")).toBe(true);
    expect(shouldIgnoreScannedPath("backend/__pycache__/main.cpython-314.pyc")).toBe(true);
    expect(shouldIgnoreScannedPath(".cursor/rules/swarm.mdc")).toBe(true);
    expect(shouldIgnoreScannedPath("src/main.py")).toBe(false);
  });
});

describe("walkRepo dependency artifact ignores", () => {
  it("skips nested Python venv and site-packages trees", () => {
    const root = makeTempRoot();

    mkdirSync(join(root, "backend", "app"), { recursive: true });
    writeFileSync(
      join(root, "backend", "app", "main.py"),
      '@app.get("/api/health")\ndef health(): pass\n',
      "utf8",
    );
    writeFileSync(
      join(root, "backend", "app", "auth.py"),
      "def require_auth(): pass\n",
      "utf8",
    );

    mkdirSync(
      join(root, "backend", ".venv", "Lib", "site-packages", "flask"),
      { recursive: true },
    );
    writeFileSync(
      join(root, "backend", ".venv", "Lib", "site-packages", "flask", "auth.py"),
      "class FlaskAuth: pass\n",
      "utf8",
    );
    writeFileSync(
      join(root, "backend", ".venv", "Lib", "site-packages", "flask", "app.py"),
      '@app.route("/login")\n',
      "utf8",
    );

    mkdirSync(join(root, "backend", "__pycache__"), { recursive: true });
    writeFileSync(join(root, "backend", "__pycache__", "main.cpython-314.pyc"), "bytecode", "utf8");

    mkdirSync(join(root, ".cursor", "rules"), { recursive: true });
    writeFileSync(join(root, ".cursor", "rules", "project.mdc"), "rules", "utf8");

    const inventory = walkRepo(root);
    const paths = inventory.files.map((file) => file.path);

    expect(paths).toEqual(["backend/app/auth.py", "backend/app/main.py"]);
    expect(paths.some((path) => path.includes(".venv"))).toBe(false);
    expect(paths.some((path) => path.includes("site-packages"))).toBe(false);
    expect(paths.some((path) => path.includes("__pycache__"))).toBe(false);
    expect(paths.some((path) => path.includes(".cursor"))).toBe(false);
  });

  it("does not emit surfaces from ignored dependency paths", () => {
    const root = makeTempRoot();

    mkdirSync(join(root, "backend", "app"), { recursive: true });
    writeFileSync(
      join(root, "backend", "app", "routes.py"),
      '@app.get("/api/users")\ndef users(): pass\n',
      "utf8",
    );
    writeFileSync(
      join(root, "backend", "app", "auth.py"),
      "def require_auth(): pass\n",
      "utf8",
    );

    mkdirSync(
      join(root, "backend", ".venv", "Lib", "site-packages", "passport"),
      { recursive: true },
    );
    writeFileSync(
      join(root, "backend", ".venv", "Lib", "site-packages", "passport", "middleware.py"),
      "session oauth jwt\n",
      "utf8",
    );

    const inventory = walkRepo(root);
    const surfaces = mapSurfaces(root, inventory);

    expect(surfaces.auth.map((entry) => entry.file)).toEqual(["backend/app/auth.py"]);
    expect(surfaces.api.map((entry) => entry.file)).toEqual(["backend/app/routes.py"]);
    expect(surfaces.auth.some((entry) => entry.file.includes("site-packages"))).toBe(false);
  });
});
