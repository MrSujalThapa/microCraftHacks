import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { walkRepo } from "./inventory";
import { detectStack } from "./stack";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-stack-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("detectStack", () => {
  it("detects Node/React stack from package.json", () => {
    const root = makeTempRoot();
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({
        dependencies: { react: "^19.0.0", express: "^5.0.0", tailwindcss: "^4.0.0" },
      }),
      "utf8",
    );

    const inventory = walkRepo(root);
    const stack = detectStack(root, inventory);

    expect(stack.map((s) => s.name)).toEqual(
      expect.arrayContaining(["React", "Express", "Tailwind CSS"]),
    );

    const react = stack.find((s) => s.name === "React");
    expect(react?.confidence).toBe("medium");
    expect(react?.evidence).toContain("package.json");
  });

  it("detects Next.js, Prisma, Docker, and GitHub Actions", () => {
    const root = makeTempRoot();

    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({
        dependencies: { next: "^15.0.0", "@prisma/client": "^6.0.0" },
        devDependencies: { prisma: "^6.0.0" },
      }),
      "utf8",
    );
    writeFileSync(join(root, "next.config.ts"), "export default {};\n", "utf8");
    mkdirSync(join(root, "prisma"), { recursive: true });
    writeFileSync(join(root, "prisma", "schema.prisma"), "model User { id Int @id }\n", "utf8");
    writeFileSync(join(root, "Dockerfile"), "FROM node:20\n", "utf8");
    mkdirSync(join(root, ".github", "workflows"), { recursive: true });
    writeFileSync(join(root, ".github", "workflows", "ci.yml"), "name: ci\n", "utf8");

    const inventory = walkRepo(root);
    const stack = detectStack(root, inventory);

    expect(stack.map((s) => s.name)).toEqual(
      expect.arrayContaining(["Next.js", "Prisma", "Docker", "GitHub Actions"]),
    );

    const next = stack.find((s) => s.name === "Next.js");
    expect(next?.confidence).toBe("high");

    const prisma = stack.find((s) => s.name === "Prisma");
    expect(prisma?.confidence).toBe("high");
  });

  it("detects FastAPI and Django from Python manifests", () => {
    const root = makeTempRoot();

    writeFileSync(join(root, "requirements.txt"), "fastapi>=0.100\ndjango>=5.0\n", "utf8");
    writeFileSync(join(root, "manage.py"), "# django\n", "utf8");
    mkdirSync(join(root, "app"), { recursive: true });
    writeFileSync(join(root, "app", "main.py"), "from fastapi import FastAPI\n", "utf8");

    const inventory = walkRepo(root);
    const stack = detectStack(root, inventory);

    expect(stack.map((s) => s.name)).toEqual(expect.arrayContaining(["FastAPI", "Django"]));
  });

  it("detects Spring Boot from build.gradle", () => {
    const root = makeTempRoot();
    writeFileSync(
      join(root, "build.gradle"),
      "plugins { id 'org.springframework.boot' version '3.4.0' }\n",
      "utf8",
    );

    const inventory = walkRepo(root);
    const stack = detectStack(root, inventory);

    expect(stack.some((s) => s.name === "Spring Boot")).toBe(true);
  });

  it("detects Supabase from package.json and config", () => {
    const root = makeTempRoot();
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2.0.0" } }),
      "utf8",
    );
    mkdirSync(join(root, "supabase"), { recursive: true });
    writeFileSync(join(root, "supabase", "config.toml"), "[project]\n", "utf8");

    const inventory = walkRepo(root);
    const stack = detectStack(root, inventory);

    const supabase = stack.find((s) => s.name === "Supabase");
    expect(supabase?.confidence).toBe("high");
  });
});

describe("detectStack on project root", () => {
  it("runs without error on this repo", () => {
    const projectRoot = join(__dirname, "..", "..");
    if (!existsSync(join(projectRoot, "package.json"))) {
      return;
    }

    const inventory = walkRepo(projectRoot);
    const stack = detectStack(projectRoot, inventory);
    expect(Array.isArray(stack)).toBe(true);
  });
});
