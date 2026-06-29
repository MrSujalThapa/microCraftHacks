import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { InventoryResult, StackConfidence, StackDetection } from "./types";

interface StackRule {
  name: string;
  detect: (ctx: StackContext) => StackDetection | null;
}

interface StackContext {
  root: string;
  inventory: InventoryResult;
  fileSet: Set<string>;
  packageJson: Record<string, unknown> | null;
  requirementsText: string | null;
  pyprojectText: string | null;
}

function hasFile(ctx: StackContext, relativePath: string): boolean {
  return ctx.fileSet.has(relativePath.replace(/\\/g, "/"));
}

function hasFileMatching(ctx: StackContext, pattern: RegExp): string[] {
  return [...ctx.fileSet].filter((path) => pattern.test(path));
}

function readJsonIfExists(root: string, relativePath: string): Record<string, unknown> | null {
  const fullPath = join(root, relativePath);
  if (!existsSync(fullPath)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(fullPath, "utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function readTextIfExists(root: string, relativePath: string): string | null {
  const fullPath = join(root, relativePath);
  if (!existsSync(fullPath)) {
    return null;
  }
  try {
    return readFileSync(fullPath, "utf8");
  } catch {
    return null;
  }
}

function getPackageDeps(pkg: Record<string, unknown> | null): Set<string> {
  const deps = new Set<string>();
  if (!pkg) {
    return deps;
  }

  for (const field of ["dependencies", "devDependencies", "peerDependencies"]) {
    const section = pkg[field];
    if (section && typeof section === "object") {
      for (const name of Object.keys(section as Record<string, unknown>)) {
        deps.add(name.toLowerCase());
      }
    }
  }

  return deps;
}

function hasPythonPackage(text: string | null, packageName: string): boolean {
  if (!text) {
    return false;
  }
  const pattern = new RegExp(`(^|\\s)${packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\s|$|==|>=|<=|~=|!=)`, "im");
  return pattern.test(text);
}

function confidenceFromEvidence(evidence: string[]): StackConfidence {
  if (evidence.length >= 2) {
    return "high";
  }
  if (evidence.length === 1) {
    return "medium";
  }
  return "low";
}

function makeDetection(name: string, evidence: string[]): StackDetection | null {
  if (evidence.length === 0) {
    return null;
  }
  return {
    name,
    confidence: confidenceFromEvidence(evidence),
    evidence: [...new Set(evidence)].sort(),
  };
}

const STACK_RULES: StackRule[] = [
  {
    name: "Next.js",
    detect: (ctx) => {
      const evidence: string[] = [];
      const deps = getPackageDeps(ctx.packageJson);
      if (deps.has("next")) {
        evidence.push("package.json");
      }
      const configFiles = hasFileMatching(ctx, /^next\.config\.(js|mjs|ts)$/);
      evidence.push(...configFiles);
      return makeDetection("Next.js", evidence);
    },
  },
  {
    name: "React",
    detect: (ctx) => {
      const evidence: string[] = [];
      const deps = getPackageDeps(ctx.packageJson);
      if (deps.has("react")) {
        evidence.push("package.json");
      }
      return makeDetection("React", evidence);
    },
  },
  {
    name: "Express",
    detect: (ctx) => {
      const evidence: string[] = [];
      const deps = getPackageDeps(ctx.packageJson);
      if (deps.has("express")) {
        evidence.push("package.json");
      }
      return makeDetection("Express", evidence);
    },
  },
  {
    name: "FastAPI",
    detect: (ctx) => {
      const evidence: string[] = [];
      if (hasPythonPackage(ctx.requirementsText, "fastapi")) {
        evidence.push("requirements.txt");
      }
      if (hasPythonPackage(ctx.pyprojectText, "fastapi")) {
        evidence.push("pyproject.toml");
      }
      const pyFiles = ctx.inventory.files.filter(
        (f) => f.category === "python" && f.path.endsWith(".py"),
      );
      for (const file of pyFiles.slice(0, 50)) {
        const text = readTextIfExists(ctx.root, file.path);
        if (text && /from\s+fastapi|import\s+fastapi/i.test(text)) {
          evidence.push(file.path);
          break;
        }
      }
      return makeDetection("FastAPI", evidence);
    },
  },
  {
    name: "Django",
    detect: (ctx) => {
      const evidence: string[] = [];
      if (hasPythonPackage(ctx.requirementsText, "django")) {
        evidence.push("requirements.txt");
      }
      if (hasPythonPackage(ctx.pyprojectText, "django")) {
        evidence.push("pyproject.toml");
      }
      if (hasFile(ctx, "manage.py")) {
        evidence.push("manage.py");
      }
      return makeDetection("Django", evidence);
    },
  },
  {
    name: "Spring Boot",
    detect: (ctx) => {
      const evidence: string[] = [];
      const gradleFiles = hasFileMatching(ctx, /^(build\.gradle(\.kts)?|settings\.gradle(\.kts)?)$/);
      for (const file of gradleFiles) {
        const text = readTextIfExists(ctx.root, file);
        if (text && /spring-boot|org\.springframework\.boot/i.test(text)) {
          evidence.push(file);
        }
      }
      if (hasFile(ctx, "pom.xml")) {
        const text = readTextIfExists(ctx.root, "pom.xml");
        if (text && /spring-boot|org\.springframework\.boot/i.test(text)) {
          evidence.push("pom.xml");
        }
      }
      return makeDetection("Spring Boot", evidence);
    },
  },
  {
    name: "Supabase",
    detect: (ctx) => {
      const evidence: string[] = [];
      const deps = getPackageDeps(ctx.packageJson);
      if (deps.has("@supabase/supabase-js") || deps.has("@supabase/auth-helpers-nextjs")) {
        evidence.push("package.json");
      }
      const supabaseConfig = hasFileMatching(ctx, /^supabase\/config\.toml$/);
      evidence.push(...supabaseConfig);
      return makeDetection("Supabase", evidence);
    },
  },
  {
    name: "Prisma",
    detect: (ctx) => {
      const evidence: string[] = [];
      const deps = getPackageDeps(ctx.packageJson);
      if (deps.has("prisma") || deps.has("@prisma/client")) {
        evidence.push("package.json");
      }
      if (hasFile(ctx, "prisma/schema.prisma")) {
        evidence.push("prisma/schema.prisma");
      }
      return makeDetection("Prisma", evidence);
    },
  },
  {
    name: "Tailwind CSS",
    detect: (ctx) => {
      const evidence: string[] = [];
      const deps = getPackageDeps(ctx.packageJson);
      if (deps.has("tailwindcss")) {
        evidence.push("package.json");
      }
      const configFiles = hasFileMatching(ctx, /^tailwind\.config\.(js|ts|cjs|mjs)$/);
      evidence.push(...configFiles);
      return makeDetection("Tailwind CSS", evidence);
    },
  },
  {
    name: "Docker",
    detect: (ctx) => {
      const evidence: string[] = [];
      const dockerfiles = hasFileMatching(ctx, /^(Dockerfile(\..+)?|docker-compose\.(ya?ml))$/);
      evidence.push(...dockerfiles);
      return makeDetection("Docker", evidence);
    },
  },
  {
    name: "GitHub Actions",
    detect: (ctx) => {
      const workflows = hasFileMatching(ctx, /^\.github\/workflows\/.*\.(ya?ml)$/);
      return makeDetection("GitHub Actions", workflows);
    },
  },
];

function buildContext(root: string, inventory: InventoryResult): StackContext {
  return {
    root,
    inventory,
    fileSet: new Set(inventory.files.map((f) => f.path)),
    packageJson: readJsonIfExists(root, "package.json"),
    requirementsText: readTextIfExists(root, "requirements.txt"),
    pyprojectText: readTextIfExists(root, "pyproject.toml"),
  };
}

export function detectStack(root: string, inventory: InventoryResult): StackDetection[] {
  const ctx = buildContext(root, inventory);
  const detections: StackDetection[] = [];

  for (const rule of STACK_RULES) {
    const detection = rule.detect(ctx);
    if (detection) {
      detections.push(detection);
    }
  }

  return detections.sort((a, b) => a.name.localeCompare(b.name));
}

export function printStackSummary(stack: StackDetection[]): void {
  if (stack.length === 0) {
    console.log("Stack: none detected");
    return;
  }

  console.log("Stack:");
  for (const item of stack) {
    const evidence = item.evidence.join(", ");
    console.log(`  ${item.name} (${item.confidence}) — ${evidence}`);
  }
}
