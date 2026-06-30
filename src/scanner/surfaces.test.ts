import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { categorizeFile, walkRepo } from "./inventory";
import { mapSurfaces } from "./surfaces";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-surfaces-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("mapSurfaces", () => {
  it("maps Next.js app router pages and API routes", () => {
    const root = makeTempRoot();

    mkdirSync(join(root, "app", "dashboard", "settings"), { recursive: true });
    mkdirSync(join(root, "app", "api", "users"), { recursive: true });
    writeFileSync(join(root, "app", "page.tsx"), "export default function Page() {}\n", "utf8");
    writeFileSync(
      join(root, "app", "dashboard", "settings", "page.tsx"),
      "export default function Page() {}\n",
      "utf8",
    );
    writeFileSync(
      join(root, "app", "api", "users", "route.ts"),
      "export async function GET() {}\n",
      "utf8",
    );

    const inventory = walkRepo(root);
    const surfaces = mapSurfaces(root, inventory);

    expect(surfaces.routes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: "/", framework: "nextjs-app" }),
        expect.objectContaining({ path: "/dashboard/settings", framework: "nextjs-app" }),
      ]),
    );
    expect(surfaces.api).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: "/api/users", framework: "nextjs-app" }),
      ]),
    );
  });

  it("maps Next.js pages router routes and API routes", () => {
    const root = makeTempRoot();

    mkdirSync(join(root, "pages", "api", "health"), { recursive: true });
    writeFileSync(join(root, "pages", "index.tsx"), "export default function Home() {}\n", "utf8");
    writeFileSync(join(root, "pages", "about.tsx"), "export default function About() {}\n", "utf8");
    writeFileSync(
      join(root, "pages", "api", "health", "index.ts"),
      "export default function handler() {}\n",
      "utf8",
    );

    const inventory = walkRepo(root);
    const surfaces = mapSurfaces(root, inventory);

    expect(surfaces.routes.map((r) => r.path)).toEqual(
      expect.arrayContaining(["/", "/about"]),
    );
    expect(surfaces.api.map((r) => r.path)).toContain("/api/health");
  });

  it("maps Express and FastAPI routes from production source files", () => {
    const root = makeTempRoot();

    mkdirSync(join(root, "src"), { recursive: true });
    mkdirSync(join(root, "app"), { recursive: true });
    writeFileSync(
      join(root, "src", "server.ts"),
      "app.get('/health', () => {});\napp.post('/api/login', () => {});\n",
      "utf8",
    );
    writeFileSync(
      join(root, "app", "main.py"),
      "@app.get('/items')\n@app.post('/api/orders')\n",
      "utf8",
    );

    const inventory = walkRepo(root);
    const surfaces = mapSurfaces(root, inventory);

    expect(surfaces.routes.map((r) => r.path)).toContain("/health");
    expect(surfaces.api.map((r) => r.path)).toEqual(
      expect.arrayContaining(["/api/login", "/api/orders", "/items"]),
    );
  });

  it("skips Express routes embedded in test files by default", () => {
    const root = makeTempRoot();

    mkdirSync(join(root, "src"), { recursive: true });
    writeFileSync(
      join(root, "src", "server.test.ts"),
      "app.get('/health', () => {});\napp.post('/api/login', () => {});\n",
      "utf8",
    );

    expect(categorizeFile("src/server.test.ts")).toBe("test");

    const inventory = walkRepo(root);
    const surfaces = mapSurfaces(root, inventory);

    expect(surfaces.routes).toHaveLength(0);
    expect(surfaces.api).toHaveLength(0);

    const withTests = mapSurfaces(root, inventory, { includeTests: true });
    expect(withTests.api.map((route) => route.path)).toContain("/api/login");
  });

  it("maps Prisma models and auth-related files", () => {
    const root = makeTempRoot();

    mkdirSync(join(root, "prisma"), { recursive: true });
    mkdirSync(join(root, "src", "auth"), { recursive: true });
    writeFileSync(
      join(root, "prisma", "schema.prisma"),
      "model User { id Int @id }\nmodel Session { id Int @id }\n",
      "utf8",
    );
    writeFileSync(join(root, "src", "middleware.ts"), "export function middleware() {}\n", "utf8");
    writeFileSync(join(root, "src", "auth", "next-auth.ts"), "export const auth = {};\n", "utf8");

    const inventory = walkRepo(root);
    const surfaces = mapSurfaces(root, inventory);

    expect(surfaces.dataModels.map((m) => m.name)).toEqual(
      expect.arrayContaining(["User", "Session"]),
    );
    expect(surfaces.auth.map((a) => a.file)).toEqual(
      expect.arrayContaining(["src/middleware.ts", "src/auth/next-auth.ts"]),
    );
  });
});

describe("mapSurfaces on project root", () => {
  it("returns structured surfaces for this repo", () => {
    const projectRoot = join(__dirname, "..", "..");
    if (!existsSync(join(projectRoot, "package.json"))) {
      return;
    }

    const inventory = walkRepo(projectRoot);
    const surfaces = mapSurfaces(projectRoot, inventory);

    expect(surfaces).toMatchObject({
      routes: expect.any(Array),
      api: expect.any(Array),
      auth: expect.any(Array),
      dataModels: expect.any(Array),
    });
  });

  it("does not emit fake API routes from scanner test fixtures", () => {
    const projectRoot = join(__dirname, "..", "..");
    if (!existsSync(join(projectRoot, "package.json"))) {
      return;
    }

    const inventory = walkRepo(projectRoot);
    const surfaces = mapSurfaces(projectRoot, inventory);

    expect(surfaces.api.map((route) => route.path)).not.toContain("/api/login");
    expect(surfaces.api.map((route) => route.path)).not.toContain("/api/orders");
    expect(surfaces.routes.map((route) => route.path)).not.toContain("/health");
    expect(surfaces.api.every((route) => !route.file.endsWith(".test.ts"))).toBe(true);
    expect(surfaces.routes.every((route) => !route.file.endsWith(".test.ts"))).toBe(true);
  });
});
