import { readFileSync } from "node:fs";
import { join } from "node:path";

import { isTestFile } from "../shared/files";
import { shouldIgnoreScannedPath } from "./ignore";
import type {
  InventoryResult,
  SurfaceAuth,
  SurfaceDataModel,
  SurfaceRoute,
  SurfacesResult,
} from "./types";

const AUTH_FILE_PATTERN =
  /(^|\/)(auth|authentication|middleware|passport|next-auth|session|oauth|jwt)(\/|\.|$)/i;

const AUTH_CONFIG_PATTERN = /(nextauth|auth0|passport|jwt|oauth|session)/i;

function readSource(root: string, relativePath: string): string | null {
  try {
    return readFileSync(join(root, relativePath), "utf8");
  } catch {
    return null;
  }
}

function nextAppPageRoute(filePath: string): string | null {
  if (/^app\/page\.(tsx|ts|jsx|js)$/.test(filePath)) {
    return "/";
  }

  const match = filePath.match(/^app\/(.+)\/page\.(tsx|ts|jsx|js)$/);
  if (!match) {
    return null;
  }
  const segments = match[1].split("/").filter((s) => !s.startsWith("(") && !s.endsWith(")"));
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

function nextAppApiRoute(filePath: string): string | null {
  if (/^app\/route\.(tsx|ts|jsx|js)$/.test(filePath)) {
    return "/api";
  }

  const match = filePath.match(/^app\/(.+)\/route\.(tsx|ts|jsx|js)$/);
  if (!match) {
    return null;
  }
  const segments = match[1].split("/").filter((s) => !s.startsWith("(") && !s.endsWith(")"));
  return `/${segments.join("/")}`;
}

function nextPagesRoute(filePath: string): string | null {
  const match = filePath.match(/^pages\/(.+)\.(tsx|ts|jsx|js)$/);
  if (!match) {
    return null;
  }
  const routePath = match[1];
  if (routePath === "index") {
    return "/";
  }
  if (routePath.endsWith("/index")) {
    return `/${routePath.slice(0, -"/index".length)}`;
  }
  return `/${routePath}`;
}

function nextPagesApiRoute(filePath: string): string | null {
  const match = filePath.match(/^pages\/api\/(.+)\.(tsx|ts|jsx|js)$/);
  if (!match) {
    return null;
  }
  const routePath = match[1];
  if (routePath === "index") {
    return "/api";
  }
  if (routePath.endsWith("/index")) {
    return `/api/${routePath.slice(0, -"/index".length)}`;
  }
  return `/api/${routePath}`;
}

function scanNextSurfaces(files: string[]): { routes: SurfaceRoute[]; api: SurfaceRoute[] } {
  const routes: SurfaceRoute[] = [];
  const api: SurfaceRoute[] = [];

  for (const file of files) {
    const appPage = nextAppPageRoute(file);
    if (appPage) {
      routes.push({ path: appPage, file, framework: "nextjs-app" });
      continue;
    }

    const appApi = nextAppApiRoute(file);
    if (appApi) {
      api.push({ path: appApi, file, framework: "nextjs-app" });
      continue;
    }

    const pagesRoute = nextPagesRoute(file);
    if (pagesRoute && !file.startsWith("pages/api/")) {
      routes.push({ path: pagesRoute, file, framework: "nextjs-pages" });
      continue;
    }

    const pagesApi = nextPagesApiRoute(file);
    if (pagesApi) {
      api.push({ path: pagesApi, file, framework: "nextjs-pages" });
    }
  }

  return { routes, api };
}

const EXPRESS_ROUTE_RE =
  /(?:app|router)\.(get|post|put|patch|delete|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/g;

function scanExpressSurfaces(root: string, files: string[]): SurfaceRoute[] {
  const routes: SurfaceRoute[] = [];

  for (const file of files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(file)) {
      continue;
    }
    const source = readSource(root, file);
    if (!source) {
      continue;
    }

    let match: RegExpExecArray | null;
    EXPRESS_ROUTE_RE.lastIndex = 0;
    while ((match = EXPRESS_ROUTE_RE.exec(source)) !== null) {
      routes.push({
        path: match[2],
        file,
        framework: "express",
      });
    }
  }

  return routes;
}

const FASTAPI_ROUTE_RE =
  /@(?:app|router)\.(get|post|put|patch|delete|options|head|api_route)\s*\(\s*['"]([^'"]+)['"]/g;

function scanFastApiSurfaces(root: string, files: string[]): SurfaceRoute[] {
  const routes: SurfaceRoute[] = [];

  for (const file of files) {
    if (!file.endsWith(".py")) {
      continue;
    }
    const source = readSource(root, file);
    if (!source) {
      continue;
    }

    let match: RegExpExecArray | null;
    FASTAPI_ROUTE_RE.lastIndex = 0;
    while ((match = FASTAPI_ROUTE_RE.exec(source)) !== null) {
      routes.push({
        path: match[2],
        file,
        framework: "fastapi",
      });
    }
  }

  return routes;
}

const PRISMA_MODEL_RE = /^model\s+(\w+)\s*\{/gm;

function scanPrismaModels(root: string, files: string[]): SurfaceDataModel[] {
  const models: SurfaceDataModel[] = [];

  for (const file of files) {
    if (!file.endsWith(".prisma")) {
      continue;
    }
    const source = readSource(root, file);
    if (!source) {
      continue;
    }

    let match: RegExpExecArray | null;
    PRISMA_MODEL_RE.lastIndex = 0;
    while ((match = PRISMA_MODEL_RE.exec(source)) !== null) {
      models.push({ file, name: match[1] });
    }
  }

  return models;
}

function inferAuthType(filePath: string, source: string | null): string | undefined {
  const lower = filePath.toLowerCase();
  if (lower.includes("middleware")) {
    return "middleware";
  }
  if (lower.includes("next-auth") || lower.includes("nextauth")) {
    return "next-auth";
  }
  if (lower.includes("passport")) {
    return "passport";
  }
  if (lower.includes("oauth")) {
    return "oauth";
  }
  if (lower.includes("jwt")) {
    return "jwt";
  }
  if (source && AUTH_CONFIG_PATTERN.test(source)) {
    return "config";
  }
  return undefined;
}

function scanAuthSurfaces(root: string, files: string[]): SurfaceAuth[] {
  const auth: SurfaceAuth[] = [];

  for (const file of files) {
    const isAuthFile = AUTH_FILE_PATTERN.test(file.replace(/\\/g, "/"));
    const isEnvConfig = file.startsWith(".env") || file.includes("auth.config");
    if (!isAuthFile && !isEnvConfig) {
      continue;
    }

    const source = readSource(root, file);
    auth.push({
      file,
      type: inferAuthType(file, source),
    });
  }

  return auth;
}

function dedupeRoutes(routes: SurfaceRoute[]): SurfaceRoute[] {
  const seen = new Set<string>();
  const result: SurfaceRoute[] = [];

  for (const route of routes) {
    const key = `${route.framework ?? ""}:${route.path}:${route.file}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(route);
  }

  return result.sort((a, b) => a.path.localeCompare(b.path) || a.file.localeCompare(b.file));
}

function dedupeDataModels(models: SurfaceDataModel[]): SurfaceDataModel[] {
  const seen = new Set<string>();
  const result: SurfaceDataModel[] = [];

  for (const model of models) {
    const key = `${model.file}:${model.name ?? ""}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(model);
  }

  return result.sort((a, b) => a.file.localeCompare(b.file));
}

function dedupeAuth(auth: SurfaceAuth[]): SurfaceAuth[] {
  const seen = new Set<string>();
  const result: SurfaceAuth[] = [];

  for (const entry of auth) {
    if (seen.has(entry.file)) {
      continue;
    }
    seen.add(entry.file);
    result.push(entry);
  }

  return result.sort((a, b) => a.file.localeCompare(b.file));
}

export interface MapSurfacesOptions {
  includeTests?: boolean;
}

function filterSurfaceFiles(files: string[], includeTests: boolean): string[] {
  if (includeTests) {
    return files;
  }
  return files.filter((file) => !isTestFile(file));
}

export function mapSurfaces(
  root: string,
  inventory: InventoryResult,
  options: MapSurfacesOptions = {},
): SurfacesResult {
  const includeTests = options.includeTests ?? false;
  const files = filterSurfaceFiles(
    inventory.files
      .map((f) => f.path)
      .filter((file) => !shouldIgnoreScannedPath(file)),
    includeTests,
  );

  const next = scanNextSurfaces(files);
  const expressRoutes = scanExpressSurfaces(root, files);
  const fastApiRoutes = scanFastApiSurfaces(root, files);

  const expressApi = expressRoutes.filter((r) => r.path === "/api" || r.path.startsWith("/api/"));
  const expressPage = expressRoutes.filter((r) => !expressApi.includes(r));

  const fastApiApi = fastApiRoutes;

  const api = dedupeRoutes([...next.api, ...expressApi, ...fastApiApi]);
  const routes = dedupeRoutes([...next.routes, ...expressPage]);

  const dataModels = dedupeDataModels(scanPrismaModels(root, files));
  const auth = dedupeAuth(scanAuthSurfaces(root, files));

  return {
    routes,
    api,
    auth,
    dataModels,
  };
}

export function printSurfacesSummary(surfaces: SurfacesResult): void {
  console.log(
    `Surfaces: ${surfaces.routes.length} routes, ${surfaces.api.length} api, ${surfaces.auth.length} auth, ${surfaces.dataModels.length} models`,
  );

  const preview = (label: string, items: string[], limit = 5): void => {
    if (items.length === 0) {
      return;
    }
    console.log(`${label}: ${items.slice(0, limit).join(", ")}${items.length > limit ? "…" : ""}`);
  };

  preview("Routes", surfaces.routes.map((r) => r.path));
  preview("API", surfaces.api.map((r) => r.path));
  preview("Auth", surfaces.auth.map((a) => a.file));
  preview("Models", surfaces.dataModels.map((m) => m.name ?? m.file));
}
