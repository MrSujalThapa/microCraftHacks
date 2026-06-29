/** Directory names skipped during repo walk and filtered from surfaces/routing. */
export const IGNORE_DIR_NAMES = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  ".next",
  "coverage",
  "vendor",
  ".turbo",
  ".pnpm-store",
  ".yarn",
  ".venv",
  "venv",
  "env",
  "__pycache__",
  ".pytest_cache",
  "site-packages",
  ".cursor",
  ".mypy_cache",
  ".ruff_cache",
  ".tox",
  ".cache",
]);

export const IGNORE_RELATIVE_PREFIXES = [".swarm/cache", ".swarm/reports"];

export function normalizeRelativePath(relPath: string): string {
  return relPath.replace(/\\/g, "/");
}

export function shouldIgnoreDirName(name: string): boolean {
  return IGNORE_DIR_NAMES.has(name);
}

/** True when any path segment is a dependency/runtime artifact directory. */
export function shouldIgnoreScannedPath(relPath: string): boolean {
  const normalized = normalizeRelativePath(relPath);
  if (
    IGNORE_RELATIVE_PREFIXES.some(
      (prefix) => normalized === prefix || normalized.startsWith(`${prefix}/`),
    )
  ) {
    return true;
  }

  for (const segment of normalized.split("/")) {
    if (IGNORE_DIR_NAMES.has(segment)) {
      return true;
    }
  }

  return false;
}
