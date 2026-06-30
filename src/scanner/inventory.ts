import { readdirSync } from "node:fs";
import { extname, join, relative } from "node:path";

import { isTestFile } from "../shared/files";
import {
  shouldIgnoreDirName,
  shouldIgnoreScannedPath,
} from "./ignore";
import type { FileEntry, InventoryResult } from "./types";

export { IGNORE_DIR_NAMES } from "./ignore";

const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".bmp",
  ".tiff",
  ".mp4",
  ".webm",
  ".mov",
  ".avi",
  ".mkv",
  ".mp3",
  ".wav",
  ".flac",
  ".ogg",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".otf",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".bin",
  ".wasm",
  ".zip",
  ".tar",
  ".gz",
  ".rar",
  ".7z",
  ".pdf",
  ".dmg",
  ".iso",
  ".db",
  ".sqlite",
  ".sqlite3",
]);

const CONFIG_NAMES = new Set([
  "package.json",
  "tsconfig.json",
  "jsconfig.json",
  "vite.config.ts",
  "vite.config.js",
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "tailwind.config.js",
  "tailwind.config.ts",
  "docker-compose.yml",
  "docker-compose.yaml",
  "pyproject.toml",
  "requirements.txt",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "settings.gradle",
  "vitest.config.ts",
  "vitest.config.js",
  "jest.config.js",
  "jest.config.ts",
  ".eslintrc",
  ".eslintrc.json",
  "eslint.config.js",
  "eslint.config.mjs",
  ".prettierrc",
  "prettier.config.js",
]);

function isBinaryFile(filePath: string): boolean {
  const ext = extname(filePath).toLowerCase();
  return BINARY_EXTENSIONS.has(ext);
}

export function categorizeFile(relativePath: string): string {
  const normalized = relativePath.replace(/\\/g, "/");
  const basename = normalized.split("/").pop() ?? normalized;
  const ext = extname(basename).toLowerCase();

  if (isTestFile(normalized)) {
    return "test";
  }

  if (CONFIG_NAMES.has(basename) || basename.endsWith(".config.js") || basename.endsWith(".config.ts")) {
    return "config";
  }

  switch (ext) {
    case ".ts":
    case ".tsx":
      return "typescript";
    case ".js":
    case ".jsx":
    case ".mjs":
    case ".cjs":
      return "javascript";
    case ".py":
      return "python";
    case ".java":
      return "java";
    case ".go":
      return "go";
    case ".rs":
      return "rust";
    case ".rb":
      return "ruby";
    case ".php":
      return "php";
    case ".cs":
      return "csharp";
    case ".swift":
      return "swift";
    case ".kt":
    case ".kts":
      return "kotlin";
    case ".html":
    case ".htm":
      return "html";
    case ".css":
      return "css";
    case ".scss":
    case ".sass":
      return "scss";
    case ".less":
      return "less";
    case ".json":
      return "json";
    case ".yaml":
    case ".yml":
      return "yaml";
    case ".md":
    case ".mdx":
      return "markdown";
    case ".sql":
      return "sql";
    case ".sh":
    case ".bash":
    case ".zsh":
      return "shell";
    case ".dockerfile":
      return "docker";
    default:
      if (basename === "Dockerfile" || basename.startsWith("Dockerfile.")) {
        return "docker";
      }
      if (basename.startsWith(".env")) {
        return "config";
      }
      return "other";
  }
}

export function walkRepo(root: string): InventoryResult {
  const files: FileEntry[] = [];

  function walk(currentDir: string): void {
    const entries = readdirSync(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (shouldIgnoreDirName(entry.name)) {
          continue;
        }
        const rel = relative(root, fullPath);
        if (shouldIgnoreScannedPath(rel)) {
          continue;
        }
        walk(fullPath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      const relPath = relative(root, fullPath).replace(/\\/g, "/");
      if (shouldIgnoreScannedPath(relPath)) {
        continue;
      }
      if (isBinaryFile(fullPath)) {
        continue;
      }

      files.push({
        path: relPath,
        category: categorizeFile(relPath),
      });
    }
  }

  walk(root);

  files.sort((a, b) => a.path.localeCompare(b.path));

  const byCategory: Record<string, number> = {};
  for (const file of files) {
    byCategory[file.category] = (byCategory[file.category] ?? 0) + 1;
  }

  return {
    totalFiles: files.length,
    byCategory,
    files,
  };
}
