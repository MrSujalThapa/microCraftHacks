import { pathToFileURL } from "node:url";
import { readdirSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";

const ARTIFACT_DIR_NAMES = new Set(["__pycache__", ".pytest_cache"]);

function isArtifactDirectory(name) {
  return ARTIFACT_DIR_NAMES.has(name) || name.endsWith(".egg-info");
}

function isArtifactFile(name) {
  return name.endsWith(".pyc") || name.endsWith(".pyo");
}

export function cleanPythonArtifacts(rootDir) {
  if (!statSync(rootDir, { throwIfNoEntry: false })?.isDirectory()) {
    return;
  }

  for (const entry of readdirSync(rootDir, { withFileTypes: true })) {
    const fullPath = join(rootDir, entry.name);
    if (entry.isDirectory()) {
      if (isArtifactDirectory(entry.name)) {
        rmSync(fullPath, { recursive: true, force: true });
        continue;
      }
      cleanPythonArtifacts(fullPath);
      continue;
    }
    if (isArtifactFile(entry.name)) {
      rmSync(fullPath, { force: true });
    }
  }
}

const invokedDirectly =
  process.argv[1] &&
  import.meta.url.replace(/\/?$/u, "") === pathToFileURL(process.argv[1]).href.replace(/\/?$/u, "");

if (invokedDirectly) {
  cleanPythonArtifacts(join(process.cwd(), "agent_runtime"));
}
