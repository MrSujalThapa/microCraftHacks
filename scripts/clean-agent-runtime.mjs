import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

function cleanRuntimeArtifacts(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__pycache__" || entry.name.endsWith(".egg-info")) {
        rmSync(fullPath, { recursive: true, force: true });
        continue;
      }
      cleanRuntimeArtifacts(fullPath);
      continue;
    }
    if (entry.name.endsWith(".pyc")) {
      rmSync(fullPath, { force: true });
    }
  }
}

cleanRuntimeArtifacts(join(process.cwd(), "agent_runtime"));
