#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  findMissingPackPaths,
  findPackViolations,
  parsePackLines,
  runPackDryRun,
} from "./pack-utils.mjs";

function main() {
  let output = "";
  try {
    output = runPackDryRun();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }

  const packedPaths = parsePackLines(output);
  if (packedPaths.length === 0) {
    console.error("Could not parse npm pack --dry-run output.");
    process.exit(1);
  }

  const violations = findPackViolations(packedPaths);

  const cliPath = join(process.cwd(), "dist/cli/index.js");
  const shebang = readFileSync(cliPath, "utf8").split(/\r?\n/u)[0];
  if (shebang !== "#!/usr/bin/env node") {
    violations.push(`dist/cli/index.js missing executable shebang (got: ${shebang ?? "none"})`);
  }

  const missing = findMissingPackPaths(packedPaths);

  if (violations.length > 0) {
    console.error("Package validation failed. Forbidden or invalid entries:");
    for (const violation of violations) {
      console.error(`  - ${violation}`);
    }
    process.exit(1);
  }

  if (missing.length > 0) {
    console.error("Package validation failed. Missing required files:");
    for (const requiredPath of missing) {
      console.error(`  - ${requiredPath}`);
    }
    process.exit(1);
  }

  console.log(`Package validation passed (${packedPaths.length} files).`);
}

main();
