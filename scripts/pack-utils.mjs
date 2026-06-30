import { spawnSync } from "node:child_process";

const FORBIDDEN_PATTERNS = [
  { label: ".env secrets file", pattern: /(?:^|\/)\\.env$/u },
  { label: ".swarm/cache", pattern: /\.swarm\/cache\//u },
  { label: ".swarm/reports", pattern: /\.swarm\/reports\//u },
  { label: "skills/external", pattern: /skills\/external\//u },
  { label: "local docs", pattern: /^docs\//u },
  { label: "compiled test files", pattern: /\.test\.(?:js|d\.ts)$/u },
  { label: "test fixtures", pattern: /fixtures\.(?:js|d\.ts)$/u },
  { label: "Python tests", pattern: /^agent_runtime\/tests\//u },
  { label: "pytest cache", pattern: /\.pytest_cache\//u },
  { label: "Python bytecode cache", pattern: /__pycache__\//u },
  { label: "Python egg-info", pattern: /\.egg-info\//u },
];

export const REQUIRED_PACK_PATHS = [
  "dist/cli/index.js",
  "agent_runtime/pyproject.toml",
  "agent_runtime/cyber_swarm/runner.py",
  "README.md",
  "LICENSE",
  ".env.example",
];

export function runPackDryRun(cwd = process.cwd()) {
  spawnSync(process.execPath, ["scripts/clean-agent-runtime.mjs"], {
    cwd,
    encoding: "utf8",
    shell: process.platform === "win32",
  });

  const result = spawnSync("npm", ["pack", "--dry-run"], {
    cwd,
    encoding: "utf8",
    shell: process.platform === "win32",
  });

  if (result.status !== 0) {
    throw new Error(`${result.stderr ?? ""}${result.stdout ?? ""}`.trim() || "npm pack --dry-run failed");
  }

  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

export function parsePackLines(output) {
  return output
    .split(/\r?\n/u)
    .map((line) => line.match(/npm notice\s+\d+(?:\.\d+)?(?:[kMG]B|B)\s+(.+)$/u)?.[1]?.trim())
    .filter(Boolean);
}

export function findPackViolations(packedPaths) {
  const violations = [];
  for (const packedPath of packedPaths) {
    for (const { label, pattern } of FORBIDDEN_PATTERNS) {
      if (pattern.test(packedPath)) {
        violations.push(`${packedPath} (${label})`);
      }
    }
  }
  return violations;
}

export function findMissingPackPaths(packedPaths, requiredPaths = REQUIRED_PACK_PATHS) {
  return requiredPaths.filter(
    (requiredPath) => !packedPaths.some((packedPath) => packedPath === requiredPath),
  );
}
