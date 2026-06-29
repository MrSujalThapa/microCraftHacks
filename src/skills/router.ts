import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import type { SwarmConfig } from "../config/types";
import type { ScanReport } from "../scanner/types";
import { SkillsError } from "./errors";
import { loadSkillBodies } from "./loader";
import { readSkillsIndex } from "./indexer";
import { getRoutedSkillsPath } from "./paths";
import type { RouteResult, RoutedSkillSelection, RoutedSkillsOutput, SkillIndexEntry } from "./types";

const AGENT_TAG_MAP: Record<string, string[]> = {
  auth: ["auth", "authentication", "authorization", "idor", "access-control", "session", "oauth", "jwt"],
  api: ["api", "rest", "graphql", "endpoint", "mutation", "bola", "owasp"],
  secrets: ["secret", "credential", "env", "key", "token"],
  injection: ["injection", "xss", "sqli", "sql", "script"],
  dependency: ["dependency", "supply-chain", "package"],
  availability: ["availability", "dos", "rate-limit", "denial"],
  business: ["business-logic", "logic", "workflow"],
  recon: ["recon", "mapping", "surface", "discovery"],
};

const STACK_KEYWORDS: Record<string, string[]> = {
  "Next.js": ["nextjs", "next", "react", "frontend", "web"],
  React: ["react", "frontend", "web", "jsx"],
  Express: ["express", "nodejs", "node", "rest"],
  FastAPI: ["fastapi", "python", "rest"],
  Django: ["django", "python", "web"],
  "Spring Boot": ["spring", "java"],
  Supabase: ["supabase", "database", "auth", "storage"],
  Prisma: ["prisma", "database", "orm", "sql"],
  "Tailwind CSS": ["tailwind", "frontend", "css"],
  Docker: ["docker", "container", "deployment"],
  "GitHub Actions": ["github", "ci", "pipeline"],
  TypeScript: ["typescript", "node", "cli"],
  Node: ["nodejs", "node", "cli", "typescript"],
  "Node.js": ["nodejs", "node", "cli", "typescript"],
  Python: ["python"],
  Vitest: ["vitest", "testing", "unit"],
};

const GENERIC_TERMS = new Set([
  "security",
  "json",
  "api",
  "validation",
  "implementing",
  "testing",
  "continuous",
  "with",
  "for",
  "skill",
  "skills",
  "agent",
  "workflow",
  "building",
  "performing",
  "detecting",
  "analyzing",
  "using",
  "review",
  "application",
  "web",
  "the",
  "and",
  "from",
  "test",
  "tests",
  "tool",
  "tools",
  "based",
  "assessment",
  "bas",
]);

const DOMAIN_SIGNALS: Record<string, string[]> = {
  kubernetes: ["kubernetes", "k8s", "rbac", "kube", "helm", "pod", "namespace"],
  cloud: ["aws", "azure", "gcp", "cloud", "lambda", "s3", "ec2"],
  firmware: ["firmware", "uefi", "chipsec", "bios"],
  phishing: ["phishing", "bec", "spear-phishing"],
  graph: ["graphrunner", "graph-runner", "microsoft-graph", "msal", "office365"],
  malware: ["malware", "cryptomining", "ransomware"],
  forensics: ["forensics", "siem", "incident-response", "intrusion", "edr", "velociraptor", "crowdstrike"],
  compliance: ["nist", "rmf", "fedramp", "cis-benchmark"],
};

const SURFACE_SKILL_HINTS: Record<string, string[]> = {
  api: ["api", "rest", "endpoint", "owasp", "bola", "authorization", "schema", "graphql", "websocket"],
  auth: ["auth", "authentication", "authorization", "access-control", "oauth", "jwt", "session", "login"],
  secrets: ["secret", "credential", "env", "config", "token", "key"],
  dependency: ["dependency", "supply-chain", "package", "npm", "composer"],
  validation: ["validation", "schema", "input", "sanitization"],
};

const EXCLUDED_INVENTORY_PREFIXES = [
  "skills/external/",
  "skills/drafts/",
  "skills/rejected/",
  "node_modules/",
  "__pycache__/",
  ".pytest_cache/",
  "egg-info/",
  ".git/",
];

const STOP_PATH_SEGMENTS = new Set([
  "src",
  "lib",
  "core",
  "config",
  "cli",
  "skills",
  "agents",
  "agent",
  "models",
  "model",
  "types",
  "shared",
  "tests",
  "test",
  "index",
  "graph",
  "nodes",
  "runtime",
  "scanner",
  "verifier",
  "findings",
  "external",
  "cyber",
  "swarm",
  "tools",
  "scripts",
  "utils",
  "common",
  "internal",
  "init",
  "load",
  "paths",
]);

const CONFIG_FILE_NAMES = new Set([
  "package.json",
  "pyproject.toml",
  "tsconfig.json",
  "vitest.config.ts",
  ".env",
  ".env.example",
  "composer.json",
  "requirements.txt",
]);

export interface RepoEvidenceMatch {
  token: string;
  reason: string;
  weight: number;
}

export interface RepoEvidence {
  keywords: Map<string, RepoEvidenceMatch[]>;
  detectedDomains: Set<string>;
  hasApiSurfaces: boolean;
  hasAuthSurfaces: boolean;
  hasSecretsSignals: boolean;
  hasDependencySignals: boolean;
}

function normalizeToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function isExcludedInventoryPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  return EXCLUDED_INVENTORY_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function addEvidence(
  evidence: RepoEvidence,
  token: string,
  reason: string,
  weight: number,
): void {
  const normalized = normalizeToken(token);
  if (!normalized || normalized.length < 2) {
    return;
  }

  const existing = evidence.keywords.get(normalized) ?? [];
  if (!existing.some((item) => item.reason === reason)) {
    existing.push({ token: normalized, reason, weight });
    evidence.keywords.set(normalized, existing);
  }

  for (const [domain, signals] of Object.entries(DOMAIN_SIGNALS)) {
    if (signals.includes(normalized)) {
      evidence.detectedDomains.add(domain);
    }
  }
}

function basenameWithoutExt(path: string): string {
  const base = path.split(/[\\/]/).pop() ?? path;
  return base.replace(/\.[^.]+$/, "");
}

function isProjectSourcePath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/");
  return (
    normalized.startsWith("src/") ||
    normalized.startsWith("agent_runtime/cyber_swarm/") ||
    CONFIG_FILE_NAMES.has(basenameWithoutExt(path)) ||
    normalized === ".env"
  );
}

export function collectRepoEvidence(report: ScanReport): RepoEvidence {
  const evidence: RepoEvidence = {
    keywords: new Map(),
    detectedDomains: new Set(),
    hasApiSurfaces: false,
    hasAuthSurfaces: false,
    hasSecretsSignals: false,
    hasDependencySignals: false,
  };

  for (const stack of report.stack ?? []) {
    addEvidence(evidence, stack.name, `stack: ${stack.name}`, 5);
    for (const token of STACK_KEYWORDS[stack.name] ?? []) {
      addEvidence(evidence, token, `stack: ${stack.name}`, 4);
    }
    for (const file of stack.evidence) {
      const base = basenameWithoutExt(file);
      addEvidence(evidence, base, `stack evidence: ${file}`, 4);
      if (base === "package-json" || file.endsWith("package.json")) {
        evidence.hasDependencySignals = true;
      }
    }
  }

  const surfaces = report.surfaces;
  if (surfaces) {
    for (const route of [...surfaces.routes, ...surfaces.api]) {
      evidence.hasApiSurfaces = true;
      addEvidence(evidence, route.path, `route: ${route.path}`, 5);
      addEvidence(evidence, route.file, `route handler: ${route.file}`, 4);
      if (route.framework) {
        addEvidence(evidence, route.framework, `route framework: ${route.framework}`, 3);
      }
      for (const segment of route.path.split("/")) {
        if (segment && segment !== "api" && segment !== "v1") {
          addEvidence(evidence, segment, `route segment: ${route.path}`, 4);
        }
      }
    }

    for (const auth of surfaces.auth) {
      evidence.hasAuthSurfaces = true;
      addEvidence(evidence, auth.file, `auth surface: ${auth.file}`, 5);
      if (auth.type) {
        addEvidence(evidence, auth.type, `auth type: ${auth.type}`, 4);
      }
      if (auth.file.includes(".env")) {
        evidence.hasSecretsSignals = true;
      }
    }

    for (const model of surfaces.dataModels) {
      if (model.name) {
        addEvidence(evidence, model.name, `data model: ${model.name}`, 4);
      }
      addEvidence(evidence, model.file, `data model file: ${model.file}`, 4);
    }

    if (evidence.hasApiSurfaces) {
      for (const hint of SURFACE_SKILL_HINTS.api) {
        addEvidence(evidence, hint, "inferred: API surfaces detected", 3);
      }
    }
    if (evidence.hasAuthSurfaces) {
      for (const hint of SURFACE_SKILL_HINTS.auth) {
        addEvidence(evidence, hint, "inferred: auth surfaces detected", 3);
      }
    }
  }

  for (const file of report.inventory.files) {
    if (isExcludedInventoryPath(file.path)) {
      continue;
    }

    if (!isProjectSourcePath(file.path) && file.category !== "config") {
      continue;
    }

    const base = basenameWithoutExt(file.path);
    if (CONFIG_FILE_NAMES.has(base) || file.path.endsWith("package.json")) {
      evidence.hasDependencySignals = true;
      addEvidence(evidence, base, `config: ${file.path}`, 4);
    }

    if (file.path.includes(".env")) {
      evidence.hasSecretsSignals = true;
      addEvidence(evidence, "env", `config: ${file.path}`, 5);
      addEvidence(evidence, "secret", `config: ${file.path}`, 4);
    }

    if (file.category === "typescript" || file.category === "python") {
      addEvidence(evidence, file.category, `source category: ${file.category}`, 3);
    }

    for (const segment of file.path.split(/[\\/]/)) {
      const token = normalizeToken(segment.replace(/\.[^.]+$/, ""));
      if (
        token.length >= 4 &&
        !GENERIC_TERMS.has(token) &&
        !STOP_PATH_SEGMENTS.has(token)
      ) {
        addEvidence(evidence, token, `source file: ${file.path}`, 2);
      }
    }
  }

  if (evidence.hasSecretsSignals) {
    for (const hint of SURFACE_SKILL_HINTS.secrets) {
      addEvidence(evidence, hint, "inferred: secrets/config signals", 3);
    }
  }

  return evidence;
}

function skillDomainTokens(skill: SkillIndexEntry): Set<string> {
  const corpus = [
    skill.name,
    skill.domain ?? "",
    skill.subdomain ?? "",
    skill.description,
    ...skill.tags,
  ]
    .join(" ")
    .toLowerCase();

  const domains = new Set<string>();
  for (const [domain, signals] of Object.entries(DOMAIN_SIGNALS)) {
    if (signals.some((signal) => corpus.includes(signal))) {
      domains.add(domain);
    }
  }
  return domains;
}

function skillMatchTokens(skill: SkillIndexEntry): string[] {
  const tokens = new Set<string>();
  const fullName = normalizeToken(skill.name);

  for (const tag of skill.tags) {
    tokens.add(normalizeToken(tag));
  }

  for (const word of skill.description.split(/\s+/)) {
    const normalized = normalizeToken(word);
    if (normalized.length >= 3) {
      tokens.add(normalized);
    }
  }

  for (const segment of skill.name.split("-")) {
    const normalized = normalizeToken(segment);
    if (normalized.length >= 3 && normalized !== fullName) {
      tokens.add(normalized);
    }
  }

  tokens.delete(fullName);
  tokens.delete("");
  return [...tokens];
}

function inferAgentTypes(skill: SkillIndexEntry, matchedTokens: string[]): string[] {
  const agents = new Set<string>();
  const corpus = [
    ...skill.tags,
    skill.name,
    skill.subdomain ?? "",
    skill.domain ?? "",
    skill.description,
    ...matchedTokens,
  ]
    .join(" ")
    .toLowerCase();

  for (const [agent, hints] of Object.entries(AGENT_TAG_MAP)) {
    if (hints.some((hint) => corpus.includes(hint))) {
      agents.add(agent);
    }
  }

  if (agents.size === 0) {
    agents.add("recon");
  }

  return [...agents].sort();
}

function surfaceBoost(skill: SkillIndexEntry, evidence: RepoEvidence): number {
  let boost = 0;
  const corpus = [
    skill.name,
    skill.description,
    ...skill.tags,
    skill.domain ?? "",
    skill.subdomain ?? "",
  ]
    .join(" ")
    .toLowerCase();

  if (evidence.hasApiSurfaces) {
    if (SURFACE_SKILL_HINTS.api.some((hint) => corpus.includes(hint))) {
      boost += 3;
    }
  }
  if (evidence.hasAuthSurfaces) {
    if (SURFACE_SKILL_HINTS.auth.some((hint) => corpus.includes(hint))) {
      boost += 3;
    }
  }
  if (evidence.hasSecretsSignals) {
    if (SURFACE_SKILL_HINTS.secrets.some((hint) => corpus.includes(hint))) {
      boost += 3;
    }
  }
  if (evidence.hasDependencySignals) {
    if (SURFACE_SKILL_HINTS.dependency.some((hint) => corpus.includes(hint))) {
      boost += 2;
    }
  }

  return boost;
}

function reasonPriority(reason: string): number {
  return reason.startsWith("inferred:") ? 1 : 0;
}

function hasUnsupportedDomain(skill: SkillIndexEntry, evidence: RepoEvidence): boolean {
  const skillDomains = skillDomainTokens(skill);
  for (const domain of skillDomains) {
    if (!evidence.detectedDomains.has(domain)) {
      return true;
    }
  }
  return false;
}

export function scoreSkill(skill: SkillIndexEntry, evidence: RepoEvidence): RoutedSkillSelection | null {
  if (hasUnsupportedDomain(skill, evidence)) {
    return null;
  }

  const tokens = skillMatchTokens(skill);
  const reasons: string[] = [];
  let score = 0;
  let concreteMatches = 0;

  for (const token of tokens) {
    const matches = evidence.keywords.get(token);
    if (!matches || matches.length === 0) {
      continue;
    }

    const isGeneric = GENERIC_TERMS.has(token);
    for (const match of matches) {
      const weight = isGeneric ? Math.max(1, Math.floor(match.weight / 2)) : match.weight;
      score += weight;
      reasons.push(match.reason);

      if (!isGeneric && match.weight >= 2) {
        concreteMatches += 1;
      }
    }
  }

  for (const tag of skill.tags) {
    const normalized = normalizeToken(tag);
    const matches = evidence.keywords.get(normalized);
    if (!matches) {
      continue;
    }
    const isGeneric = GENERIC_TERMS.has(normalized);
    for (const match of matches) {
      score += isGeneric ? 1 : 4;
      reasons.push(`tag ${tag} -> ${match.reason}`);
      if (!isGeneric) {
        concreteMatches += 1;
      }
    }
  }

  score += surfaceBoost(skill, evidence);

  if (concreteMatches === 0 || score === 0) {
    return null;
  }

  const normalizedScore = Math.min(1, score / 12);
  if (normalizedScore < 0.2) {
    return null;
  }

  const uniqueReasons = [...new Set(reasons)]
    .sort((left, right) => reasonPriority(left) - reasonPriority(right))
    .slice(0, 5);
  const matchedTokens = tokens.filter((token) => evidence.keywords.has(token));

  return {
    name: skill.name,
    path: skill.path,
    score: Number(normalizedScore.toFixed(2)),
    reasons: uniqueReasons,
    agentTypes: inferAgentTypes(skill, matchedTokens),
  };
}

export function routeSkills(
  report: ScanReport,
  index: { skills: SkillIndexEntry[] },
  limit = 15,
): RoutedSkillSelection[] {
  const evidence = collectRepoEvidence(report);

  const scored = index.skills
    .map((skill) => scoreSkill(skill, evidence))
    .filter((entry): entry is RoutedSkillSelection => entry !== null)
    .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  return scored.slice(0, limit);
}

export function readScanReport(reportPath: string): ScanReport {
  const resolved = resolve(reportPath);
  if (!existsSync(resolved)) {
    throw new SkillsError(`Scan report not found at ${resolved}`, "INVALID_REPORT");
  }

  return JSON.parse(readFileSync(resolved, "utf8")) as ScanReport;
}

export function routeSkillsFromReport(
  root: string,
  config: SwarmConfig,
  reportPath: string,
): RouteResult {
  const report = readScanReport(reportPath);
  const index = readSkillsIndex(root, config);
  const selected = routeSkills(report, index);

  const loaded = loadSkillBodies(root, selected);

  const output: RoutedSkillsOutput = {
    reportPath: resolve(reportPath),
    routedAt: new Date().toISOString(),
    selected,
    loaded,
  };

  const outputPath = getRoutedSkillsPath(root, config);
  mkdirSync(join(root, config.cacheDir), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`, "utf8");

  return { outputPath, output };
}

export function printRouteSummary(output: RoutedSkillsOutput, outputPath: string): void {
  console.log(`Routed skills: ${output.selected.length}`);
  for (const skill of output.selected.slice(0, 10)) {
    const reason = skill.reasons[0] ?? "matched repo signals";
    console.log(`  ${skill.name} (${skill.score}) — ${reason}`);
    console.log(`    path: ${skill.path}`);
  }
  if (output.selected.length > 10) {
    console.log(`  … and ${output.selected.length - 10} more`);
  }
  console.log(`Loaded bodies: ${output.loaded.length}`);
  console.log(`Routed cache: ${outputPath}`);
}
