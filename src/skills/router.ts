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
  api: ["api", "rest", "graphql", "endpoint", "mutation"],
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
  Express: ["express", "api", "nodejs", "node", "rest"],
  FastAPI: ["fastapi", "python", "api", "rest"],
  Django: ["django", "python", "web"],
  "Spring Boot": ["spring", "java", "api"],
  Supabase: ["supabase", "database", "auth", "storage"],
  Prisma: ["prisma", "database", "orm", "sql"],
  "Tailwind CSS": ["tailwind", "frontend", "css"],
  Docker: ["docker", "container", "deployment"],
  "GitHub Actions": ["github", "ci", "pipeline", "workflow"],
};

function normalizeToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function collectReportKeywords(report: ScanReport): Set<string> {
  const keywords = new Set<string>();

  for (const stack of report.stack ?? []) {
    keywords.add(normalizeToken(stack.name));
    for (const token of STACK_KEYWORDS[stack.name] ?? []) {
      keywords.add(token);
    }
    for (const evidence of stack.evidence) {
      const base = evidence.split(/[\\/]/).pop() ?? evidence;
      keywords.add(normalizeToken(base.replace(/\.[^.]+$/, "")));
    }
  }

  const surfaces = report.surfaces;
  if (surfaces) {
    for (const route of [...surfaces.routes, ...surfaces.api]) {
      for (const segment of route.path.split("/")) {
        if (segment) {
          keywords.add(normalizeToken(segment));
        }
      }
      keywords.add(normalizeToken(route.framework ?? ""));
    }

    for (const auth of surfaces.auth) {
      for (const segment of auth.file.split(/[\\/]/)) {
        keywords.add(normalizeToken(segment.replace(/\.[^.]+$/, "")));
      }
      if (auth.type) {
        keywords.add(normalizeToken(auth.type));
      }
    }

    for (const model of surfaces.dataModels) {
      if (model.name) {
        keywords.add(normalizeToken(model.name));
      }
    }
  }

  for (const file of report.inventory.files) {
    keywords.add(normalizeToken(file.category));
    for (const segment of file.path.split(/[\\/]/)) {
      keywords.add(normalizeToken(segment.replace(/\.[^.]+$/, "")));
    }
  }

  keywords.delete("");
  return keywords;
}

function skillTokens(skill: SkillIndexEntry): string[] {
  const tokens = new Set<string>();
  tokens.add(normalizeToken(skill.name));
  tokens.add(normalizeToken(skill.domain ?? ""));
  tokens.add(normalizeToken(skill.subdomain ?? ""));
  for (const tag of skill.tags) {
    tokens.add(normalizeToken(tag));
  }
  for (const word of skill.description.split(/\s+/)) {
    tokens.add(normalizeToken(word));
  }
  for (const word of skill.name.split("-")) {
    tokens.add(normalizeToken(word));
  }
  return [...tokens].filter(Boolean);
}

function inferAgentTypes(skill: SkillIndexEntry, matchedKeywords: string[]): string[] {
  const agents = new Set<string>();
  const corpus = [
    ...skill.tags,
    skill.name,
    skill.subdomain ?? "",
    skill.domain ?? "",
    skill.description,
    ...matchedKeywords,
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

function scoreSkill(skill: SkillIndexEntry, keywords: Set<string>): RoutedSkillSelection | null {
  const tokens = skillTokens(skill);
  const reasons: string[] = [];
  let score = 0;

  for (const token of tokens) {
    if (keywords.has(token)) {
      score += token.length > 3 ? 2 : 1;
      reasons.push(`matched keyword: ${token}`);
    }
  }

  for (const tag of skill.tags) {
    const normalized = normalizeToken(tag);
    if (keywords.has(normalized)) {
      score += 3;
      reasons.push(`matched tag: ${tag}`);
    }
  }

  if (score === 0) {
    return null;
  }

  const normalizedScore = Math.min(1, score / 10);
  const uniqueReasons = [...new Set(reasons)].slice(0, 5);

  return {
    name: skill.name,
    path: skill.path,
    score: Number(normalizedScore.toFixed(2)),
    reasons: uniqueReasons,
    agentTypes: inferAgentTypes(skill, uniqueReasons.map((r) => r.split(": ").pop() ?? "")),
  };
}

export function routeSkills(
  report: ScanReport,
  index: { skills: SkillIndexEntry[] },
  limit = 15,
): RoutedSkillSelection[] {
  const keywords = collectReportKeywords(report);

  const scored = index.skills
    .map((skill) => scoreSkill(skill, keywords))
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
