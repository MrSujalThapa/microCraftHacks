import { assessEvidenceStrictness } from "./evidenceStrict";
import { isDemoReady } from "./demoQuality";
import type { VerifiedFinding } from "./types";
import { redactSecrets } from "../shared/redaction";

interface FixTemplate {
  summary: string;
  changes: string[];
  validation: string[];
}

const FIX_TEMPLATES: Record<string, FixTemplate> = {
  "broken-access-control": {
    summary: "Enforce authentication and authorization before sensitive route handlers execute.",
    changes: [],
    validation: [
      "Confirm protected handlers invoke auth middleware or guards.",
      "Run static route inventory checks for unprotected endpoints.",
    ],
  },
  "secret-exposure": {
    summary: "Remove secrets from source control and load credentials from environment or a secret manager.",
    changes: [],
    validation: [
      "Confirm affected files no longer contain credential-like literals.",
      "Verify runtime reads secrets from environment or secret manager.",
      "Ensure .env is listed in .gitignore and never committed.",
      "Keep .env.example with placeholder values only.",
    ],
  },
  bola: {
    summary: "Enforce object ownership checks before data access using the authenticated user's identity.",
    changes: [],
    validation: [
      "Create resource as user A; request with user B's token and a different owner_id; expect 403.",
      "Assert queries filter by owner_id or tenant_id from the auth context, not from request params alone.",
    ],
  },
  "privilege-escalation": {
    summary: "Replace service-role/admin clients in request handlers with user-scoped clients protected by RLS.",
    changes: [],
    validation: [
      "Confirm route handlers use anon/user-scoped Supabase clients only.",
      "Integration test with anon key must not access other tenants' rows.",
    ],
  },
  "ai-action-abuse": {
    summary: "Gate AI/tool actions behind approval, role checks, or tenant boundaries before execution.",
    changes: [],
    validation: [
      "Call action endpoint without approval flag; assert tool/LLM is not invoked.",
      "Verify non-admin users cannot trigger side-effecting tool calls.",
    ],
  },
};

export function formatFixRefusal(findingId: string, reasons: string[]): string {
  const lines = [
    `Cannot generate concrete patch plan: ${findingId}`,
    "=".repeat(Math.max(40, findingId.length + 32)),
    "",
    "This finding is not evidence-strict enough for automated patch guidance.",
    "",
    "Reasons:",
    ...reasons.map((reason) => `  - ${reason}`),
    "",
    "Provide concrete file-level evidence (path, line range, function/route name, and the",
    "specific missing or incorrect check) before requesting a patch plan.",
    "",
    "Note: No files were modified.",
  ];
  return lines.join("\n");
}

export function formatFixPlan(
  finding: VerifiedFinding,
  reportPath: string,
  evidencePacks: import("./types").EvidencePack[] | undefined = undefined,
): string {
  const strictness = assessEvidenceStrictness(finding);
  const secretWithEnvEvidence = hasSecretExposureEvidence(finding);
  if (!strictness.strict && !secretWithEnvEvidence) {
    return formatFixRefusal(finding.id, strictness.reasons);
  }

  const template = FIX_TEMPLATES[finding.vulnerability_class];
  const lines: string[] = [];

  lines.push(`Patch plan: ${finding.id}`);
  lines.push("=".repeat(Math.max(24, finding.id.length + 12)));
  lines.push(`Report: ${reportPath}`);
  lines.push(`Title: ${redactSecrets(finding.title)}`);
  lines.push(`Class: ${finding.vulnerability_class}`);
  lines.push(`Severity: ${finding.severity}  Confidence: ${finding.confidence}`);
  lines.push(`Demo ready: ${isDemoReady(finding) ? "yes" : "no"}`);
  if (!isDemoReady(finding)) {
    lines.push("");
    lines.push("Warning: This finding is not demo-ready. Review evidence before applying patches.");
    if (finding.demo_reason) {
      lines.push(`Reason: ${finding.demo_reason}`);
    }
  }
  lines.push("");
  lines.push("Summary");
  lines.push(template?.summary ?? redactSecrets(finding.claim));
  lines.push("");
  lines.push("Affected surfaces");
  if (finding.affected_surfaces.length === 0) {
    lines.push("  - (none)");
  } else {
    for (const surface of finding.affected_surfaces) {
      lines.push(`  - ${surface}`);
    }
  }
  lines.push("");
  lines.push("Affected files");
  for (const file of finding.affected_files) {
    lines.push(`  - ${file}`);
  }
  lines.push("");
  lines.push("Concrete fix locations");
  for (const location of collectFixLocations(finding)) {
    lines.push(`  - ${location}`);
  }
  if (finding.graph_path?.missing_guard) {
    lines.push("");
    lines.push("Graph remediation");
    lines.push(`  Trust boundary: ${finding.graph_path.trust_boundary_crossed}`);
    lines.push(`  Add guard: ${finding.graph_path.missing_guard}`);
    lines.push(`  Path: ${finding.graph_path.path_description}`);
  }
  lines.push("");
  lines.push("Recommended changes");
  const changes = buildConcreteChanges(finding, template, evidencePacks);
  for (const [index, change] of changes.entries()) {
    lines.push(`  ${index + 1}. ${change}`);
  }
  lines.push("");
  lines.push("Evidence basis");
  for (const item of finding.evidence) {
    const path = item.path ?? "unknown";
    const range =
      item.line_start != null
        ? `:${item.line_start}${item.line_end != null ? `-${item.line_end}` : ""}`
        : "";
    lines.push(`  - [${item.type}] ${path}${range}: ${redactSecrets(item.explanation)}`);
    const snippet = resolveFixSnippet(item, evidencePacks);
    if (snippet) {
      lines.push(`    snippet: ${redactSecrets(snippet.split("\n")[0]!)}`);
    }
  }
  lines.push("");
  lines.push("Validation steps");
  const validation = template?.validation ?? [
    "Re-run the safe reproduction steps from the finding report.",
  ];
  for (const [index, step] of validation.entries()) {
    lines.push(`  ${index + 1}. ${step}`);
  }
  if (finding.safe_reproduction.steps.length > 0) {
    lines.push(`  ${validation.length + 1}. Safe reproduction (${finding.safe_reproduction.mode}):`);
    for (const step of finding.safe_reproduction.steps) {
      lines.push(`     - ${redactSecrets(step)}`);
    }
  }
  lines.push("");
  lines.push("Note: Suggested patch plan only — no files were modified.");

  return lines.join("\n");
}

function buildConcreteChanges(
  finding: VerifiedFinding,
  template: FixTemplate | undefined,
  evidencePacks: import("./types").EvidencePack[] | undefined,
): string[] {
  if (finding.vulnerability_class === "secret-exposure") {
    return buildSecretRemediationChanges(finding);
  }

  const changes: string[] = [];

  for (const item of finding.evidence) {
    if (!item.path) {
      continue;
    }
    const location =
      item.line_start != null
        ? `${item.path}:${item.line_start}${item.line_end != null ? `-${item.line_end}` : ""}`
        : item.path;
    const symbol = item.symbol ? ` (${item.symbol})` : "";
    const snippet = resolveFixSnippet(item, evidencePacks);
    const snippetHint = snippet ? ` — see: ${redactSecrets(snippet.split("\n")[0]!)}` : "";
    changes.push(`Patch ${location}${symbol} — ${redactSecrets(item.explanation)}${snippetHint}`);
  }

  if (changes.length === 0) {
    for (const file of finding.affected_files) {
      changes.push(`Review and patch ${file} to address: ${redactSecrets(finding.claim)}`);
    }
  }

  if (template?.changes.length) {
    changes.push(...template.changes);
  }

  return changes;
}

function buildSecretRemediationChanges(finding: VerifiedFinding): string[] {
  const envFiles = collectSecretEnvFiles(finding);
  const keyNames = collectSecretKeyNames(finding);
  const changes: string[] = [];

  for (const file of envFiles) {
    changes.push(`Remove committed secret values from ${file} and purge the file from git history if tracked.`);
    if (keyNames.length > 0) {
      for (const keyName of keyNames) {
        changes.push(`Rotate the exposed ${keyName} at the provider; treat the committed value as compromised.`);
      }
    } else {
      changes.push(`Rotate any exposed credentials referenced in ${file}.`);
    }
    changes.push(`Ensure ${file} is listed in .gitignore and never committed again.`);
    changes.push(`Keep ${envExamplePath(file)} with placeholder values only (for example ${placeholderKey(keyNames)}=<your-secret-here>).`);
    changes.push(`Load live values from runtime environment variables or a secret manager instead of ${file}.`);
  }

  if (changes.length === 0) {
    changes.push("Remove committed secret values from tracked configuration files and purge from git history.");
    changes.push("Rotate any exposed credential keys at the provider (never rotate placeholder redaction tokens).");
    changes.push("Ensure .env and other secret files are listed in .gitignore.");
    changes.push("Keep .env.example with placeholder values only.");
    changes.push("Load credentials from runtime environment variables or a secret manager.");
  }

  return changes;
}

function collectSecretEnvFiles(finding: VerifiedFinding): string[] {
  const files = new Set<string>();
  for (const file of finding.affected_files) {
    if (isEnvLikePath(file)) {
      files.add(file);
    }
  }
  for (const item of finding.evidence) {
    if (item.path && isEnvLikePath(item.path)) {
      files.add(item.path);
    }
  }
  return [...files];
}

function collectSecretKeyNames(finding: VerifiedFinding): string[] {
  const keys = new Set<string>();
  const keyPattern =
    /\b([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY))\b/g;

  for (const item of finding.evidence) {
    if (item.symbol && !item.symbol.startsWith("NEXT_PUBLIC_") && isRealSecretKeyName(item.symbol)) {
      keys.add(item.symbol);
    }
    for (const source of [item.explanation, item.snippet, finding.claim]) {
      if (!source) {
        continue;
      }
      for (const match of source.matchAll(keyPattern)) {
        const keyName = match[1]!;
        if (isRealSecretKeyName(keyName)) {
          keys.add(keyName);
        }
      }
    }
  }

  return [...keys];
}

function isRealSecretKeyName(key: string): boolean {
  if (key === "REDACTED_SECRET" || key.startsWith("REDACTED")) {
    return false;
  }
  if (/^API_KEY$/i.test(key) && key === "API_KEY") {
    return true;
  }
  return key.length > 0;
}

function isEnvLikePath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  return normalized.includes(".env") || normalized.endsWith(".env");
}

function envExamplePath(envPath: string): string {
  const normalized = envPath.replace(/\\/g, "/");
  const parts = normalized.split("/");
  const fileName = parts.pop() ?? ".env";
  if (fileName.startsWith(".env.")) {
    return [...parts, fileName].filter(Boolean).join("/") || fileName;
  }
  const directory = parts.join("/");
  return directory ? `${directory}/.env.example` : ".env.example";
}

function placeholderKey(keyNames: string[]): string {
  return keyNames[0] ?? "API_KEY";
}

function hasSecretExposureEvidence(finding: VerifiedFinding): boolean {
  if (finding.vulnerability_class !== "secret-exposure") {
    return false;
  }
  return (
    finding.affected_files.some(isEnvLikePath) ||
    finding.evidence.some((item) => item.path != null && isEnvLikePath(item.path))
  );
}

function collectFixLocations(finding: VerifiedFinding): string[] {
  const locations = new Set<string>();

  for (const file of finding.affected_files) {
    locations.add(file);
  }

  for (const item of finding.evidence) {
    if (item.path && item.line_start != null) {
      const end = item.line_end != null ? `-${item.line_end}` : "";
      locations.add(`${item.path}:${item.line_start}${end}`);
      continue;
    }
    if (item.path) {
      locations.add(item.path);
    }
  }

  for (const surface of finding.affected_surfaces) {
    if (surface.startsWith("/")) {
      locations.add(`route ${surface}`);
    }
  }

  return [...locations];
}

function resolveFixSnippet(
  item: VerifiedFinding["evidence"][number],
  evidencePacks: import("./types").EvidencePack[] | undefined,
): string | undefined {
  if (item.snippet?.trim()) {
    return item.snippet;
  }
  if (!item.evidence_pack_id || !evidencePacks?.length) {
    return undefined;
  }
  return evidencePacks.find((pack) => pack.id === item.evidence_pack_id)?.snippet;
}
