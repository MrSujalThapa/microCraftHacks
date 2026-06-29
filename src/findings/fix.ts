import { assessEvidenceStrictness } from "./evidenceStrict";
import type { VerifiedFinding } from "./types";

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

export function formatFixPlan(finding: VerifiedFinding, reportPath: string): string {
  const strictness = assessEvidenceStrictness(finding);
  if (!strictness.strict) {
    return formatFixRefusal(finding.id, strictness.reasons);
  }

  const template = FIX_TEMPLATES[finding.vulnerability_class];
  const lines: string[] = [];

  lines.push(`Patch plan: ${finding.id}`);
  lines.push("=".repeat(Math.max(24, finding.id.length + 12)));
  lines.push(`Report: ${reportPath}`);
  lines.push(`Title: ${finding.title}`);
  lines.push(`Class: ${finding.vulnerability_class}`);
  lines.push(`Severity: ${finding.severity}  Confidence: ${finding.confidence}`);
  lines.push("");
  lines.push("Summary");
  lines.push(template?.summary ?? finding.claim);
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
  lines.push("");
  lines.push("Recommended changes");
  const changes = buildConcreteChanges(finding, template);
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
    lines.push(`  - [${item.type}] ${path}${range}: ${item.explanation}`);
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
      lines.push(`     - ${step}`);
    }
  }
  lines.push("");
  lines.push("Note: Suggested patch plan only — no files were modified.");

  return lines.join("\n");
}

function buildConcreteChanges(
  finding: VerifiedFinding,
  template: FixTemplate | undefined,
): string[] {
  const changes: string[] = [];

  for (const item of finding.evidence) {
    if (!item.path) {
      continue;
    }
    const location =
      item.line_start != null
        ? `${item.path}:${item.line_start}${item.line_end != null ? `-${item.line_end}` : ""}`
        : item.path;
    changes.push(`Patch ${location} — ${item.explanation}`);
  }

  if (changes.length === 0) {
    for (const file of finding.affected_files) {
      changes.push(`Review and patch ${file} to address: ${finding.claim}`);
    }
  }

  if (template?.changes.length) {
    changes.push(...template.changes);
  }

  return changes;
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
