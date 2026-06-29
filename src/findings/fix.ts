import type { VerifiedFinding } from "./types";

interface FixTemplate {
  summary: string;
  changes: string[];
  validation: string[];
}

const FIX_TEMPLATES: Record<string, FixTemplate> = {
  "broken-access-control": {
    summary: "Enforce authentication and authorization before sensitive route handlers execute.",
    changes: [
      "Audit route handlers for missing auth middleware or guard checks.",
      "Apply consistent auth middleware to all protected routes in affected files.",
      "Add explicit role or scope checks where handlers mutate sensitive data.",
      "Return 401/403 for unauthenticated or unauthorized requests instead of falling through.",
    ],
    validation: [
      "Review affected route files and confirm every protected endpoint invokes auth middleware.",
      "Run static tests or route inventory checks to ensure no unprotected handlers remain.",
      "Verify safe reproduction steps still pass after auth guards are added.",
    ],
  },
  "secret-exposure": {
    summary: "Remove secrets from source control and load credentials from environment or a secret manager.",
    changes: [
      "Remove credential-like values from tracked files and rotate exposed secrets.",
      "Load secrets from environment variables or a managed secret store at runtime.",
      "Add pre-commit or CI checks to block credential patterns in new commits.",
      "Replace hard-coded keys with references to secure configuration.",
    ],
    validation: [
      "Confirm affected files no longer contain credential-like literals.",
      "Verify application reads secrets from environment or secret manager.",
      "Run repository secret scan locally before committing.",
    ],
  },
};

const DEFAULT_FIX_TEMPLATE: FixTemplate = {
  summary: "Address the verified issue using evidence-backed, minimal changes in affected files.",
  changes: [
    "Review the cited evidence locations and confirm the vulnerable behavior.",
    "Apply the smallest change that removes the unsafe behavior.",
    "Add regression coverage or static checks to prevent recurrence.",
  ],
  validation: [
    "Re-run the safe reproduction steps from the finding report.",
    "Confirm affected routes or files no longer exhibit the reported behavior.",
    "Review related files for the same vulnerability class.",
  ],
};

export function formatFixPlan(finding: VerifiedFinding, reportPath: string): string {
  const template = FIX_TEMPLATES[finding.vulnerability_class] ?? DEFAULT_FIX_TEMPLATE;
  const lines: string[] = [];

  lines.push(`Patch plan: ${finding.id}`);
  lines.push("=".repeat(Math.max(24, finding.id.length + 12)));
  lines.push(`Report: ${reportPath}`);
  lines.push(`Title: ${finding.title}`);
  lines.push(`Class: ${finding.vulnerability_class}`);
  lines.push(`Severity: ${finding.severity}  Confidence: ${finding.confidence}`);
  lines.push("");
  lines.push("Summary");
  lines.push(template.summary);
  lines.push("");
  lines.push("Affected files");
  if (finding.affected_files.length === 0) {
    lines.push("  - (none listed — inspect evidence paths below)");
  } else {
    for (const file of finding.affected_files) {
      lines.push(`  - ${file}`);
    }
  }
  lines.push("");
  lines.push("Likely fix locations");
  const locations = collectFixLocations(finding);
  for (const location of locations) {
    lines.push(`  - ${location}`);
  }
  lines.push("");
  lines.push("Recommended changes");
  for (const [index, change] of template.changes.entries()) {
    lines.push(`  ${index + 1}. ${change}`);
  }
  lines.push("");
  lines.push("Evidence basis");
  for (const item of finding.evidence) {
    const path = item.path ?? item.route ?? "unknown";
    lines.push(`  - [${item.type}] ${path}: ${item.explanation}`);
  }
  lines.push("");
  lines.push("Validation steps");
  for (const [index, step] of template.validation.entries()) {
    lines.push(`  ${index + 1}. ${step}`);
  }
  if (finding.safe_reproduction.steps.length > 0) {
    lines.push(`  ${template.validation.length + 1}. Safe reproduction (${finding.safe_reproduction.mode}):`);
    for (const step of finding.safe_reproduction.steps) {
      lines.push(`     - ${step}`);
    }
  }
  lines.push("");
  lines.push("Note: Suggested patch plan only — no files were modified.");

  return lines.join("\n");
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
      continue;
    }
    if (item.route) {
      locations.add(`route ${item.route}`);
    }
  }

  for (const surface of finding.affected_surfaces) {
    if (surface.startsWith("/")) {
      locations.add(`route ${surface}`);
    }
  }

  if (locations.size === 0) {
    locations.add("(inspect evidence and affected surfaces)");
  }

  return [...locations];
}
