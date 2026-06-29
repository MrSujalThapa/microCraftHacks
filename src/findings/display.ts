import type { EvidencePack, FindingsReport, RejectedFinding, Severity, VerifiedFinding } from "./types";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function sortVerifiedFindings(findings: VerifiedFinding[]): VerifiedFinding[] {
  return [...findings].sort((left, right) => {
    const severityDelta = SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }
    return right.ranking_rationale.total_score - left.ranking_rationale.total_score;
  });
}

export function formatAffectedTarget(finding: VerifiedFinding): string {
  const route = finding.affected_surfaces[0];
  const file = finding.affected_files[0] ?? finding.evidence.find((item) => item.path)?.path;
  if (route && file) {
    return `${route} (${file})`;
  }
  return route ?? file ?? "—";
}

export function formatFindingsTable(report: FindingsReport, reportPath: string): string {
  const lines: string[] = [];
  const summary = report.metrics.summary;
  const verifiedCount = summary?.verifiedCount ?? report.verifiedFindings.length;
  const rejectedCount = summary?.rejectedCount ?? report.rejectedFindings.length;

  lines.push(`Findings report: ${reportPath}`);
  lines.push(`Scan: ${report.scanId}  Verified: ${verifiedCount}  Rejected: ${rejectedCount}`);
  lines.push("");

  if (report.verifiedFindings.length === 0) {
    lines.push("No verified findings.");
    return lines.join("\n");
  }

  const rows = sortVerifiedFindings(report.verifiedFindings).map((finding) => ({
    severity: finding.severity,
    confidence: finding.confidence,
    title: truncate(finding.title, 36),
    target: truncate(formatAffectedTarget(finding), 32),
    id: finding.id,
  }));

  const headers = ["SEVERITY", "CONF", "TITLE", "ROUTE/FILE", "ID"];
  const widths = [
    Math.max(headers[0]!.length, ...rows.map((row) => row.severity.length)),
    Math.max(headers[1]!.length, ...rows.map((row) => row.confidence.length)),
    Math.max(headers[2]!.length, ...rows.map((row) => row.title.length)),
    Math.max(headers[3]!.length, ...rows.map((row) => row.target.length)),
    Math.max(headers[4]!.length, ...rows.map((row) => row.id.length)),
  ];

  lines.push(formatRow(headers, widths));
  lines.push(widths.map((width) => "-".repeat(width)).join("  "));
  for (const row of rows) {
    lines.push(
      formatRow(
        [row.severity, row.confidence, row.title, row.target, row.id],
        widths,
      ),
    );
  }

  return lines.join("\n");
}

export function formatFindingExplanation(
  finding: VerifiedFinding,
  evidencePacks: EvidencePack[] | undefined = undefined,
): string {
  const lines: string[] = [];

  lines.push(`${finding.title} (${finding.id})`);
  lines.push(`Severity: ${finding.severity}  Confidence: ${finding.confidence}`);
  lines.push(`Class: ${finding.vulnerability_class}`);
  lines.push("");
  lines.push("Claim");
  lines.push(finding.claim);
  lines.push("");
  lines.push("Impact");
  lines.push(finding.impact_hypothesis);
  lines.push("");
  lines.push("Attack path");
  lines.push(finding.attack_path);
  lines.push("");
  lines.push("Affected surfaces");
  for (const surface of finding.affected_surfaces) {
    lines.push(`  - ${surface}`);
  }
  lines.push("");
  lines.push("Affected files");
  for (const file of finding.affected_files) {
    lines.push(`  - ${file}`);
  }
  lines.push("");
  lines.push("Evidence");
  for (const item of finding.evidence) {
    const location = formatEvidenceLocation(item);
    lines.push(`  - [${item.type}] ${location}: ${item.explanation}`);
    appendEvidenceSnippet(lines, item, evidencePacks);
  }
  lines.push("");
  lines.push("Safe reproduction");
  lines.push(`  Mode: ${finding.safe_reproduction.mode}`);
  for (const step of finding.safe_reproduction.steps) {
    lines.push(`  - ${step}`);
  }
  lines.push(`  Expected: ${finding.safe_reproduction.expected_result}`);
  if (finding.safe_reproduction.safety_notes.length > 0) {
    lines.push("  Safety notes:");
    for (const note of finding.safe_reproduction.safety_notes) {
      lines.push(`    - ${note}`);
    }
  }
  lines.push("");
  lines.push("Ranking rationale");
  for (const factor of finding.ranking_rationale.factors) {
    lines.push(`  - ${factor}`);
  }
  lines.push(`  Total score: ${finding.ranking_rationale.total_score.toFixed(2)}`);
  lines.push("");
  lines.push("Contributors");
  lines.push(`  Agents: ${finding.contributing_agents.join(", ") || "—"}`);
  lines.push(`  Specialists: ${finding.contributing_specialists.join(", ") || "—"}`);
  lines.push(`  Skills: ${finding.selected_skills.join(", ") || "—"}`);

  return lines.join("\n");
}

export function formatRejectedExplanation(
  finding: RejectedFinding,
  evidencePacks: EvidencePack[] | undefined = undefined,
): string {
  const lines: string[] = [];
  const id = finding.draft_id ?? finding.title ?? "rejected-finding";

  lines.push(`Rejected finding (${id})`);
  if (finding.title) {
    lines.push(`Title: ${finding.title}`);
  }
  lines.push(`Reason: ${finding.reason}`);
  lines.push("");

  if (finding.failed_checks?.length) {
    lines.push("Failed checks");
    for (const check of finding.failed_checks) {
      lines.push(`  - ${check}`);
    }
    lines.push("");
  }

  if (finding.missing_evidence?.length) {
    lines.push("Missing evidence");
    for (const item of finding.missing_evidence) {
      lines.push(`  - ${item}`);
    }
    lines.push("");
  }

  if (finding.evidence?.length) {
    lines.push("Evidence");
    for (const item of finding.evidence) {
      const location = formatEvidenceLocation(item);
      lines.push(`  - [${item.type}] ${location}: ${item.explanation}`);
      appendEvidenceSnippet(lines, item, evidencePacks);
    }
  }

  return lines.join("\n");
}

function appendEvidenceSnippet(
  lines: string[],
  item: VerifiedFinding["evidence"][number],
  evidencePacks: EvidencePack[] | undefined,
): void {
  const snippet = resolveEvidenceSnippet(item, evidencePacks);
  if (!snippet) {
    return;
  }
  lines.push("    ```");
  for (const line of snippet.split("\n")) {
    lines.push(`    ${line}`);
  }
  lines.push("    ```");
}

function resolveEvidenceSnippet(
  item: VerifiedFinding["evidence"][number],
  evidencePacks: EvidencePack[] | undefined,
): string | undefined {
  if (item.snippet?.trim()) {
    return item.snippet;
  }
  if (!item.evidence_pack_id || !evidencePacks?.length) {
    return undefined;
  }
  const pack = evidencePacks.find((candidate) => candidate.id === item.evidence_pack_id);
  return pack?.snippet;
}

function formatEvidenceLocation(item: VerifiedFinding["evidence"][number]): string {
  if (item.route && item.path) {
    return `${item.route} @ ${item.path}`;
  }
  if (item.path) {
    if (item.line_start != null) {
      const end = item.line_end != null ? `-${item.line_end}` : "";
      return `${item.path}:${item.line_start}${end}`;
    }
    return item.path;
  }
  return item.route ?? "unknown";
}

function formatRow(cells: string[], widths: number[]): string {
  return cells.map((cell, index) => cell.padEnd(widths[index]!)).join("  ");
}

function truncate(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, maxLength - 1)}…`;
}
