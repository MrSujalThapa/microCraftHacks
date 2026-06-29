import type { VerifiedFinding } from "./types";

export function isDemoReady(finding: VerifiedFinding): boolean {
  return finding.demo_ready === true;
}

export function sortFindingsForDisplay(findings: VerifiedFinding[]): VerifiedFinding[] {
  return [...findings].sort((left, right) => {
    const leftDemo = isDemoReady(left) ? 0 : 1;
    const rightDemo = isDemoReady(right) ? 0 : 1;
    if (leftDemo !== rightDemo) {
      return leftDemo - rightDemo;
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const severityDelta =
      severityOrder[left.severity] - severityOrder[right.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }

    return right.ranking_rationale.total_score - left.ranking_rationale.total_score;
  });
}

export function filterDemoFindings(findings: VerifiedFinding[]): VerifiedFinding[] {
  return sortFindingsForDisplay(findings.filter(isDemoReady));
}
