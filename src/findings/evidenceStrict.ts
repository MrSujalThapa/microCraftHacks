import type { VerifiedFinding } from "./types";

const HEDGE_LANGUAGE =
  /\b(potential|possible|may|might|could|should check|needs review|review needed|should review|requires review|appears to|seems to)\b/i;

const GENERIC_EVIDENCE =
  /supports?\s+(review|static|analysis|abuse|access-control)|security[- ]relevant|document routes|identify routes|inspect (the )?(identified )?(files|routes|handlers)|review (the )?(identified )?(files|routes|handlers|code)|map protected routes|without visible|that should enforce/i;

const CODE_ELEMENT =
  /\b(function|def\s+\w+|class\s+\w+|@app\.(get|post|put|patch|delete|route)|router\.(get|post)|middleware|guard|requireAuth|get_current_user|validate|schema|handler|endpoint|createClient|useSession|API_KEY|SECRET|password\s*=)/i;

const ABSTRACT_SURFACE = /<->|<|>|frontend|backend|trust boundary|service boundary/i;

const VALID_PATH = /^(?:[\w.-]+\/)+[\w.-]+\.(?:ts|tsx|js|jsx|py|json|yaml|yml|toml|md)$|^\.env[\w.-]*$/i;

const ISSUE_MARKERS =
  /\b(missing| lacks |without |not enforced|not validated|unauthenticated|no auth|no validation|fails to|does not |absent |bypass|exposed|hardcoded|omit|skipped|never calls)\b/i;

export interface EvidenceStrictResult {
  strict: boolean;
  reasons: string[];
}

export function isValidRepoFilePath(path: string): boolean {
  const cleaned = path.trim();
  if (!cleaned || ABSTRACT_SURFACE.test(cleaned) || cleaned.includes(" ")) {
    return false;
  }
  if (cleaned.startsWith(".env")) {
    return true;
  }
  return VALID_PATH.test(cleaned);
}

export function assessEvidenceStrictness(finding: VerifiedFinding): EvidenceStrictResult {
  const reasons: string[] = [];

  if (finding.title.trim().toLowerCase().startsWith("potential")) {
    reasons.push("title uses Potential prefix");
  }
  if (HEDGE_LANGUAGE.test(finding.title) || HEDGE_LANGUAGE.test(finding.claim)) {
    reasons.push("claim or title uses non-conclusive language");
  }
  if (!ISSUE_MARKERS.test(finding.claim)) {
    const symbols = finding.evidence.flatMap((item) => {
      const matches: string[] = [];
      const snippet = item.snippet ?? "";
      for (const match of snippet.matchAll(/(?:function|def|class)\s+(\w+)/g)) {
        matches.push(match[1]!);
      }
      return matches;
    });
    if (!symbols.some((symbol) => finding.claim.toLowerCase().includes(symbol.toLowerCase()))) {
      reasons.push("claim does not identify a specific missing or incorrect check");
    }
  }

  const fileEvidence = finding.evidence.filter((item) => item.type !== "skill");
  if (fileEvidence.length === 0) {
    reasons.push("missing file-level evidence");
  }

  for (const item of fileEvidence) {
    if (!item.explanation || GENERIC_EVIDENCE.test(item.explanation)) {
      reasons.push(`generic evidence explanation: ${item.explanation ?? "(empty)"}`);
    }
    const blob = [item.snippet, item.explanation, item.path].filter(Boolean).join(" ");
    const anchored = item.path != null && item.line_start != null;
    if (!anchored && !CODE_ELEMENT.test(blob)) {
      reasons.push(`evidence lacks concrete code anchor: ${item.path ?? item.route ?? "unknown"}`);
    }
  }

  for (const file of finding.affected_files) {
    if (!isValidRepoFilePath(file)) {
      reasons.push(`affected file is not a valid repo path: ${file}`);
    }
  }

  for (const surface of finding.affected_surfaces) {
    if (surface.startsWith("/")) {
      continue;
    }
    if (!isValidRepoFilePath(surface)) {
      reasons.push(`affected surface should be route-only, not abstract label: ${surface}`);
    }
  }

  const repro = finding.safe_reproduction.steps.join(" ").toLowerCase();
  if (
    finding.affected_files.length > 0 &&
    !finding.affected_files.some((path) => repro.includes(path.toLowerCase()))
  ) {
    reasons.push("safe reproduction steps do not reference affected file paths");
  }

  return { strict: reasons.length === 0, reasons: [...new Set(reasons)] };
}
