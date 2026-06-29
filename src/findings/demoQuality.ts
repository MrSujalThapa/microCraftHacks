import type { VerifiedFinding } from "./types";

const PUBLIC_ROUTE_PATHS = new Set(["/", "/health", "/api/health", "/status", "/ping"]);

const GENERIC_AUTH_GAP =
  /(?:missing|lacks|without|no|not)\s+(?:[\w-]+\s+){0,4}(?:auth(?:entication|orization)?|validation|credentials?|guard|middleware)|unauthenticated|not enforced|not validated|visible auth|visible validation|visible authorization|missing visible auth|missing visible validation|lacks auth dependency|lacks schema validation|auth dependency|schema validation|public health|health endpoint|health check|health route|\/health|\/api\/health|\/ping|\/status/i;

const SENSITIVE_INDICATORS =
  /credential|secret|password|token|api[_-]?key|private[_-]?key|pii|ssn|credit.?card|user.?data|email.?address|database.?url|connection.?string|internal.?infra|stack.?trace|debug.?info|env.?var|service.?role|admin.?key|side.?effect|tool.?call|llm|openai|anthropic|embedding|prompt.?injection|supabase|postgres|redis|aws|stripe/i;

const STATE_CHANGING = /\b(post|put|patch|delete|mutate|write|execute|invoke)\b/i;

const NEGATIVE_AUTH_CONTEXT =
  /\b(without|missing|lacks|no)\s+(auth(?:entication)?|credentials?|validation)\b/gi;

const ROUTES_IN_TEXT = /(?:^|\s|['"`(])(\/api\/health|\/health|\/status|\/ping)\b/gi;

export interface DemoQualityAssessment {
  demoReady: boolean;
  demoReason: string;
}

function normalizeRoute(route: string): string {
  let cleaned = route.trim().toLowerCase();
  if (!cleaned.startsWith("/")) {
    cleaned = `/${cleaned}`;
  }
  const trimmed = cleaned.replace(/\/+$/, "");
  return trimmed || "/";
}

function routesFromText(finding: VerifiedFinding): Set<string> {
  const routes = new Set<string>();
  const text = findingText(finding);
  for (const match of text.matchAll(ROUTES_IN_TEXT)) {
    routes.add(normalizeRoute(match[1]!));
  }
  if (/\bhealth endpoint\b|\bhealth check\b|\bpublic health\b/i.test(text)) {
    routes.add("/health");
  }
  return routes;
}

function collectRoutes(finding: VerifiedFinding): Set<string> {
  const routes = new Set<string>();
  for (const surface of finding.affected_surfaces) {
    if (surface.trim().startsWith("/")) {
      routes.add(normalizeRoute(surface));
    }
  }
  for (const item of finding.evidence) {
    if (item.route) {
      routes.add(normalizeRoute(item.route));
    }
  }
  for (const route of routesFromText(finding)) {
    routes.add(route);
  }
  return routes;
}

function findingText(finding: VerifiedFinding): string {
  const parts = [finding.title, finding.claim, finding.impact_hypothesis, finding.attack_path];
  for (const item of finding.evidence) {
    parts.push(item.explanation);
    if (item.snippet) {
      parts.push(item.snippet);
    }
  }
  return parts.filter(Boolean).join(" ");
}

function exposureText(finding: VerifiedFinding): string {
  const blob = findingText(finding);
  return blob.replace(NEGATIVE_AUTH_CONTEXT, "");
}

export function isGenericPublicRouteFinding(finding: VerifiedFinding): boolean {
  const routes = collectRoutes(finding);
  if (routes.size === 0) {
    return false;
  }
  for (const route of routes) {
    if (!PUBLIC_ROUTE_PATHS.has(route)) {
      return false;
    }
  }

  const text = findingText(finding);
  const exposure = exposureText(finding);
  if (SENSITIVE_INDICATORS.test(exposure)) {
    return false;
  }
  if (STATE_CHANGING.test(text) && !GENERIC_AUTH_GAP.test(finding.claim)) {
    return false;
  }

  return GENERIC_AUTH_GAP.test(text);
}

export function assessDemoQuality(finding: VerifiedFinding): DemoQualityAssessment {
  if (isGenericPublicRouteFinding(finding)) {
    return {
      demoReady: false,
      demoReason:
        "Generic public health/root route finding without sensitive exposure or side effects",
    };
  }

  if (finding.vulnerability_class === "secret-exposure") {
    return {
      demoReady: true,
      demoReason: "Verified secret exposure with redacted evidence",
    };
  }

  const routes = collectRoutes(finding);
  const onPublicRouteOnly =
    routes.size > 0 && [...routes].every((route) => PUBLIC_ROUTE_PATHS.has(route));
  if (onPublicRouteOnly && GENERIC_AUTH_GAP.test(findingText(finding))) {
    return {
      demoReady: false,
      demoReason:
        "Public health/root route finding without sensitive exposure or side effects",
    };
  }

  if (finding.confidence === "high" && finding.ranking_rationale.total_score >= 0.5) {
    return {
      demoReady: true,
      demoReason: "High-confidence verified finding with strong ranking score",
    };
  }

  if (finding.confidence === "high" || finding.confidence === "medium") {
    return {
      demoReady: true,
      demoReason: "Verified finding suitable for live demo",
    };
  }

  return {
    demoReady: false,
    demoReason: "Verified but lower confidence; review before demo",
  };
}

export function isDemoReady(finding: VerifiedFinding): boolean {
  return assessDemoQuality(finding).demoReady;
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
