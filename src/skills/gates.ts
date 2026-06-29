import type { SkillIndexEntry } from "./types";

export interface GateRepoEvidence {
  keywords: Map<string, unknown>;
}

/** App route segments — surfaces only, not cybersecurity skill keywords. */
export const GENERIC_ROUTE_SEGMENTS = new Set([
  "profile",
  "profiles",
  "incidents",
  "incident",
  "login",
  "logout",
  "signin",
  "sign-in",
  "signup",
  "sign-up",
  "map",
  "community",
  "communities",
  "issues",
  "issue",
  "activity",
  "activities",
  "badges",
  "badge",
  "stats",
  "health",
  "dashboard",
  "home",
  "settings",
  "users",
  "user",
  "about",
  "search",
  "report",
  "reports",
  "detail",
  "details",
  "documents",
  "document",
  "operator",
  "draft",
  "drafts",
  "role",
  "roles",
  "civic",
  "index",
  "new",
  "edit",
  "delete",
  "list",
  "view",
  "create",
  "update",
  "item",
  "items",
  "data",
  "info",
  "public",
  "private",
  "feed",
  "posts",
  "post",
  "comments",
  "comment",
  "messages",
  "message",
  "notifications",
  "notification",
  "events",
  "event",
  "orders",
  "order",
  "products",
  "product",
  "cart",
  "checkout",
  "billing",
  "account",
  "accounts",
  "media",
  "upload",
  "uploads",
  "files",
  "file",
  "images",
  "image",
  "photos",
  "photo",
  "videos",
  "video",
  "admin",
  "manage",
  "management",
]);

export const THREAT_INTEL_EVIDENCE = [
  "actor",
  "campaign",
  "ioc",
  "iocs",
  "ttp",
  "ttps",
  "osint",
  "stix",
  "threat-intel",
  "threat-intelligence",
  "threat-actor",
  "mitre",
  "att&ck",
  "attack",
  "apt",
  "malware",
  "ransomware",
];

export const THREAT_CAMPAIGN_EVIDENCE = [
  "campaign",
  "ioc",
  "iocs",
  "malware",
  "threat-actor",
  "threat-intel",
  "threat-campaign",
  "apt",
  "ransomware",
];

export const DELINEA_PAM_EVIDENCE = [
  "delinea",
  "pam",
  "secret-server",
  "privileged-access",
  "privileged-access-management",
  "cyberark",
  "hashicorp-vault",
  "vault-enterprise",
];

export const CISCO_ISE_NAC_EVIDENCE = [
  "cisco",
  "ise",
  "nac",
  "network-access-control",
  "radius",
  "802-1x",
  "8021x",
  "network-access",
];

export const ENTRA_PASSWORDLESS_EVIDENCE = [
  "entra",
  "azure-ad",
  "azuread",
  "microsoft-identity",
  "microsoft-entra",
  "passwordless",
  "passkey",
  "fido2",
  "webauthn",
];

export interface SemanticGateDefinition {
  id: string;
  label: string;
  skillPattern: RegExp;
  requiredAny: string[];
}

export const SEMANTIC_GATES: SemanticGateDefinition[] = [
  {
    id: "threat_intel_osint",
    label: "threat intel / OSINT",
    skillPattern:
      /threat-actor|threat-intel|threat-intelligence|\bosint\b|\bstix\b|\bttp\b|\bioc\b|indicator-of-compromise|att&ck|mitre-attack/i,
    requiredAny: THREAT_INTEL_EVIDENCE,
  },
  {
    id: "threat_campaign",
    label: "threat campaign correlation",
    skillPattern: /correlating-threat|threat-campaign|campaign-correl|threat-campaigns/i,
    requiredAny: THREAT_CAMPAIGN_EVIDENCE,
  },
  {
    id: "delinea_pam",
    label: "Delinea / PAM / secret server",
    skillPattern: /delinea|secret-server|privileged-access|cyberark|\bpam\b|hashicorp-vault/i,
    requiredAny: DELINEA_PAM_EVIDENCE,
  },
  {
    id: "cisco_ise_nac",
    label: "Cisco ISE / NAC",
    skillPattern: /cisco-ise|\bise\b|network-access-control|\bnac\b|\bradius\b|802-1x|8021x/i,
    requiredAny: CISCO_ISE_NAC_EVIDENCE,
  },
  {
    id: "entra_passwordless",
    label: "Entra / passwordless identity",
    skillPattern:
      /entra|azure-ad|azuread|microsoft-identity|microsoft-entra|passwordless|passkey|fido2|webauthn/i,
    requiredAny: ENTRA_PASSWORDLESS_EVIDENCE,
  },
  {
    id: "api_gateway",
    label: "API gateway",
    skillPattern: /api-gateway|gateway-security-control|kong-gateway|apigee|tyk-gateway/i,
    requiredAny: ["api-gateway", "kong", "apigee", "nginx", "envoy", "traefik", "tyk"],
  },
  {
    id: "zero_knowledge_auth",
    label: "zero-knowledge authentication",
    skillPattern: /zero-knowledge|zk-proof|zkp|snark|cryptographic-proof/i,
    requiredAny: ["zero-knowledge", "zk-proof", "zkp", "snark", "cryptographic-proof"],
  },
  {
    id: "behavioral_auth_analytics",
    label: "anomalous authentication analytics",
    skillPattern: /anomalous-authentication|authentication-anomaly|\bueba\b|behavioral-analytics/i,
    requiredAny: ["siem", "ueba", "anomaly-detection", "behavioral-analytics", "splunk", "sentinel"],
  },
];

function skillCorpus(skill: SkillIndexEntry): string {
  return [skill.name, skill.description, skill.domain ?? "", skill.subdomain ?? "", ...skill.tags]
    .join(" ")
    .toLowerCase();
}

function normalizeToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function matchedGateEvidence(
  evidence: GateRepoEvidence,
  requiredAny: string[],
): string[] {
  return requiredAny.filter((token) => evidence.keywords.has(normalizeToken(token)));
}

export function matchingSemanticGate(skill: SkillIndexEntry): SemanticGateDefinition | null {
  const corpus = skillCorpus(skill);
  for (const gate of SEMANTIC_GATES) {
    if (gate.skillPattern.test(corpus)) {
      return gate;
    }
  }
  return null;
}

export interface SemanticGateResult {
  passed: boolean;
  gate: SemanticGateDefinition | null;
  matchedEvidence: string[];
  reason?: string;
}

export function evaluateSemanticGate(
  skill: SkillIndexEntry,
  evidence: GateRepoEvidence,
): SemanticGateResult {
  const gate = matchingSemanticGate(skill);
  if (!gate) {
    return { passed: true, gate: null, matchedEvidence: [] };
  }

  const matchedEvidence = matchedGateEvidence(evidence, gate.requiredAny);
  if (matchedEvidence.length === 0) {
    return {
      passed: false,
      gate,
      matchedEvidence: [],
      reason: `blocked ${gate.label}: missing ${gate.requiredAny.slice(0, 4).join(", ")} evidence`,
    };
  }

  return {
    passed: true,
    gate,
    matchedEvidence,
    reason: `gate ${gate.id}: matched ${matchedEvidence.join(", ")}`,
  };
}

export function isGenericRouteSegment(segment: string): boolean {
  const normalized = normalizeToken(segment);
  if (!normalized) {
    return true;
  }
  if (GENERIC_ROUTE_SEGMENTS.has(normalized)) {
    return true;
  }
  if (/^\[.+\]$/.test(segment) || segment.startsWith(":")) {
    return true;
  }
  return false;
}

export function countDistinctEvidenceTypes(reasons: string[]): number {
  const types = new Set<string>();
  for (const reason of reasons) {
    if (reason.startsWith("gate ")) {
      types.add("gate");
      continue;
    }
    const prefix = reason.split(":")[0]?.trim();
    if (prefix) {
      types.add(prefix);
    }
  }
  return types.size;
}

const GENERIC_LOGIN_ROUTE_SEGMENTS = /^route segment: \/(login|logout|signin|sign-in)(\/|$)/;

export function hasEvidenceBeyondGenericLoginRoute(reasons: string[]): boolean {
  const concrete = [...new Set(reasons.filter((reason) => reason.startsWith("route segment:") || reason.includes(":")))];
  return concrete.some((reason) => !GENERIC_LOGIN_ROUTE_SEGMENTS.test(reason));
}

export function capRoutedScore(
  rawScore: number,
  concreteMatches: number,
  reasons: string[],
): number {
  const normalized = Math.min(0.95, rawScore);
  const evidenceTypes = countDistinctEvidenceTypes(reasons);
  const uniqueConcrete = new Set(reasons.filter((reason) => reason.includes(":"))).size;
  if (
    uniqueConcrete >= 3 &&
    concreteMatches >= 3 &&
    evidenceTypes >= 2 &&
    hasEvidenceBeyondGenericLoginRoute(reasons)
  ) {
    return Number(normalized.toFixed(2));
  }
  return Number(Math.min(0.85, normalized).toFixed(2));
}
