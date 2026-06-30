import { describe, expect, it } from "vitest";

import { evaluateSemanticGate, isGenericRouteSegment, capRoutedScore } from "./gates";
import type { SkillIndexEntry } from "./types";

function skill(name: string, tags: string[] = []): SkillIndexEntry {
  return {
    name,
    description: `Skill for ${name}`,
    tags,
    path: `skills/external/${name}/SKILL.md`,
    sourceType: "external",
  };
}

describe("isGenericRouteSegment", () => {
  it("treats common app routes as non-keyword segments", () => {
    expect(isGenericRouteSegment("profile")).toBe(true);
    expect(isGenericRouteSegment("incidents")).toBe(true);
    expect(isGenericRouteSegment("login")).toBe(true);
    expect(isGenericRouteSegment("[id]")).toBe(true);
    expect(isGenericRouteSegment("supabase")).toBe(false);
  });
});

describe("evaluateSemanticGate", () => {
  it("blocks threat intel skills without intel evidence", () => {
    const result = evaluateSemanticGate(skill("building-threat-actor-profile-from-osint", ["osint"]), {
      keywords: new Map([["authentication", []]]),
    });

    expect(result.passed).toBe(false);
    expect(result.gate?.id).toBe("threat_intel_osint");
  });

  it("blocks Delinea PAM skills when only generic secret config exists", () => {
    const result = evaluateSemanticGate(skill("implementing-delinea-secret-server-for-pam", ["pam"]), {
      keywords: new Map([
        ["secret", []],
        ["env", []],
      ]),
    });

    expect(result.passed).toBe(false);
    expect(result.gate?.id).toBe("delinea_pam");
  });
});

describe("capRoutedScore", () => {
  it("caps score below 0.95 unless multiple evidence types support the skill", () => {
    expect(capRoutedScore(0.95, 1, ["auth surface: src/auth.ts"])).toBeLessThanOrEqual(0.85);
    expect(
      capRoutedScore(0.95, 1, ["route segment: /login", "route segment: /login"]),
    ).toBeLessThanOrEqual(0.85);
    expect(
      capRoutedScore(
        0.95,
        4,
        ["auth surface: src/auth.ts", "route handler: src/api.ts", "stack: Next.js", "config: .env"],
      ),
    ).toBe(0.95);
  });
});
