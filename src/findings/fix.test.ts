import { describe, expect, it } from "vitest";

import { assessEvidenceStrictness, isValidRepoFilePath } from "./evidenceStrict";
import type { VerifiedFinding } from "./types";
import { sampleFindingsReport } from "./fixtures";
import { formatFixPlan, formatFixRefusal } from "./fix";
import { findVerifiedFinding } from "./load";

describe("assessEvidenceStrictness", () => {
  it("accepts backend/.env as a valid repo path", () => {
    expect(isValidRepoFilePath("backend/.env")).toBe(true);
  });

  it("accepts concrete verified finding fixtures", () => {
    const report = sampleFindingsReport();
    const finding = report.verifiedFindings[0]!;
    const result = assessEvidenceStrictness(finding);
    expect(result.strict).toBe(true);
    expect(result.reasons).toEqual([]);
  });

  it("rejects generic potential auth gap findings", () => {
    const result = assessEvidenceStrictness({
      ...sampleFindingsReport().verifiedFindings[0]!,
      title: "Potential auth boundary enforcement gap",
      claim:
        "Static evidence shows auth middleware that should enforce access control before sensitive API routes are reached.",
      evidence: [
        {
          type: "file",
          explanation: "Auth-related production context supports access-control review",
          path: "src/auth.ts",
        },
      ],
      affected_surfaces: ["/api/login", "Next.js frontend <-> FastAPI backend"],
      affected_files: ["Next.js frontend <-> FastAPI backend"],
      safe_reproduction: {
        mode: "static-proof",
        steps: ["Inspect auth middleware in identified files."],
        expected_result: "Document routes lacking auth enforcement.",
        safety_notes: [],
      },
    });

    expect(result.strict).toBe(false);
    expect(result.reasons.length).toBeGreaterThan(0);
  });
});

describe("formatFixPlan", () => {
  it("generates concrete patch plan for evidence-strict verified finding", () => {
    const report = sampleFindingsReport();
    const finding = findVerifiedFinding(report, "verified-draft-auth-1");
    const output = formatFixPlan(finding, "report.json");

    expect(output).toContain("Patch plan: verified-draft-auth-1");
    expect(output).toContain("Affected surfaces");
    expect(output).toContain("Affected files");
    expect(output).toContain("src/auth.ts");
    expect(output).toContain("Concrete fix locations");
    expect(output).toContain("Patch src/auth.ts:12-28");
    expect(output).toContain("requireAuth()");
    expect(output).not.toContain("Review the cited evidence");
  });

  it("refuses generic patch plan for weak finding", () => {
    const weakFinding: VerifiedFinding = {
      ...sampleFindingsReport().verifiedFindings[0]!,
      id: "verified-weak-1",
      title: "Potential API abuse via weak handler validation",
      claim: "API endpoints should enforce input validation before processing sensitive requests.",
      evidence: [
        {
          type: "file",
          explanation: "API route or handler context supports schema/abuse review",
          path: "lib/badge-definitions.ts",
        },
      ],
      affected_surfaces: ["/api/users"],
      affected_files: ["lib/badge-definitions.ts"],
      safe_reproduction: {
        mode: "static-proof",
        steps: ["Review mapped API route handlers in identified source files."],
        expected_result: "Document handlers lacking visible validation.",
        safety_notes: [],
      },
    };

    const output = formatFixPlan(weakFinding, "report.json");
    expect(output).toContain("Cannot generate concrete patch plan");
    expect(output).toContain("not evidence-strict");
    expect(output).not.toContain("Review the cited evidence");
  });

  it("generates secret-exposure remediation steps", () => {
    const secretFinding: VerifiedFinding = {
      ...sampleFindingsReport().verifiedFindings[0]!,
      id: "verified-secret-1",
      title: "Committed secret in backend/.env",
      vulnerability_class: "secret-exposure",
      claim: "backend/.env exposed SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET> in committed source control.",
      affected_surfaces: ["backend/.env"],
      affected_files: ["backend/.env"],
      evidence: [
        {
          type: "file",
          explanation: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
          path: "backend/.env",
          line_start: 1,
          line_end: 1,
          snippet: "SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>",
          evidence_pack_id: "ep-secret",
          symbol: "SUPABASE_SERVICE_ROLE_KEY",
        },
      ],
      safe_reproduction: {
        mode: "static-proof",
        steps: ["Open backend/.env and confirm the service role key line."],
        expected_result: "Secret key line is present in tracked file.",
        safety_notes: [],
      },
      demo_ready: true,
      demo_reason: "Verified secret exposure with redacted evidence",
    };

    const output = formatFixPlan(secretFinding, "report.json");
    expect(output).toContain("backend/.env");
    expect(output).not.toContain("super-secret");
    expect(output).toContain(".gitignore");
    expect(output).toContain("backend/.env.example");
    expect(output).toContain("Rotate");
    expect(output).toContain("Remove committed secret values");
    expect(output).toContain("runtime environment");
    expect(output).toContain("SUPABASE_SERVICE_ROLE_KEY");
    expect(output).not.toMatch(/^Patch backend\/\.env/m);
    expect(output).not.toContain("Patch backend/.env:1");
  });

  it("uses access-control validation for broken-access-control class", () => {
    const report = sampleFindingsReport();
    const finding = findVerifiedFinding(report, "verified-draft-auth-1");
    const output = formatFixPlan(finding, "report.json");

    expect(output).toContain("auth middleware");
  });
});

describe("formatFixRefusal", () => {
  it("explains why no patch is available", () => {
    const output = formatFixRefusal("verified-weak-1", ["generic evidence explanation"]);
    expect(output).toContain("Cannot generate concrete patch plan");
    expect(output).toContain("generic evidence explanation");
  });
});

describe("runFixCommand errors", () => {
  it("rejects rejected finding ids", () => {
    const report = sampleFindingsReport();
    expect(() => findVerifiedFinding(report, "draft-unsupported")).toThrow(/rejected/i);
  });
});
