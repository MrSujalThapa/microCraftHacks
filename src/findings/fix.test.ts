import { describe, expect, it } from "vitest";

import { sampleFindingsReport } from "./fixtures";
import { formatFixPlan } from "./fix";
import { findVerifiedFinding } from "./load";

describe("formatFixPlan", () => {
  it("generates concrete patch plan for verified finding", () => {
    const report = sampleFindingsReport();
    const finding = findVerifiedFinding(report, "verified-draft-auth-1");
    const output = formatFixPlan(finding, "report.json");

    expect(output).toContain("Patch plan: verified-draft-auth-1");
    expect(output).toContain("Affected files");
    expect(output).toContain("src/auth.ts");
    expect(output).toContain("Likely fix locations");
    expect(output).toContain("Recommended changes");
    expect(output).toContain("Validation steps");
    expect(output).toContain("Evidence basis");
    expect(output).toContain("no files were modified");
  });

  it("uses access-control template for broken-access-control class", () => {
    const report = sampleFindingsReport();
    const finding = findVerifiedFinding(report, "verified-draft-auth-1");
    const output = formatFixPlan(finding, "report.json");

    expect(output).toContain("auth middleware");
    expect(output).toContain("401/403");
  });
});

describe("runFixCommand errors", () => {
  it("rejects rejected finding ids", () => {
    const report = sampleFindingsReport();
    expect(() => findVerifiedFinding(report, "draft-unsupported")).toThrow(/rejected/i);
  });
});
