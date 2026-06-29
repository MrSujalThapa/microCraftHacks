import { describe, expect, it } from "vitest";

import { sampleFindingsReport } from "./fixtures";
import { formatFindingExplanation, formatFindingsTable } from "./display";

describe("formatFindingsTable", () => {
  it("renders concise table with required columns", () => {
    const output = formatFindingsTable(sampleFindingsReport(), "report.json");

    expect(output).toContain("SEVERITY");
    expect(output).toContain("CONF");
    expect(output).toContain("TITLE");
    expect(output).toContain("ROUTE/FILE");
    expect(output).toContain("ID");
    expect(output).toContain("high");
    expect(output).toContain("verified-draft-auth-1");
    expect(output).toContain("/api/login");
  });
});

describe("formatFindingExplanation", () => {
  it("includes claim, evidence, and safe reproduction", () => {
    const finding = sampleFindingsReport().verifiedFindings[0]!;
    const output = formatFindingExplanation(finding);

    expect(output).toContain("Claim");
    expect(output).toContain("Evidence");
    expect(output).toContain("Safe reproduction");
    expect(output).toContain("src/auth.ts");
    expect(output).toContain("Ranking rationale");
  });
});
