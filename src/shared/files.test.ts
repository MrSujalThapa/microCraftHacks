import { describe, expect, it } from "vitest";

import { isTestFile } from "./files";

describe("isTestFile", () => {
  it("detects common test file patterns", () => {
    expect(isTestFile("src/scanner/surfaces.test.ts")).toBe(true);
    expect(isTestFile("src/scanner/surfaces.spec.ts")).toBe(true);
    expect(isTestFile("src/__tests__/router.ts")).toBe(true);
    expect(isTestFile("tests/integration/server.ts")).toBe(true);
    expect(isTestFile("test/server.ts")).toBe(true);
    expect(isTestFile("src/fixtures/sample.ts")).toBe(true);
  });

  it("does not flag production source files", () => {
    expect(isTestFile("src/scanner/surfaces.ts")).toBe(false);
    expect(isTestFile("src/cli/index.ts")).toBe(false);
    expect(isTestFile("package.json")).toBe(false);
    expect(isTestFile(".env")).toBe(false);
  });
});
