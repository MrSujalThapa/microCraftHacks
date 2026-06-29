import { describe, expect, it } from "vitest";
import { getPackageVersion } from "./version";

describe("getPackageVersion", () => {
  it("returns a semver string", () => {
    expect(getPackageVersion()).toMatch(/^\d+\.\d+\.\d+/);
  });
});
