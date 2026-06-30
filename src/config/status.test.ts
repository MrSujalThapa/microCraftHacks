import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { initProject } from "./init";
import { getDoctorConfigStatus } from "./status";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-doctor-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("getDoctorConfigStatus", () => {
  it("returns ResolvedProvider shape with provider field", () => {
    const root = makeTempRoot();
    initProject(root);

    const status = getDoctorConfigStatus(root);

    expect(status.provider).not.toBeNull();
    expect(status.provider).toMatchObject({
      provider: "openai",
      model: "gpt-5-mini",
      sources: {
        provider: "config",
        model: "config",
      },
    });
    expect(status.provider).not.toHaveProperty("name");
    expect(typeof status.provider?.openaiKeyPresent).toBe("boolean");
  });
});
