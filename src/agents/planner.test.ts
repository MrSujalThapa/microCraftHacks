import { describe, expect, it } from "vitest";

import {
  countUniqueSpecialists,
  planAgentsFromScanReport,
  SPECIALIST_BY_AGENT_TYPE,
} from "./planner";
import type { ScanReport } from "../scanner/types";

function cliOnlyReport(): ScanReport {
  return {
    version: "0.1.0",
    scannedAt: "2026-06-29T12:00:00.000Z",
    projectRoot: "/tmp/cli-tool",
    inventory: {
      totalFiles: 4,
      byCategory: { typescript: 2, config: 2 },
      files: [
        { path: "src/cli/index.ts", category: "typescript" },
        { path: "src/config/load.ts", category: "typescript" },
        { path: ".swarm/config.json", category: "config" },
        { path: "package.json", category: "json" },
      ],
    },
    stack: [{ name: "TypeScript", confidence: "high", evidence: ["package.json"] }],
    surfaces: { routes: [], api: [], auth: [], dataModels: [] },
  };
}

function webAppReport(): ScanReport {
  return {
    version: "0.1.0",
    scannedAt: "2026-06-29T12:00:00.000Z",
    projectRoot: "/tmp/web-app",
    inventory: {
      totalFiles: 3,
      byCategory: { typescript: 2, config: 1 },
      files: [
        { path: "src/middleware/auth.ts", category: "typescript" },
        { path: "app/api/users/route.ts", category: "typescript" },
        { path: ".env.example", category: "config" },
      ],
    },
    stack: [{ name: "Next.js", confidence: "high", evidence: ["next.config.js"] }],
    surfaces: {
      routes: [],
      api: [{ path: "/api/users", file: "app/api/users/route.ts", framework: "nextjs" }],
      auth: [{ file: "src/middleware/auth.ts", type: "middleware" }],
      dataModels: [],
    },
  };
}

describe("planAgentsFromScanReport", () => {
  it("activates config/dependency/secrets agents for CLI-only repos without web surfaces", () => {
    const planned = planAgentsFromScanReport(cliOnlyReport());
    const types = planned.map((agent) => agent.agentType);

    expect(types).toContain("dependency");
    expect(types).toContain("secrets");
    expect(types.some((type) => type === "config" || type === "secrets")).toBe(true);
    expect(types).not.toContain("auth");
    expect(types).not.toContain("api");
  });

  it("activates auth and api agents when web surfaces exist regardless of skill count", () => {
    const planned = planAgentsFromScanReport(webAppReport());
    const types = planned.map((agent) => agent.agentType);

    expect(types).toContain("auth");
    expect(types).toContain("api");
  });

  it("does not equate four routed skills with four agents", () => {
    const fourSkills = 4;
    const planned = planAgentsFromScanReport(cliOnlyReport());

    expect(fourSkills).toBe(4);
    expect(planned.length).not.toBe(fourSkills);
    expect(countUniqueSpecialists(planned)).toBeLessThanOrEqual(
      Object.keys(SPECIALIST_BY_AGENT_TYPE).length,
    );
  });

  it("plans agents with zero routed skills context", () => {
    const planned = planAgentsFromScanReport(cliOnlyReport());
    expect(planned.length).toBeGreaterThan(0);
    for (const agent of planned) {
      expect(agent.specialist).toBeTruthy();
      expect(agent.reasons.length).toBeGreaterThan(0);
    }
  });
});
