import { describe, expect, it } from "vitest";

import { AgentRuntimeError } from "../agents/runtime";
import { ConfigError } from "../config/errors";
import { printCliError } from "./errors";

describe("printCliError", () => {
  it("includes init guidance for missing config", () => {
    const lines: string[] = [];
    const errorSpy = (message?: string) => {
      lines.push(message ?? "");
    };

    const original = console.error;
    console.error = errorSpy;

    try {
      printCliError(new ConfigError("Config not found", "MISSING", ".swarm/config.json"));
    } finally {
      console.error = original;
    }

    expect(lines.join("\n")).toContain("Run `swarm init`");
    expect(lines.join("\n")).toContain("Config not found");
  });

  it("prints Python stdout and stderr for runtime failures", () => {
    const lines: string[] = [];
    const errorSpy = (message?: string) => {
      lines.push(message ?? "");
    };

    const original = console.error;
    console.error = errorSpy;

    try {
      printCliError(
        new AgentRuntimeError(
          "Python agent runtime failed with exit code 1",
          1,
          "Cyber Swarm findings summary",
          "NameError: annotate_demo_quality is not defined",
        ),
      );
    } finally {
      console.error = original;
    }

    const output = lines.join("\n");
    expect(output).toContain("exit code 1");
    expect(output).toContain("Python stdout:");
    expect(output).toContain("Cyber Swarm findings summary");
    expect(output).toContain("Python stderr:");
    expect(output).toContain("annotate_demo_quality");
  });
});
