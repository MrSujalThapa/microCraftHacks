import { describe, expect, it } from "vitest";

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
});
