import { describe, expect, it } from "vitest";

import { containsRawSecret, redactSecrets, REDACTED_SECRET } from "./redaction";

describe("redactSecrets", () => {
  it("preserves key names while redacting values", () => {
    const redacted = redactSecrets("SUPABASE_SERVICE_ROLE_KEY=super-secret-value");
    expect(redacted).toContain(`SUPABASE_SERVICE_ROLE_KEY=${REDACTED_SECRET}`);
    expect(redacted).not.toContain("super-secret-value");
    expect(containsRawSecret(redacted)).toBe(false);
  });

  it("redacts sk- tokens", () => {
    const redacted = redactSecrets("token sk-1234567890abcdef in file");
    expect(redacted).not.toContain("sk-1234567890abcdef");
    expect(redacted).toContain(REDACTED_SECRET);
  });
});
