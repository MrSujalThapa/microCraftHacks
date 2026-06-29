import { describe, expect, it } from "vitest";

import { parseSkillFrontmatter, extractSkillBody } from "./frontmatter";

describe("parseSkillFrontmatter", () => {
  it("parses required and optional fields", () => {
    const content = `---
name: detecting-broken-access-control
description: Find routes where ownership is not enforced
domain: application-security
subdomain: web-application-security
tags: [auth, authorization, idor]
---

# Skill body
`;

    const parsed = parseSkillFrontmatter(content);
    expect(parsed).toEqual({
      name: "detecting-broken-access-control",
      description: "Find routes where ownership is not enforced",
      domain: "application-security",
      subdomain: "web-application-security",
      tags: ["auth", "authorization", "idor"],
    });
  });

  it("accepts summary as description fallback", () => {
    const content = `---
name: example-skill
summary: Short summary line
tags: api, rest
---
`;
    const parsed = parseSkillFrontmatter(content);
    expect(parsed?.description).toBe("Short summary line");
    expect(parsed?.tags).toEqual(["api", "rest"]);
  });

  it("returns null for missing frontmatter or name", () => {
    expect(parseSkillFrontmatter("# no frontmatter")).toBeNull();
    expect(parseSkillFrontmatter("---\ndescription: missing name\n---")).toBeNull();
  });
});

describe("extractSkillBody", () => {
  it("strips frontmatter block", () => {
    const content = `---
name: test
---
Body content here.
`;
    expect(extractSkillBody(content)).toBe("Body content here.");
  });
});
