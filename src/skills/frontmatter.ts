import type { SkillFrontmatter } from "./types";

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---/;

function parseYamlValue(line: string): { key: string; value: string } | null {
  const match = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
  if (!match) {
    return null;
  }
  return { key: match[1], value: match[2].trim() };
}

function parseTags(raw: string): string[] {
  const trimmed = raw.trim();
  if (!trimmed) {
    return [];
  }

  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return trimmed
      .slice(1, -1)
      .split(",")
      .map((tag) => tag.trim().replace(/^['"]|['"]$/g, ""))
      .filter(Boolean);
  }

  return trimmed
    .split(/[,\s]+/)
    .map((tag) => tag.trim().replace(/^['"]|['"]$/g, ""))
    .filter(Boolean);
}

export function parseSkillFrontmatter(content: string): SkillFrontmatter | null {
  const match = FRONTMATTER_RE.exec(content);
  if (!match) {
    return null;
  }

  const fields: Record<string, string> = {};
  for (const line of match[1].split(/\r?\n/)) {
    const parsed = parseYamlValue(line);
    if (parsed) {
      fields[parsed.key] = parsed.value;
    }
  }

  const name = fields.name?.trim();
  if (!name) {
    return null;
  }

  const description = (fields.description ?? fields.summary ?? "").trim();
  const domain = fields.domain?.trim() || undefined;
  const subdomain = fields.subdomain?.trim() || undefined;
  const tags = parseTags(fields.tags ?? "");

  return {
    name,
    description,
    domain,
    subdomain,
    tags,
  };
}

export function extractSkillBody(content: string): string {
  const match = FRONTMATTER_RE.exec(content);
  if (!match) {
    return content.trim();
  }
  return content.slice(match[0].length).trim();
}
