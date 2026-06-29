import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { ScanReport } from "../scanner/types";
import { extractSkillBody } from "./frontmatter";
import type { LoadedSkillBody, RoutedSkillSelection, SkillIndexEntry } from "./types";

export function loadSkillBodies(
  projectRoot: string,
  selections: RoutedSkillSelection[],
): LoadedSkillBody[] {
  const loaded: LoadedSkillBody[] = [];

  for (const selection of selections) {
    const fullPath = join(projectRoot, selection.path);
    const content = readFileSync(fullPath, "utf8");
    loaded.push({
      name: selection.name,
      path: selection.path,
      body: extractSkillBody(content),
    });
  }

  return loaded;
}
