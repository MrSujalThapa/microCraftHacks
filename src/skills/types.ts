export interface SkillsLockfile {
  version: number;
  source: string;
  commit: string;
  syncedAt: string;
  skillsRoot: string;
  localApprovedRoot: string;
  draftRoot: string;
  rejectedRoot: string;
}

export interface SkillFrontmatter {
  name: string;
  description: string;
  domain?: string;
  subdomain?: string;
  tags: string[];
}

export interface SkillIndexEntry {
  name: string;
  description: string;
  domain?: string;
  subdomain?: string;
  tags: string[];
  path: string;
  sourceType: "external" | "local-approved";
}

export interface SkillsIndex {
  version: string;
  indexedAt: string;
  count: number;
  skills: SkillIndexEntry[];
}

export interface RoutedSkillSelection {
  name: string;
  path: string;
  score: number;
  reasons: string[];
  agentTypes: string[];
}

export interface LoadedSkillBody {
  name: string;
  path: string;
  body: string;
}

export interface RoutedSkillsOutput {
  reportPath: string;
  routedAt: string;
  selected: RoutedSkillSelection[];
  loaded: LoadedSkillBody[];
}

export interface SyncResult {
  lockfilePath: string;
  lockfile: SkillsLockfile;
  cloned: boolean;
  overlayDirs: string[];
}

export interface IndexResult {
  indexPath: string;
  index: SkillsIndex;
  skipped: string[];
}

export interface RouteResult {
  outputPath: string;
  output: RoutedSkillsOutput;
}
