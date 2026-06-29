import { execFileSync } from "node:child_process";

export function runGit(args: string[], cwd?: string): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export function cloneRepo(repoUrl: string, targetPath: string, ref?: string): void {
  const args = ["clone", "--depth", "1"];
  if (ref) {
    args.push("--branch", ref);
  }
  args.push(repoUrl, targetPath);
  runGit(args);
}

export function resolveHeadCommit(repoPath: string): string {
  return runGit(["rev-parse", "HEAD"], repoPath);
}
