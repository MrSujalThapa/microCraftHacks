import { readFileSync } from "node:fs";
import { join } from "node:path";

export function getPackageVersion(): string {
  const packagePath = join(__dirname, "..", "..", "package.json");
  const pkg = JSON.parse(readFileSync(packagePath, "utf8")) as { version: string };
  return pkg.version;
}
