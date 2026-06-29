import { existsSync } from "node:fs";
import { arch, cwd, platform, version as nodeVersion } from "node:process";

import { getPackageVersion } from "../shared/version";

export function runDoctor(): void {
  const root = cwd();

  console.log("Cyber Swarm Doctor");
  console.log("");
  console.log(`Version:     ${getPackageVersion()}`);
  console.log(`Node:        ${nodeVersion}`);
  console.log(`Platform:    ${platform} (${arch})`);
  console.log(`CWD:         ${root}`);
  console.log(
    `Config:      ${existsSync("swarm.config.json") ? "swarm.config.json found" : "swarm.config.json missing"}`,
  );
  console.log(
    `Skills dir:  ${existsSync("skills/external") ? "skills/external present" : "skills/external missing"}`,
  );
  console.log("");
  console.log("Environment looks usable for local development.");
}
