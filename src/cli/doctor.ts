import { arch, cwd, platform, version as nodeVersion } from "node:process";

import { CONFIG_RELATIVE_PATH } from "../config/paths";
import { getDoctorConfigStatus } from "../config/status";
import { getPackageVersion } from "../shared/version";

function formatFolderSummary(folders: { path: string; exists: boolean }[]): string {
  if (folders.length === 0) {
    return "n/a";
  }

  const missing = folders.filter((folder) => !folder.exists);
  if (missing.length === 0) {
    return "ok";
  }

  return `${missing.length} missing (${missing.map((folder) => folder.path).join(", ")})`;
}

function formatKeyPresence(present: boolean): string {
  return present ? "present" : "missing";
}

export function runDoctor(): void {
  const status = getDoctorConfigStatus();
  const configLabel = status.valid
    ? `${CONFIG_RELATIVE_PATH} (${status.message})`
    : status.exists
      ? `${CONFIG_RELATIVE_PATH} (${status.message})`
      : `${CONFIG_RELATIVE_PATH} (${status.message})`;

  console.log("Cyber Swarm Doctor");
  console.log(`Version   ${getPackageVersion()}`);
  console.log(`Node      ${nodeVersion}`);
  console.log(`Platform  ${platform} (${arch})`);
  console.log(`CWD       ${cwd()}`);
  console.log(`Config    ${configLabel}`);
  console.log(`Folders   ${formatFolderSummary(status.folders)}`);
  console.log(`Execution ${status.execution ?? "n/a"}`);

  if (status.provider) {
    console.log(
      `Provider  ${status.provider.name} (${status.provider.sources.provider})`,
    );
    console.log(`Model     ${status.provider.model} (${status.provider.sources.model})`);
    console.log(`OpenAI    key ${formatKeyPresence(status.provider.openaiKeyPresent)}`);
  }
}
