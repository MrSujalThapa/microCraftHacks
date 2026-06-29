import { initProject } from "../config/init";
import { CONFIG_RELATIVE_PATH } from "../config/paths";

export function runInit(): void {
  const result = initProject();

  if (result.configCreated) {
    console.log(`Created ${CONFIG_RELATIVE_PATH}`);
    console.log("Run `swarm scan` to start your first scan.");
    return;
  }

  console.log(`Config already exists at ${CONFIG_RELATIVE_PATH}`);
  if (result.directoriesCreated.length > 0) {
    console.log(`Created folders: ${result.directoriesCreated.join(", ")}`);
  }
}
