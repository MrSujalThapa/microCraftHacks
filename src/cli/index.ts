#!/usr/bin/env node

import { Command } from "commander";

import { loadConfig } from "../config/load";
import { runDoctor } from "./doctor";
import { printCliError } from "./errors";
import { runInit } from "./init";
import { getPackageVersion } from "../shared/version";

const program = new Command();

program
  .name("swarm")
  .description("Cyber Swarm — autonomous security swarm for authorized pre-production testing")
  .version(getPackageVersion(), "-V, --version", "output the version number");

program
  .command("version")
  .description("Show Cyber Swarm version")
  .action(() => {
    console.log(getPackageVersion());
  });

program
  .command("init")
  .description("Create default .swarm/config.json and project folders")
  .action(runInit);

program.command("doctor").description("Check local environment and project layout").action(runDoctor);

program
  .command("scan [path]")
  .description("Run a security scan (not implemented yet)")
  .action(() => {
    try {
      loadConfig();
    } catch (error) {
      printCliError(error);
      process.exitCode = 1;
      return;
    }

    console.error("swarm scan is not implemented yet.");
    process.exitCode = 1;
  });

program
  .command("skills")
  .description("Manage the security skills library (not implemented yet)")
  .action(() => {
    try {
      loadConfig();
    } catch (error) {
      printCliError(error);
      process.exitCode = 1;
      return;
    }

    console.error("swarm skills is not implemented yet.");
    process.exitCode = 1;
  });

program.parse(process.argv);
