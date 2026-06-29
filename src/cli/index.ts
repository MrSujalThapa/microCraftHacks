#!/usr/bin/env node

import { Command } from "commander";

import { runDoctor } from "./doctor";
import { printCliError } from "./errors";
import { runInit } from "./init";
import { runScanCommand } from "./scan";
import { runSkillsCommand, runSkillsSyncCommand } from "./skills";
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
  .description("Run a static repo intelligence scan")
  .action((scanPath?: string) => {
    try {
      runScanCommand(scanPath);
    } catch (error) {
      printCliError(error);
      process.exitCode = 1;
    }
  });

const skillsCommand = program
  .command("skills")
  .description("Manage the external cybersecurity skills library");

skillsCommand
  .command("sync")
  .description("Clone external skills repo and write skills lockfile")
  .option("--repo <url>", "Override external skill repo URL")
  .option("--ref <ref>", "Optional branch/tag/commit to pin")
  .action((options: { repo?: string; ref?: string }) => {
    runSkillsCommand(() => runSkillsSyncCommand(options));
  });

program.parse(process.argv);
