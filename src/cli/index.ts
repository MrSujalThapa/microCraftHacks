#!/usr/bin/env node

import { Command } from "commander";

import { runDoctor } from "./doctor";
import { printCliError } from "./errors";
import { runInit } from "./init";
import { runScanCommand } from "./scan";
import { runAgentsRunCommand } from "./agents";
import { runDemoCliCommand } from "./demo";
import { runFindingsExplainCommand, runFindingsFixCommand, runFindingsListCommand } from "./findings";
import { runSkillsCommand, runSkillsIndexCommand, runSkillsListCommand, runSkillsRouteCommand, runSkillsSyncCommand } from "./skills";
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

skillsCommand
  .command("index")
  .description("Build skills index from external and local-approved SKILL.md frontmatter")
  .action(() => {
    runSkillsCommand(() => runSkillsIndexCommand());
  });

skillsCommand
  .command("list")
  .description("List indexed skills")
  .action(() => {
    runSkillsCommand(() => runSkillsListCommand());
  });

skillsCommand
  .command("route")
  .description("Route relevant skills from a scan report")
  .requiredOption("--report <path>", "Path to scan report JSON")
  .action((options: { report: string }) => {
    runSkillsCommand(() => runSkillsRouteCommand(options.report));
  });

const agentsCommand = program
  .command("agents")
  .description("Run Python LangGraph agent runtime");

agentsCommand
  .command("run")
  .description("Run agent runtime against scan and routed skill artifacts")
  .requiredOption("--report <path>", "Path to scan report JSON")
  .option("--routed-skills <path>", "Path to routed skills JSON")
  .option("--output <path>", "Path to write findings output JSON")
  .option("--provider <name>", "Model provider: openai, mock, or local")
  .option("--model <name>", "Model name when using an LLM provider")
  .option("--mode <name>", "Runtime mode: full, demo, or fast")
  .option("--fast", "Alias for --mode demo")
  .option("--from-cache", "Reuse cached findings when scan report hash matches")
  .action(
    (options: {
      report: string;
      routedSkills?: string;
      output?: string;
      provider?: "openai" | "mock" | "local";
      model?: string;
      mode?: string;
      fast?: boolean;
      fromCache?: boolean;
    }) => {
      runAgentsRunCommand({
        ...options,
        mode: options.fast ? "demo" : options.mode,
        fromCache: options.fromCache,
      });
    },
  );

program
  .command("demo [target]")
  .description("Run scan → route playbooks → demo specialists → show demo-ready findings")
  .option("--provider <name>", "Model provider: openai, mock, or local")
  .option("--model <name>", "Model name when using an LLM provider")
  .option("--from-cache", "Replay cached demo findings without model calls")
  .action(
    (
      target: string | undefined,
      options: {
        provider?: "openai" | "mock" | "local";
        model?: string;
        fromCache?: boolean;
      },
    ) => {
      runDemoCliCommand({ target, ...options });
    },
  );

program
  .command("findings")
  .description("List verified findings from the latest findings report")
  .option("--report <path>", "Path to findings report JSON")
  .option("--demo", "Show only demo-ready verified findings")
  .option("--best", "Print the best demo-ready finding ID and follow-up commands")
  .action((options: { report?: string; demo?: boolean; best?: boolean }) => {
    runFindingsListCommand(options);
  });

program
  .command("explain <finding-id>")
  .description("Explain a verified finding in detail")
  .option("--report <path>", "Path to findings report JSON")
  .action((findingId: string, options: { report?: string }) => {
    runFindingsExplainCommand(findingId, options);
  });

program
  .command("fix <finding-id>")
  .description("Generate a concrete patch plan for a verified finding")
  .option("--report <path>", "Path to findings report JSON")
  .action((findingId: string, options: { report?: string }) => {
    runFindingsFixCommand(findingId, options);
  });

program.parse(process.argv);
