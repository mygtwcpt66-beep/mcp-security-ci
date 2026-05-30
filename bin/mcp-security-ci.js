#!/usr/bin/env node

const {
  DEFAULT_CONFIG_CANDIDATES,
  formatJson,
  formatMarkdown,
  formatSarif,
  formatText,
  runScan,
  severityRank,
} = require("../lib/scanner");

function printHelp() {
  console.log(`mcp-security-ci

Usage:
  mcp-security-ci [--config <path>] [--format text|json|markdown|sarif] [--fail-on low|medium|high|critical|none]

Defaults:
  --format text
  --fail-on high

If --config is omitted, the scanner checks common MCP config locations in the current repo.
`);
}

function parseArgs(argv) {
  const args = {
    configPaths: [],
    format: "text",
    failOn: "high",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--config" || arg === "-c") {
      const value = argv[++i];
      if (!value) throw new Error("--config requires a path");
      args.configPaths.push(value);
    } else if (arg === "--format" || arg === "-f") {
      const value = argv[++i];
      if (!["text", "json", "markdown", "sarif"].includes(value)) {
        throw new Error("--format must be text, json, markdown, or sarif");
      }
      args.format = value;
    } else if (arg === "--fail-on") {
      const value = argv[++i];
      if (!["none", "low", "medium", "high", "critical"].includes(value)) {
        throw new Error("--fail-on must be none, low, medium, high, or critical");
      }
      args.failOn = value;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (args.configPaths.length === 0) {
    args.configPaths = DEFAULT_CONFIG_CANDIDATES;
  }

  return args;
}

function shouldFail(report, failOn) {
  if (failOn === "none") return false;
  const threshold = severityRank(failOn);
  return report.findings.some((finding) => severityRank(finding.severity) >= threshold);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const report = runScan({
    rootDir: process.cwd(),
    configPaths: args.configPaths,
  });

  if (args.format === "json") {
    process.stdout.write(`${formatJson(report)}\n`);
  } else if (args.format === "markdown") {
    process.stdout.write(`${formatMarkdown(report)}\n`);
  } else if (args.format === "sarif") {
    process.stdout.write(`${formatSarif(report)}\n`);
  } else {
    process.stdout.write(`${formatText(report)}\n`);
  }

  if (shouldFail(report, args.failOn)) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(`mcp-security-ci: ${error.message}`);
  process.exitCode = 2;
});
