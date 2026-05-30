const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_CONFIG_CANDIDATES = [
  ".mcp.json",
  "mcp.json",
  ".cursor/mcp.json",
  ".vscode/mcp.json",
  ".claude/mcp.json",
  "claude_desktop_config.json",
  "codex.mcp.json",
];

const SEVERITY_ORDER = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function severityRank(severity) {
  return SEVERITY_ORDER[severity] || 0;
}

function readJsonFile(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

function readConfigFile(filePath) {
  if (/\.toml$/i.test(filePath)) {
    return parseTomlMcpConfig(fs.readFileSync(filePath, "utf8"));
  }
  return readJsonFile(filePath);
}

function parseTomlMcpConfig(raw) {
  const config = { mcp_servers: {} };
  let current = null;
  let currentEnv = null;

  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const sectionMatch = line.match(/^\[mcp_servers\.(?:"([^"]+)"|([^\].]+))(?:\.env)?\]$/);
    if (sectionMatch) {
      const name = sectionMatch[1] || sectionMatch[2];
      if (!config.mcp_servers[name]) config.mcp_servers[name] = {};
      current = config.mcp_servers[name];
      currentEnv = line.endsWith(".env]");
      if (currentEnv && !current.env) current.env = {};
      continue;
    }

    if (!current || !line.includes("=")) continue;
    const index = line.indexOf("=");
    const key = line.slice(0, index).trim();
    const value = parseTomlValue(line.slice(index + 1).trim());

    if (currentEnv) {
      current.env[key] = value;
    } else {
      current[key] = value;
    }
  }

  return config;
}

function parseTomlValue(value) {
  if (value === "true") return true;
  if (value === "false") return false;
  if (/^".*"$/.test(value)) return value.slice(1, -1).replace(/\\"/g, '"');
  if (/^\[.*\]$/.test(value)) {
    const body = value.slice(1, -1).trim();
    if (!body) return [];
    return splitTomlArray(body).map((item) => parseTomlValue(item.trim()));
  }
  return value;
}

function splitTomlArray(body) {
  const items = [];
  let current = "";
  let inString = false;
  let escaped = false;

  for (const char of body) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      current += char;
      escaped = true;
      continue;
    }
    if (char === '"') {
      current += char;
      inString = !inString;
      continue;
    }
    if (char === "," && !inString) {
      items.push(current);
      current = "";
      continue;
    }
    current += char;
  }

  if (current.trim()) items.push(current);
  return items;
}

function normalizeArg(arg) {
  if (arg === null || arg === undefined) return "";
  if (typeof arg === "string") return arg;
  return JSON.stringify(arg);
}

function redactedEnvKeys(env) {
  if (!env || typeof env !== "object") return [];
  return Object.keys(env).sort();
}

function discoverServers(config) {
  const servers = [];

  function addServer(name, value, sourcePath) {
    if (!value || typeof value !== "object") return;
    if (value.enabled === false) return;
    const hasCommand = typeof value.command === "string";
    const hasUrl = typeof value.url === "string";
    const hasArgs = Array.isArray(value.args);
    if (!hasCommand && !hasUrl && !hasArgs) return;

    servers.push({
      name,
      command: value.command || "",
      args: Array.isArray(value.args) ? value.args.map(normalizeArg) : [],
      envKeys: redactedEnvKeys(value.env),
      cwd: value.cwd || "",
      url: value.url || "",
      sourcePath,
      raw: value,
    });
  }

  function walk(value, sourcePath = []) {
    if (!value || typeof value !== "object") return;

    for (const key of ["mcpServers", "mcp_servers", "servers"]) {
      if (value[key] && typeof value[key] === "object" && !Array.isArray(value[key])) {
        for (const [name, server] of Object.entries(value[key])) {
          addServer(name, server, sourcePath.concat(key, name));
        }
      }
    }

    for (const [key, child] of Object.entries(value)) {
      if (child && typeof child === "object") {
        walk(child, sourcePath.concat(key));
      }
    }
  }

  walk(config);
  const seen = new Set();
  return servers.filter((server) => {
    const fingerprint = `${server.sourcePath.join(".")}:${server.command}:${server.url}:${server.args.join("\u0000")}`;
    if (seen.has(fingerprint)) return false;
    seen.add(fingerprint);
    return true;
  });
}

function addFinding(findings, finding) {
  findings.push({
    id: finding.id,
    severity: finding.severity,
    title: finding.title,
    message: finding.message,
    server: finding.server,
    file: finding.file,
    evidence: finding.evidence || "",
    recommendation: finding.recommendation || "",
  });
}

function joinedCommand(server) {
  return [server.command].concat(server.args).join(" ").trim();
}

function looksLikeShell(command) {
  return /(^|\/)(sh|bash|zsh|fish|cmd|powershell|pwsh)$/.test(command);
}

function scanServer(server, file, findings) {
  const commandLine = joinedCommand(server);
  const lower = commandLine.toLowerCase();

  if (server.url) {
    addFinding(findings, {
      id: "remote-mcp-server",
      severity: "medium",
      title: "Remote MCP server requires trust review",
      message: `Server "${server.name}" connects to a remote MCP endpoint.`,
      server: server.name,
      file,
      evidence: server.url,
      recommendation: "Require explicit approval, auth review, and data boundary review for remote MCP endpoints.",
    });
  }

  if (server.command && looksLikeShell(server.command) && server.args.some((arg) => arg === "-c" || arg === "/c")) {
    addFinding(findings, {
      id: "shell-command",
      severity: "high",
      title: "Shell command execution in MCP server",
      message: `Server "${server.name}" starts through a shell command.`,
      server: server.name,
      file,
      evidence: commandLine,
      recommendation: "Avoid shell wrappers where possible. Pin the executable and review every command argument.",
    });
  }

  if (/\b(rm\s+-rf|mkfs|diskutil\s+erase|del\s+\/f|format\s+[a-z]:)/i.test(commandLine)) {
    addFinding(findings, {
      id: "destructive-command",
      severity: "critical",
      title: "Potentially destructive command",
      message: `Server "${server.name}" includes a destructive command pattern.`,
      server: server.name,
      file,
      evidence: commandLine,
      recommendation: "Block this server unless the command is fully sandboxed and explicitly approved.",
    });
  }

  if (/\b(curl|wget)\b.+\|\s*(sh|bash|zsh|python|node)\b/i.test(commandLine)) {
    addFinding(findings, {
      id: "network-pipe-to-shell",
      severity: "critical",
      title: "Network download piped to interpreter",
      message: `Server "${server.name}" downloads code and executes it.`,
      server: server.name,
      file,
      evidence: commandLine,
      recommendation: "Replace pipe-to-shell install/start patterns with pinned packages or reviewed scripts.",
    });
  }

  if (/\b(npx|pnpm\s+dlx|bunx|uvx|pipx)\b/i.test(commandLine) && !/[@=](\d+\.){1,2}\d+/.test(commandLine)) {
    addFinding(findings, {
      id: "unpinned-runtime-package",
      severity: "medium",
      title: "Unpinned runtime package",
      message: `Server "${server.name}" appears to execute an unpinned package.`,
      server: server.name,
      file,
      evidence: commandLine,
      recommendation: "Pin package versions for MCP servers used in CI or production-like agents.",
    });
  }

  if (/@latest\b/i.test(commandLine)) {
    addFinding(findings, {
      id: "latest-version",
      severity: "medium",
      title: "Latest version tag used",
      message: `Server "${server.name}" uses a floating latest version.`,
      server: server.name,
      file,
      evidence: commandLine,
      recommendation: "Use an explicit version and review upgrades through pull requests.",
    });
  }

  if (/\b(sudo|chmod\s+777|chown\s+-r)\b/i.test(commandLine)) {
    addFinding(findings, {
      id: "privileged-command",
      severity: "high",
      title: "Privileged or broad permission command",
      message: `Server "${server.name}" includes privileged command patterns.`,
      server: server.name,
      file,
      evidence: commandLine,
      recommendation: "Run MCP servers as least-privileged users and avoid permission-changing startup commands.",
    });
  }

  const broadPathArgs = server.args.filter((arg) => {
    const expanded = arg.replace(/^~($|\/)/, `${process.env.HOME || ""}$1`);
    return expanded === "/" || expanded === process.env.HOME || /^\/Users\/[^/]+$/.test(expanded);
  });
  if (broadPathArgs.length > 0) {
    addFinding(findings, {
      id: "broad-filesystem-scope",
      severity: "high",
      title: "Broad filesystem scope",
      message: `Server "${server.name}" appears to receive broad filesystem access.`,
      server: server.name,
      file,
      evidence: broadPathArgs.join(", "),
      recommendation: "Restrict filesystem MCP servers to the smallest project directories needed.",
    });
  }

  const secretEnvKeys = server.envKeys.filter((key) => /(token|secret|password|api[_-]?key|credential|private)/i.test(key));
  if (secretEnvKeys.length > 0) {
    addFinding(findings, {
      id: "secret-env",
      severity: "medium",
      title: "Sensitive environment keys exposed to MCP server",
      message: `Server "${server.name}" receives environment variables that look sensitive.`,
      server: server.name,
      file,
      evidence: secretEnvKeys.join(", "),
      recommendation: "Verify that this server needs each secret. Prefer scoped tokens and secret managers.",
    });
  }

  if (/(filesystem|file-system|fs|shell|terminal|computer|browser|puppeteer|playwright)/i.test(server.name) || /(filesystem|shell|terminal|puppeteer|playwright)/i.test(lower)) {
    addFinding(findings, {
      id: "powerful-tool-surface",
      severity: "low",
      title: "Powerful tool surface",
      message: `Server "${server.name}" looks like it can affect local files, browser state, or command execution.`,
      server: server.name,
      file,
      evidence: commandLine,
      recommendation: "Require explicit approval and policy review for powerful MCP surfaces.",
    });
  }
}

function summarize(findings) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  const maxSeverity = ["critical", "high", "medium", "low"].find((severity) => counts[severity] > 0) || "none";
  return {
    counts,
    maxSeverity,
    total: findings.length,
  };
}

function resolveCandidate(rootDir, candidate) {
  if (path.isAbsolute(candidate)) return candidate;
  return path.join(rootDir, candidate);
}

function runScan({ rootDir, configPaths }) {
  const scannedFiles = [];
  const skippedFiles = [];
  const servers = [];
  const findings = [];

  for (const candidate of configPaths) {
    const filePath = resolveCandidate(rootDir, candidate);
    if (!fs.existsSync(filePath)) {
      skippedFiles.push(filePath);
      continue;
    }

    let config;
    try {
      config = readConfigFile(filePath);
    } catch (error) {
      addFinding(findings, {
        id: "invalid-json",
        severity: "high",
        title: "Invalid JSON config",
        message: `Could not parse ${filePath}: ${error.message}`,
        server: "",
        file: filePath,
        recommendation: "Fix JSON syntax before relying on MCP config scans.",
      });
      scannedFiles.push(filePath);
      continue;
    }

    const discovered = discoverServers(config);
    for (const server of discovered) {
      servers.push({ ...server, file: filePath });
      scanServer(server, filePath, findings);
    }
    scannedFiles.push(filePath);
  }

  return {
    tool: "mcp-security-ci",
    version: "0.1.0",
    scannedAt: new Date().toISOString(),
    scannedFiles,
    skippedFiles,
    servers: servers.map((server) => ({
      name: server.name,
      file: server.file,
      command: server.command,
      args: server.args,
      url: server.url,
      envKeys: server.envKeys,
      cwd: server.cwd,
    })),
    findings,
    summary: summarize(findings),
  };
}

function formatText(report) {
  const lines = [];
  lines.push(`mcp-security-ci ${report.version}`);
  lines.push(`Scanned files: ${report.scannedFiles.length}`);
  lines.push(`MCP servers: ${report.servers.length}`);
  lines.push(`Findings: ${report.summary.total} (critical ${report.summary.counts.critical}, high ${report.summary.counts.high}, medium ${report.summary.counts.medium}, low ${report.summary.counts.low})`);
  lines.push("");

  if (report.scannedFiles.length === 0) {
    lines.push("No MCP config files found. Pass --config <path> to scan a specific file.");
    return lines.join("\n");
  }

  if (report.findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n");
  }

  for (const finding of report.findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity))) {
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.title}`);
    lines.push(`  file: ${finding.file}`);
    if (finding.server) lines.push(`  server: ${finding.server}`);
    lines.push(`  ${finding.message}`);
    if (finding.evidence) lines.push(`  evidence: ${finding.evidence}`);
    if (finding.recommendation) lines.push(`  fix: ${finding.recommendation}`);
    lines.push("");
  }

  return lines.join("\n").trimEnd();
}

function formatJson(report) {
  return JSON.stringify(report, null, 2);
}

function formatMarkdown(report) {
  const lines = [];
  lines.push("# MCP Security CI Report");
  lines.push("");
  lines.push(`- Scanned at: ${report.scannedAt}`);
  lines.push(`- Scanned files: ${report.scannedFiles.length}`);
  lines.push(`- MCP servers: ${report.servers.length}`);
  lines.push(`- Findings: ${report.summary.total}`);
  lines.push(`- Max severity: ${report.summary.maxSeverity}`);
  lines.push("");

  if (report.findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n");
  }

  lines.push("| Severity | Server | Finding | Recommendation |");
  lines.push("|---|---|---|---|");
  for (const finding of report.findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity))) {
    lines.push(`| ${finding.severity} | ${finding.server || "-"} | ${escapeMarkdown(finding.title)} | ${escapeMarkdown(finding.recommendation)} |`);
  }
  return lines.join("\n");
}

function escapeMarkdown(value) {
  return String(value || "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function formatSarif(report) {
  const rules = new Map();
  for (const finding of report.findings) {
    if (!rules.has(finding.id)) {
      rules.set(finding.id, {
        id: finding.id,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.recommendation || finding.message },
        defaultConfiguration: {
          level: sarifLevel(finding.severity),
        },
      });
    }
  }

  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-security-ci",
            informationUri: "https://github.com/mygtwcpt66-beep/hive/tree/main/products/mcp-security-ci",
            rules: Array.from(rules.values()),
          },
        },
        results: report.findings.map((finding) => ({
          ruleId: finding.id,
          level: sarifLevel(finding.severity),
          message: {
            text: `${finding.title}: ${finding.message}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.file,
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function sarifLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

module.exports = {
  DEFAULT_CONFIG_CANDIDATES,
  discoverServers,
  formatJson,
  formatMarkdown,
  formatSarif,
  formatText,
  runScan,
  severityRank,
};
