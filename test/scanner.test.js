const assert = require("node:assert/strict");
const test = require("node:test");
const path = require("node:path");

const { runScan } = require("../lib/scanner");

const fixtures = path.join(__dirname, "fixtures");

test("safe config scans without findings", () => {
  const report = runScan({
    rootDir: fixtures,
    configPaths: ["safe.mcp.json"],
  });

  assert.equal(report.servers.length, 1);
  assert.equal(report.findings.length, 0);
});

test("risky config flags important MCP supply-chain risks", () => {
  const report = runScan({
    rootDir: fixtures,
    configPaths: ["risky.mcp.json"],
  });

  const ids = new Set(report.findings.map((finding) => finding.id));
  assert.equal(report.servers.length, 2);
  assert.ok(ids.has("latest-version"));
  assert.ok(ids.has("broad-filesystem-scope"));
  assert.ok(ids.has("secret-env"));
  assert.ok(ids.has("network-pipe-to-shell"));
  assert.ok(ids.has("shell-command"));
  assert.equal(report.summary.counts.critical, 1);
});

test("codex TOML config is parsed and disabled servers are ignored", () => {
  const report = runScan({
    rootDir: fixtures,
    configPaths: ["codex.config.toml"],
  });

  const names = new Set(report.servers.map((server) => server.name));
  const ids = new Set(report.findings.map((finding) => finding.id));

  assert.ok(names.has("filesystem"));
  assert.ok(names.has("github"));
  assert.equal(names.has("disabled"), false);
  assert.ok(ids.has("broad-filesystem-scope"));
});
