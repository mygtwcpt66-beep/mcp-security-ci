# MCP Security CI

Scan MCP configs before an agent can exfiltrate secrets or run unsafe tools.

`mcp-security-ci` is a small CI-first scanner for Model Context Protocol (MCP) and agent tool configurations. It catches risky tool surfaces, broad filesystem scopes, shell wrappers, floating package versions, and secret exposure before they land in your agent workflow.

## Why This Exists

Agents are moving from chat to action. MCP servers can give them access to files, browsers, shells, APIs, internal systems, and credentials.

That creates a new supply-chain question:

> Did this pull request change what our agents are allowed to do?

This tool makes MCP permissions and tool surfaces reviewable in CI.

## What It Checks

- MCP server definitions in common JSON and TOML config files
- Remote MCP endpoints
- Shell wrappers and destructive command patterns
- Network-download-to-shell patterns such as `curl | bash`
- Floating `latest` or unpinned runtime packages
- Broad filesystem scopes
- Sensitive environment keys
- Powerful local tool surfaces such as filesystem, shell, browser, Playwright, or terminal tools

## Quick Start

```bash
npx github:mygtwcpt66-beep/mcp-security-ci --config path/to/mcp.json
```

For this source repo:

```bash
npm test
node ./bin/mcp-security-ci.js --config test/fixtures/risky.mcp.json
```

Scan common MCP config locations in the current repo:

```bash
npx github:mygtwcpt66-beep/mcp-security-ci
```

Common locations include `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/mcp.json`, and `claude_desktop_config.json`.

Codex-style TOML sections such as `[mcp_servers.filesystem]` are also supported.

## CLI

```bash
npx github:mygtwcpt66-beep/mcp-security-ci [--config <path>] [--format text|json|markdown|sarif] [--fail-on low|medium|high|critical|none]
```

Defaults:

- `--format text`
- `--fail-on high`

Examples:

```bash
npx github:mygtwcpt66-beep/mcp-security-ci --format markdown
npx github:mygtwcpt66-beep/mcp-security-ci --config .cursor/mcp.json --format sarif --fail-on none > mcp-security.sarif
npx github:mygtwcpt66-beep/mcp-security-ci --fail-on medium
```

## GitHub Actions

```yaml
name: MCP Security

on:
  pull_request:
  push:
    branches: [main]

jobs:
  mcp-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx github:mygtwcpt66-beep/mcp-security-ci --format markdown --fail-on high
```

SARIF upload:

```yaml
      - run: npx github:mygtwcpt66-beep/mcp-security-ci --format sarif --fail-on none > mcp-security.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-security.sarif
```

## Example Output

```text
[HIGH] Broad filesystem scope
  server: filesystem
  evidence: /Users/acme
  fix: Restrict filesystem MCP servers to the smallest project directories needed.

[MEDIUM] Latest version tag used
  server: github
  evidence: @latest
  fix: Use an explicit version and review upgrades through pull requests.
```

## Roadmap

- MCP lockfile and permission diff
- policy file support
- GitHub PR comments
- signed approvals and attestations
- audit receipts for agent tool runs
- known risky MCP server registry

## Security Scope

This scanner is a review aid, not a security guarantee or certification. It highlights risky MCP configuration patterns so humans and CI policies can review them before agents use those tools.

## License

MIT
