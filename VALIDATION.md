# Validation Plan

Goal: prove or kill the MCP Security CI business hypothesis quickly.

## Core Hypothesis

Small AI teams and MCP server authors will pay for CI checks that prevent unsafe MCP tool changes from reaching agent workflows.

The free scanner is not the business. The business is:

- private repo CI
- permission diff history
- team policies
- signed approvals
- audit/attestation artifacts

## Target Users

- MCP server authors
- AI infra engineers
- teams building internal agents with Claude/Codex/Cursor
- small SaaS teams exposing MCP servers to customers
- AI automation shops managing several client toolchains

## Outreach Without Sales Calls

Use product-led touchpoints:

- GitHub README and demo
- Hacker News "Show HN"
- Reddit / MCP / AI engineering communities
- posts showing real risky MCP examples
- free scan reports for public MCP repos
- a badge people can add after a passing scan

No cold email campaign. No sales calls. If someone wants a call, treat it as validation, not operating model.

## Validation Metrics

Green:

- 30+ scanner runs from real users
- 5+ requests for CI/private repo/history/policies
- 1-3 paid or explicitly committed users

Yellow:

- lots of stars, no usage
- users only want a free local scanner
- people ask for generic agent observability instead

Red:

- no one understands the risk
- no one wants this in CI
- everyone says platform vendors will handle it

## Kill Criteria

Kill or pivot after 14 days if:

- no paid signal appears
- no team asks for CI or policy history
- users treat it as a one-time checklist, not a recurring control

## Pivot Options

If the scanner gets usage but no paid signal:

- keep it open source as distribution
- pivot to MCP lockfile/permission diff as a tiny dev utility
- use the audience to test SpecDelta or another monitoring product

If teams ask for proof artifacts:

- build signed attestation and audit receipts

If teams ask for runtime blocking:

- consider a local MCP proxy/firewall, but only after scanner demand is proven
