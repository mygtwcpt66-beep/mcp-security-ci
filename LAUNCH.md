# Launch Plan

Goal: validate whether developers want MCP config checks in CI badly enough to ask for paid history, policies, or attestations.

## Launch Copy

**Title**

MCP Security CI: scan MCP configs before agents can use unsafe tools

**Short Description**

A tiny CLI/GitHub Action that checks MCP configs for broad filesystem scopes, shell wrappers, `curl | bash`, floating packages, secret env keys, and powerful tool surfaces.

**Post**

Agents are getting real tool access through MCP: files, shells, browsers, APIs, and credentials.

I built a small scanner that answers one CI question:

> Did this pull request change what our agents are allowed to do?

It flags:

- broad filesystem scopes
- shell wrappers
- network downloads piped to shells
- floating `@latest` MCP packages
- sensitive env keys
- powerful local tool surfaces

It outputs text, JSON, Markdown, and SARIF.

Run it:

```bash
npx github:mygtwcpt66-beep/mcp-security-ci --format markdown
```

I'm trying to learn whether teams want this as CI history, policies, and signed attestations, or whether it should stay a free local checklist.

## Places To Test

- Hacker News: Show HN
- Reddit: MCP / AI engineering communities
- GitHub topic pages via useful README
- small posts with real examples from public MCP configs
- MCP server authors who already publish public repos

## Paid Signal

Ignore compliments. Look for:

- "Can this run on private repos?"
- "Can I define allowed policies?"
- "Can it comment on PRs?"
- "Can it prove what changed?"
- "Can it block tool permission changes?"

Those are paid-product signals.
