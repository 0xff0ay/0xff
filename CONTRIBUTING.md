# AI Contributor Guidelines

This repo uses AI to help with contributions. Here's the setup:

## MCP Servers

The repo includes `mcp.json` with these AI tools:
- Filesystem - read/write files
- GitHub - manage issues/PRs
- Brave Search - web search
- Docker - container management
- And more...

## GitHub Actions Workflows

1. **ai-review.yml** - Auto-review PRs with AI
2. **ai-automation.yml** - Scheduled AI contributions (every 6 hours)
3. **ai-contributor.yml** - Manual AI tasks

## Adding Human Collaborators

Go to: https://github.com/0xff0ay/0xff/settings/collaboration

## Setup AI API Key

To enable AI features:
1. Go to repo Settings → Secrets
2. Add `ANTHROPIC_API_KEY` with your Anthropic API key

## Commands for AI

- `/ai` comment on issues triggers AI review
- Manual workflow dispatch for custom tasks