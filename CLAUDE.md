# Claude Code Project Instructions

This is a penetration testing documentation repository (0xff) with AI-powered automation.

## Project Structure

```
0xff/
├── content/
│   ├── Methodology/Penetration-Testing/  # Pentest techniques
│   ├── Resources/                        # Tools & resources
│   ├── Tutorials/                        # Learning guides
│   └── Markdown/                         # Markdown syntax docs
├── .github/workflows/                    # AI & automation workflows
├── .claude/agents/                       # Custom AI agents
└── mcp.json                              # MCP server configuration
```

## AI Contributors

This repo uses multiple AI agents for automated contributions:

| AI | Model | Purpose | Schedule |
|----|-------|---------|----------|
| Claude | Sonnet 4 | Primary contributor | On-demand/6h |
| GPT-4 | Turbo | Secondary contributor | 12h |
| Gemini | Pro | Research & analysis | 8h |
| Ollama | Llama3 | Local security tasks | 4h |

## MCP Servers

Available MCP servers configured in `mcp.json`:

- **filesystem** - File operations on ./content
- **github** - GitHub API integration
- **brave-search** - Web search
- **puppeteer** - Browser automation
- **docker** - Docker management
- **playwright** - Web testing
- **notion** - Notion integration
- **slack** - Slack notifications
- **linear** - Project management
- **sentry** - Error tracking
- **git** - Git operations
- **memory** - Persistent memory
- **sequential-thinking** - Advanced reasoning

## Available Commands

### Slash Commands
- `/commit` - Create git commit with staged changes
- `/test` - Run project tests
- `/review-pr` - Review pull requests

### Automation Workflows

Run manually via GitHub Actions:
1. **AI Auto Contributor** - Claude AI contributions
2. **GPT-4 Contributor** - OpenAI GPT contributions
3. **Gemini Contributor** - Google Gemini contributions
4. **Ollama Contributor** - Local Llama contributions
5. **Auto Security Scan** - Daily security topic scanning
6. **Link Checker** - Broken link detection
7. **TOC Generator** - Auto-generate table of contents

## LLM Configuration

Configured in `mcp.json`:
- **Anthropic**: Claude (default)
- **OpenAI**: GPT-4, GPT-3.5
- **Google**: Gemini Pro
- **Ollama**: Llama3 (local)

## Agent Configuration

Custom agents in `.claude/agents/`:
- **Pentesting AI** - Specialized for security research

## Contributing

1. AI contributors run automatically on schedule
2. Manual triggers available via GitHub Actions
3. All AI changes create pull requests for review

## Notes

- Node.js 20+ required for workflows
- Set required secrets: ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY
- Ollama runs locally (self-hosted runners recommended)