# AI Contributors Configuration

## Active AI Agents

| Agent | Emoji | Schedule | Status |
|-------|-------|----------|--------|
| Claude | 🤖 | Every 4 hours | ✅ Active |
| OpenCode | 🔵 | Every 6 hours | ✅ Active |
| GPT (OpenAI) | 🟢 | On demand | ✅ Active |
| Gemini | 🟡 | On demand | ✅ Active |
| LLaMA | 🟣 | On demand | ✅ Active |
| Mistral | 🔵 | On demand | ✅ Active |

## MCP Servers Configured

### Core
- `filesystem` - File system access
- `github` - GitHub API integration
- `git` - Git operations

### Search & Web
- `brave-search` - Web search
- `puppeteer` - Browser automation
- `fetch` - HTTP requests

### Database
- `postgres` - PostgreSQL
- `sqlite` - SQLite database

### Communication
- `slack` - Slack integration
- `linear` - Linear issue tracking
- `sentry` - Error monitoring

### Development
- `docker` - Docker container management
- `memory` - Persistent memory
- `sequential-thinking` - Reasoning

## API Keys Required

Add these secrets in GitHub Settings → Secrets and variables → Actions:

| Secret | Description |
|--------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic/Claude API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `GEMINI_API_KEY` | Google Gemini API key |
| `OPENCODE_API_KEY` | OpenCode API key |
| `CLAUDE_API_KEY` | Claude Code CLI key |

## Contributing as an AI

### Option 1: GitHub Actions
Trigger workflows manually or on schedule.

### Option 2: Local Development
1. Clone the repo
2. Install MCP servers: `npm install -g @modelcontextprotocol/server-*`
3. Configure your API keys
4. Make contributions

### Option 3: Pull Request
Submit changes via PR and AI will review.

## Bot Identity

Each AI agent uses this format:
- **Email**: `agent@ai.contributor`
- **Name**: `[Agent] AI`
- **Avatar**: GitHub default bot avatar

---

**Note**: To add more AI agents, edit `.github/workflows/` and add new workflow files.