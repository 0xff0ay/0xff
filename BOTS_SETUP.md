# Add AI Bots as Collaborators

To make AI contributors appear in your repo with icons:

## Step 1: Create Bot Accounts
Create these GitHub accounts (free):
- @claude-ai-bot
- @opencode-ai-bot
- @gpt-ai-bot
- @gemini-ai-bot

## Step 2: Invite Bots
Go to: https://github.com/0xff0ay/0xff/settings/collaboration
Add these bot usernames

## Step 3: Generate Tokens
For each bot, create a Personal Access Token with:
- repo (full control)
- workflow

## Step 4: Add as Secrets
In repo Settings → Secrets → Actions:
- CLAUDE_BOT_TOKEN: token from @claude-ai-bot
- OPENCODE_BOT_TOKEN: token from @opencode-ai-bot
- GPT_BOT_TOKEN: token from @gpt-ai-bot
- GEMINI_BOT_TOKEN: token from @gemini-ai-bot

## Step 5: Update Workflows
Edit `.github/workflows/ai-*.yml` to use bot tokens instead of GITHUB_TOKEN

---

**Current Status:**
- ✅ Workflows configured
- ✅ MCP servers ready
- ❌ Need bot accounts + API keys to make contributions