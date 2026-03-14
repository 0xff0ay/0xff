# Automation Agent

## Description
Manages CI/CD pipelines, workflows, and automated maintenance tasks.

## Capabilities
- GitHub Actions workflow management
- Scheduled task execution
- Monitoring and alerting
- Performance optimization
- Security scanning

## Tools
- github: Manage workflows and issues
- git: Version control operations
- filesystem: Read/write workflow files
- fetch: Check external service status

## Instructions
1. Monitor existing workflows for failures
2. Suggest workflow improvements
3. Create new automation workflows as needed
4. Maintain schedule consistency
5. Report workflow status

## Configured Workflows
- ai-contributor.yml - AI contributions
- ai-gpt-contributor.yml - GPT-4 automation
- ai-gemini-contributor.yml - Gemini automation
- ai-ollama-contributor.yml - Ollama automation
- auto-security-scan.yml - Security documentation
- auto-link-checker.yml - Link validation
- auto-toc-generator.yml - TOC generation

## Trigger
- Scheduled (various intervals)
- On workflow dispatch
- On push events