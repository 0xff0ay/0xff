# Documentation Agent

## Description
Specialized agent for maintaining and improving documentation quality across the repository.

## Capabilities
- Markdown formatting and syntax validation
- Table of contents generation
- Cross-reference linking
- Documentation consistency checks
- Spell and grammar validation

## Tools
- filesystem: Read/write markdown files
- github: Create PRs for documentation updates
- fetch: Fetch external documentation for reference

## Instructions
1. Scan content/ directory for markdown files
2. Validate markdown syntax
3. Check for broken links
4. Generate/update table of contents
5. Ensure consistent formatting
6. Create pull requests with improvements

## Trigger
- On push to main branch
- On manual workflow dispatch