---
title: How to Build a CI/CD Pipeline with GitHub Actions
description: Master GitHub Actions from scratch — automate testing, building, and deploying your applications with powerful, event-driven CI/CD workflows.
navigation:
  icon: i-simple-icons-githubactions
---

## Introduction

GitHub Actions is a **CI/CD platform** built directly into GitHub that lets you automate your software development workflows. From running tests on every push to deploying production releases — all defined as code inside your repository.

::note
CI/CD stands for **Continuous Integration** (automatically testing and merging code) and **Continuous Delivery/Deployment** (automatically releasing to production). GitHub Actions handles both.
::

::card-group
  ::card
  ---
  title: What You'll Learn
  icon: i-lucide-book-open
  ---
  - Write workflow files from scratch
  - Run tests & lint on every push/PR
  - Build and push Docker images
  - Deploy to production environments
  - Use secrets, caching, and matrix builds
  ::

  ::card
  ---
  title: Prerequisites
  icon: i-lucide-clipboard-check
  ---
  - A GitHub account & repository
  - Basic Git knowledge (push, pull, branches)
  - Familiarity with YAML syntax
  - A project with tests (Node.js used in examples)
  ::
::

---

## Why GitHub Actions?

Many CI/CD tools exist, but GitHub Actions has unique advantages by being **native to GitHub**.

::tabs
  :::tabs-item{icon="i-lucide-scale" label="Comparison"}

  | Feature              | GitHub Actions       | Jenkins              | GitLab CI            | CircleCI            |
  | -------------------- | -------------------- | -------------------- | -------------------- | ------------------- |
  | Setup                | Zero — built into GH | Self-hosted server   | Built into GitLab    | SaaS account needed |
  | Config               | YAML in repo         | Groovy / UI          | YAML in repo         | YAML in repo        |
  | Marketplace          | 20,000+ actions      | 1,800+ plugins       | Templates available  | Orbs registry       |
  | Free Tier            | 2,000 mins/month     | Free (self-hosted)   | 400 mins/month       | 6,000 mins/month    |
  | Container Support    | Native               | Plugin required      | Native               | Native              |
  | Matrix Builds        | ✅ Built-in          | Plugin required      | ✅ Built-in          | ✅ Built-in         |
  | Self-hosted Runners  | ✅ Supported         | ✅ Default           | ✅ Supported         | ✅ Supported        |

  :::

  :::tabs-item{icon="i-lucide-sparkles" label="Key Benefits"}

  - **Zero infrastructure** — No servers to maintain, GitHub hosts the runners
  - **Event-driven** — Trigger on push, PR, schedule, release, issue, or any GitHub event
  - **Marketplace ecosystem** — Thousands of pre-built actions to plug into your workflow
  - **Matrix strategy** — Test across multiple OS, language versions, and configurations in parallel
  - **Built-in secrets** — Encrypted secret management for API keys and credentials
  - **Reusable workflows** — Share pipelines across repositories with composite actions
  - **Free for public repos** — Unlimited minutes for open-source projects

  :::
::

::tip
GitHub Actions is **free for public repositories** with unlimited minutes. Private repos get **2,000 free minutes/month** on the Free plan and **3,000 minutes** on the Pro plan.
::

---

## Core Concepts

Before writing your first workflow, understand the building blocks:

![GitHub Actions Workflow Architecture](https://docs.github.com/assets/cb-25535/mw-1440/images/help/actions/overview-actions-simple.webp)

::card-group
  ::card
  ---
  title: Workflow
  icon: i-lucide-git-branch
  ---
  A configurable automated process defined in a **YAML file** inside `.github/workflows/`. A repository can have multiple workflows, each triggered by different events.
  ::

  ::card
  ---
  title: Event
  icon: i-lucide-zap
  ---
  A specific activity that **triggers** a workflow — like `push`, `pull_request`, `release`, `schedule`, or even `workflow_dispatch` for manual triggers.
  ::

  ::card
  ---
  title: Job
  icon: i-lucide-layers
  ---
  A set of **steps** that execute on the same runner. Jobs run in **parallel by default** but can be configured to run sequentially with dependencies.
  ::

  ::card
  ---
  title: Step
  icon: i-lucide-footprints
  ---
  An individual task inside a job. A step can run a **shell command** (`run:`) or use a **pre-built action** (`uses:`).
  ::

  ::card
  ---
  title: Runner
  icon: i-lucide-server
  ---
  The **virtual machine** that executes your jobs. GitHub provides hosted runners (Ubuntu, Windows, macOS) or you can use self-hosted runners.
  ::

  ::card
  ---
  title: Action
  icon: i-lucide-puzzle
  ---
  A **reusable unit** of code from the GitHub Marketplace. Actions handle common tasks like checking out code, setting up languages, or deploying.
  ::
::

### How It All Connects

```mdc
Workflow (.yml file)
├── Event Trigger (on: push)
├── Job 1: test (runs-on: ubuntu-latest)
│   ├── Step 1: Checkout code (uses: actions/checkout@v4)
│   ├── Step 2: Setup Node.js (uses: actions/setup-node@v4)
│   ├── Step 3: Install deps (run: npm ci)
│   └── Step 4: Run tests (run: npm test)
├── Job 2: build (needs: test)
│   ├── Step 1: Checkout code
│   ├── Step 2: Build app (run: npm run build)
│   └── Step 3: Upload artifact
└── Job 3: deploy (needs: build)
    ├── Step 1: Download artifact
    └── Step 2: Deploy to production
```

::note
Jobs run on **separate runners** (fresh VMs). To pass data between jobs, use **artifacts** or **outputs**. Each job starts with a clean environment.
::

---

## Project Setup

::steps{level="3"}

### Create the Directory Structure

GitHub Actions looks for workflow files in a specific location:

::code-tree{default-value=".github/workflows/ci.yml"}
```yaml [.github/workflows/ci.yml]
# We'll build this step by step
```

```yaml [.github/workflows/deploy.yml]
# Deployment workflow — we'll add this later
```

```json [package.json]
{
  "name": "my-app",
  "version": "1.0.0",
  "scripts": {
    "dev": "nuxt dev",
    "build": "nuxt build",
    "test": "vitest run",
    "test:coverage": "vitest run --coverage",
    "lint": "eslint .",
    "lint:fix": "eslint --fix .",
    "typecheck": "nuxt typecheck"
  },
  "dependencies": {
    "nuxt": "^4.1.0",
    "@nuxt/ui": "^3.0.0"
  },
  "devDependencies": {
    "vitest": "^3.2.1",
    "@vitest/coverage-v8": "^3.2.1",
    "eslint": "^9.34.0",
    "@nuxt/eslint": "^1.4.1",
    "typescript": "^5.9.3"
  }
}
```

```ts [vitest.config.ts]
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'html'],
      thresholds: {
        statements: 80,
        branches: 80,
        functions: 80,
        lines: 80
      }
    }
  }
})
```

```dockerfile [Dockerfile]
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS production
WORKDIR /app
COPY --from=build /app/.output .output
EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
```

```ignore [.gitignore]
node_modules/
.output/
.nuxt/
dist/
coverage/
*.log
.env
```
::

::caution
Workflow files **must** be placed in `.github/workflows/` at the root of your repository. GitHub will not detect them in any other location.
::

### Understand Workflow File Anatomy

Every workflow file follows this structure:

```yaml [.github/workflows/ci.yml]
# 1. Name — displayed in the GitHub Actions UI
name: CI Pipeline

# 2. Triggers — when should this workflow run?
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

# 3. Jobs — what should happen?
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```
::
::field-group
  ::field{name="name" type="string"}
  Display name shown in the GitHub Actions tab. Make it descriptive — you'll have multiple workflows.
  ::

  ::field{name="on" type="object"}
  **Required.** Defines which events trigger the workflow. Supports `push`, `pull_request`, `schedule`, `workflow_dispatch`, `release`, and [40+ more](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows).
  ::

  ::field{name="jobs" type="object"}
  **Required.** Contains one or more jobs. Each job has a unique ID key and runs on its own runner.
  ::

  ::field{name="runs-on" type="string"}
  **Required per job.** Specifies the runner environment: `ubuntu-latest`, `ubuntu-24.04`, `windows-latest`, `macos-latest`, or a self-hosted runner label.
  ::

  ::field{name="steps" type="array"}
  **Required per job.** Ordered list of steps — each either `uses:` an action or `run:` a shell command.
  ::

  ::field{name="needs" type="string | array"}
  Makes a job wait for other jobs to complete. Creates sequential execution between parallel jobs.
  ::

  ::field{name="permissions" type="object"}
  Fine-grained control over the `GITHUB_TOKEN` permissions. Follow principle of least privilege.
  ::


---

## Building the CI Pipeline

Let's build a complete, production-grade CI pipeline step by step.

::steps{level="3"}

### Basic CI — Lint & Test

Start with the fundamentals: ensure every push and pull request passes linting and tests.

```yaml [.github/workflows/ci.yml]
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

# Cancel in-progress runs for the same branch/PR
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    name: 🔍 Lint
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run ESLint
        run: npm run lint

      - name: Type check
        run: npm run typecheck

  test:
    name: 🧪 Test
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run tests with coverage
        run: npm run test:coverage

      - name: Upload coverage report
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: coverage/
          retention-days: 7
```

::tip
The `concurrency` block prevents wasted resources — if you push again while a workflow is running for the same branch, the old run is **automatically cancelled**.
::

### Add Matrix Strategy

Test across multiple Node.js versions and operating systems simultaneously:

```yaml [.github/workflows/ci.yml — matrix job]
  test-matrix:
    name: 🧪 Test (Node ${{ matrix.node-version }} / ${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        node-version: [18, 20, 22]
        os: [ubuntu-latest, windows-latest, macos-latest]
        exclude:
          # Skip Node 18 on macOS to save minutes
          - os: macos-latest
            node-version: 18
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test
```

This creates **8 parallel jobs** (3 × 3 minus 1 exclusion):

| | Ubuntu | Windows | macOS |
|---|---|---|---|
| **Node 18** | ✅ | ✅ | ❌ excluded |
| **Node 20** | ✅ | ✅ | ✅ |
| **Node 22** | ✅ | ✅ | ✅ |

::note
Set `fail-fast: false` so all matrix combinations run to completion even if one fails. This helps you identify **all** compatibility issues in a single run.
::

### Add Build Step

Ensure your application builds successfully before merging:

```yaml [.github/workflows/ci.yml — build job]
  build:
    name: 🏗️ Build
    runs-on: ubuntu-latest
    needs: [lint, test]
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build application
        run: npm run build

      - name: Upload build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: .output/
          retention-days: 3
```

::warning
The `needs: [lint, test]` line means the build job **only runs after** both lint and test jobs succeed. If either fails, build is skipped entirely.
::

---

## The Complete CI Workflow

Here's the full CI workflow file combining everything:

::code-collapse

```yaml [.github/workflows/ci.yml]
# ============================================================================
# CI Pipeline
# Runs on every push to main/develop and every pull request targeting main
# ============================================================================

name: CI

on:
  push:
    branches: [main, develop]
    paths-ignore:
      - '*.md'
      - 'docs/**'
      - '.vscode/**'
      - 'LICENSE'
  pull_request:
    branches: [main]
    paths-ignore:
      - '*.md'
      - 'docs/**'

# Cancel previous runs for the same ref
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

# Minimum permissions
permissions:
  contents: read

jobs:
  # ──────────────────────────────────────────────
  # Lint & Type Check
  # ──────────────────────────────────────────────
  lint:
    name: 🔍 Lint & Type Check
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run ESLint
        run: npm run lint

      - name: Type check
        run: npm run typecheck

  # ──────────────────────────────────────────────
  # Unit & Integration Tests
  # ──────────────────────────────────────────────
  test:
    name: 🧪 Test
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run tests with coverage
        run: npm run test:coverage

      - name: Upload coverage report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: coverage/
          retention-days: 7

      - name: Check coverage thresholds
        run: |
          COVERAGE=$(cat coverage/coverage-summary.json | jq '.total.lines.pct')
          echo "Line coverage: ${COVERAGE}%"
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "::error::Coverage ${COVERAGE}% is below 80% threshold"
            exit 1
          fi

  # ──────────────────────────────────────────────
  # Matrix Testing (Multiple Node.js versions)
  # ──────────────────────────────────────────────
  test-compat:
    name: 🔄 Compat (Node ${{ matrix.node-version }})
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        node-version: [18, 20, 22]
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test

  # ──────────────────────────────────────────────
  # Build Application
  # ──────────────────────────────────────────────
  build:
    name: 🏗️ Build
    runs-on: ubuntu-latest
    timeout-minutes: 15
    needs: [lint, test]
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build application
        run: npm run build
        env:
          NODE_ENV: production

      - name: Upload build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: .output/
          retention-days: 3

  # ──────────────────────────────────────────────
  # Build & Push Docker Image
  # ──────────────────────────────────────────────
  docker:
    name: 🐳 Docker Build
    runs-on: ubuntu-latest
    timeout-minutes: 20
    needs: [build]
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    permissions:
      contents: read
      packages: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{ github.repository }}
          tags: |
            type=sha,prefix=
            type=ref,event=branch
            type=semver,pattern={{version}}
            type=raw,value=latest,enable={{is_default_branch}}

      - name: Build and push Docker image
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  # ──────────────────────────────────────────────
  # Pipeline Status Gate
  # ──────────────────────────────────────────────
  ci-status:
    name: ✅ CI Status
    runs-on: ubuntu-latest
    needs: [lint, test, test-compat, build]
    if: always()
    steps:
      - name: Check all job results
        run: |
          if [[ "${{ needs.lint.result }}" != "success" ]] ||
             [[ "${{ needs.test.result }}" != "success" ]] ||
             [[ "${{ needs.build.result }}" != "success" ]]; then
            echo "::error::One or more required jobs failed"
            exit 1
          fi
          echo "✅ All required checks passed!"
```

::

### Workflow Visualization

This is how the jobs flow when triggered:

```
push to main
    │
    ├──→ 🔍 Lint ──────────┐
    │                       ├──→ 🏗️ Build ──→ 🐳 Docker ──→ 🚀 Deploy
    ├──→ 🧪 Test ──────────┘
    │
    └──→ 🔄 Compat (18, 20, 22)   ← runs independently
```

::tip
The `ci-status` job acts as a **status gate** — use it as the single required check in branch protection rules instead of listing every individual job.
::

---

## Building the CD Pipeline

Now let's add **Continuous Deployment** — automatically deploying when CI passes on `main`.

::steps{level="3"}

### Configure Secrets

Store sensitive deployment credentials in GitHub Secrets:

::tabs
  :::tabs-item{icon="i-lucide-settings" label="How to Add Secrets"}

  1. Go to your repository on GitHub
  2. Navigate to **Settings** → **Secrets and variables** → **Actions**
  3. Click **New repository secret**
  4. Add your secrets:

  | Secret Name | Description | Example |
  |---|---|---|
  | `DEPLOY_HOST` | Server IP or hostname | `203.0.113.50` |
  | `DEPLOY_USERNAME` | SSH username | `deploy` |
  | `DEPLOY_SSH_KEY` | Private SSH key | `-----BEGIN OPENSSH...` |
  | `DOCKER_USERNAME` | Docker Hub username | `myuser` |
  | `DOCKER_PASSWORD` | Docker Hub token | `dckr_pat_xxx...` |
  | `VERCEL_TOKEN` | Vercel deploy token | `vrcl_xxx...` |

  :::

  :::tabs-item{icon="i-lucide-shield" label="Environment Secrets"}

  For environment-specific secrets, use **GitHub Environments**:

  ```yaml
  jobs:
    deploy:
      environment: production    # Uses secrets from "production" environment
      runs-on: ubuntu-latest
      steps:
        - run: echo "Deploying to ${{ vars.DEPLOY_URL }}"
  ```

  Environments support:
  - **Required reviewers** — manual approval before deploy
  - **Wait timer** — delay deployment by N minutes
  - **Branch restrictions** — only allow deploys from `main`
  - **Environment-specific secrets** — different credentials per environment

  :::
::

::caution
**Never** hardcode secrets in workflow files. Always use `${{ secrets.SECRET_NAME }}`. Secrets are automatically **masked** in logs — GitHub replaces them with `***`.
::

### Deploy to Multiple Targets

::tabs
  :::tabs-item{icon="i-simple-icons-vercel" label="Vercel"}
  ```yaml [.github/workflows/deploy-vercel.yml]
  name: Deploy to Vercel

  on:
    push:
      branches: [main]

  jobs:
    deploy:
      name: 🚀 Deploy to Vercel
      runs-on: ubuntu-latest
      environment:
        name: production
        url: ${{ steps.deploy.outputs.url }}
      steps:
        - name: Checkout code
          uses: actions/checkout@v4

        - name: Setup Node.js
          uses: actions/setup-node@v4
          with:
            node-version: 20
            cache: 'npm'

        - name: Install Vercel CLI
          run: npm i -g vercel@latest

        - name: Pull Vercel environment
          run: vercel pull --yes --environment=production --token=${{ secrets.VERCEL_TOKEN }}

        - name: Build project
          run: vercel build --prod --token=${{ secrets.VERCEL_TOKEN }}

        - name: Deploy to production
          id: deploy
          run: |
            URL=$(vercel deploy --prebuilt --prod --token=${{ secrets.VERCEL_TOKEN }})
            echo "url=$URL" >> "$GITHUB_OUTPUT"
  ```
  :::

  :::tabs-item{icon="i-simple-icons-docker" label="Docker + SSH"}
  ```yaml [.github/workflows/deploy-docker.yml]
  name: Deploy via Docker

  on:
    push:
      branches: [main]

  jobs:
    deploy:
      name: 🚀 Deploy to Server
      runs-on: ubuntu-latest
      needs: [build, docker]
      environment:
        name: production
        url: https://myapp.example.com
      steps:
        - name: Deploy via SSH
          uses: appleboy/ssh-action@v1
          with:
            host: ${{ secrets.DEPLOY_HOST }}
            username: ${{ secrets.DEPLOY_USERNAME }}
            key: ${{ secrets.DEPLOY_SSH_KEY }}
            script: |
              cd /opt/myapp

              # Pull latest image
              docker pull ghcr.io/${{ github.repository }}:latest

              # Update running containers
              docker compose pull
              docker compose up -d --remove-orphans

              # Cleanup old images
              docker image prune -f

              # Verify health
              sleep 10
              curl -f http://localhost:3000/api/health || exit 1
              echo "✅ Deployment successful!"
  ```
  :::

  :::tabs-item{icon="i-simple-icons-amazonaws" label="AWS S3 + CloudFront"}
  ```yaml [.github/workflows/deploy-aws.yml]
  name: Deploy to AWS

  on:
    push:
      branches: [main]

  permissions:
    id-token: write
    contents: read

  jobs:
    deploy:
      name: 🚀 Deploy to AWS
      runs-on: ubuntu-latest
      environment: production
      steps:
        - name: Checkout code
          uses: actions/checkout@v4

        - name: Setup Node.js
          uses: actions/setup-node@v4
          with:
            node-version: 20
            cache: 'npm'

        - name: Install & Build
          run: |
            npm ci
            npm run build

        - name: Configure AWS credentials
          uses: aws-actions/configure-aws-credentials@v4
          with:
            role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
            aws-region: us-east-1

        - name: Sync to S3
          run: |
            aws s3 sync .output/public s3://${{ secrets.AWS_S3_BUCKET }} \
              --delete \
              --cache-control "max-age=31536000"

        - name: Invalidate CloudFront cache
          run: |
            aws cloudfront create-invalidation \
              --distribution-id ${{ secrets.AWS_CF_DISTRIBUTION_ID }} \
              --paths "/*"
  ```
  :::

  :::tabs-item{icon="i-simple-icons-cloudflare" label="Cloudflare Pages"}
  ```yaml [.github/workflows/deploy-cloudflare.yml]
  name: Deploy to Cloudflare Pages

  on:
    push:
      branches: [main]

  jobs:
    deploy:
      name: 🚀 Deploy to Cloudflare
      runs-on: ubuntu-latest
      environment:
        name: production
        url: ${{ steps.deploy.outputs.deployment-url }}
      permissions:
        contents: read
        deployments: write
      steps:
        - name: Checkout code
          uses: actions/checkout@v4

        - name: Setup Node.js
          uses: actions/setup-node@v4
          with:
            node-version: 20
            cache: 'npm'

        - name: Install & Build
          run: |
            npm ci
            npm run build

        - name: Deploy to Cloudflare Pages
          id: deploy
          uses: cloudflare/wrangler-action@v3
          with:
            apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
            accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
            command: pages deploy .output/public --project-name=my-app
  ```
  :::
::

### Add Deployment Notifications

Get notified when deployments succeed or fail:

```yaml [Notification step — add to any deploy job]
      - name: Notify on success
        if: success()
        uses: slackapi/slack-github-action@v2
        with:
          webhook: ${{ secrets.SLACK_WEBHOOK_URL }}
          webhook-type: incoming-webhook
          payload: |
            {
              "text": "✅ *${{ github.repository }}* deployed successfully!",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "✅ *Deployment Successful*\n*Repo:* ${{ github.repository }}\n*Branch:* `${{ github.ref_name }}`\n*Commit:* `${{ github.sha }}` by ${{ github.actor }}\n*URL:* ${{ steps.deploy.outputs.url }}"
                  }
                }
              ]
            }

      - name: Notify on failure
        if: failure()
        uses: slackapi/slack-github-action@v2
        with:
          webhook: ${{ secrets.SLACK_WEBHOOK_URL }}
          webhook-type: incoming-webhook
          payload: |
            {
              "text": "❌ *${{ github.repository }}* deployment FAILED!",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "❌ *Deployment Failed*\n*Repo:* ${{ github.repository }}\n*Branch:* `${{ github.ref_name }}`\n*Commit:* `${{ github.sha }}`\n*Logs:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Run>"
                  }
                }
              ]
            }
```

::

---

## Advanced Patterns

::accordion
  :::accordion-item{icon="i-lucide-zap" label="Caching Dependencies"}
  Speed up workflows by caching `node_modules`:

  ```yaml
  - name: Setup Node.js
    uses: actions/setup-node@v4
    with:
      node-version: 20
      cache: 'npm'    # ← Built-in caching!
  ```

  For custom caching:

  ```yaml
  - name: Cache node_modules
    uses: actions/cache@v4
    id: cache-deps
    with:
      path: node_modules
      key: deps-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
      restore-keys: |
        deps-${{ runner.os }}-

  - name: Install dependencies
    if: steps.cache-deps.outputs.cache-hit != 'true'
    run: npm ci
  ```

  ::tip
  Caching typically reduces install time from **45–90 seconds** down to **2–5 seconds**.
  ::
  :::

  :::accordion-item{icon="i-lucide-database" label="Service Containers (Databases in CI)"}
  Need a real database for integration tests? Use service containers:

  ```yaml
  jobs:
    test-integration:
      runs-on: ubuntu-latest
      services:
        postgres:
          image: postgres:16-alpine
          env:
            POSTGRES_USER: testuser
            POSTGRES_PASSWORD: testpass
            POSTGRES_DB: testdb
          ports:
            - 5432:5432
          options: >-
            --health-cmd="pg_isready -U testuser"
            --health-interval=10s
            --health-timeout=5s
            --health-retries=5

        redis:
          image: redis:7-alpine
          ports:
            - 6379:6379
          options: >-
            --health-cmd="redis-cli ping"
            --health-interval=10s
            --health-timeout=5s
            --health-retries=5

      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-node@v4
          with:
            node-version: 20
            cache: 'npm'
        - run: npm ci
        - run: npm run test:integration
          env:
            DATABASE_URL: postgres://testuser:testpass@localhost:5432/testdb
            REDIS_URL: redis://localhost:6379
  ```
  :::

  :::accordion-item{icon="i-lucide-recycle" label="Reusable Workflows"}
  Share workflows across repositories to avoid duplication:

  ```yaml [.github/workflows/reusable-ci.yml]
  # Callable workflow — other repos can use this
  name: Reusable CI

  on:
    workflow_call:
      inputs:
        node-version:
          required: false
          type: string
          default: '20'
        run-e2e:
          required: false
          type: boolean
          default: false
      secrets:
        SONAR_TOKEN:
          required: false

  jobs:
    ci:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-node@v4
          with:
            node-version: ${{ inputs.node-version }}
            cache: 'npm'
        - run: npm ci
        - run: npm run lint
        - run: npm test
        - run: npm run test:e2e
          if: ${{ inputs.run-e2e }}
  ```

  Call it from another workflow:

  ```yaml [.github/workflows/ci.yml]
  name: CI
  on: [push, pull_request]

  jobs:
    ci:
      uses: my-org/shared-workflows/.github/workflows/reusable-ci.yml@main
      with:
        node-version: '20'
        run-e2e: true
      secrets:
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
  ```
  :::

  :::accordion-item{icon="i-lucide-git-pull-request" label="PR Preview Deployments"}
  Deploy every pull request to a unique preview URL:

  ```yaml [.github/workflows/preview.yml]
  name: Preview Deployment

  on:
    pull_request:
      types: [opened, synchronize, reopened]

  jobs:
    preview:
      runs-on: ubuntu-latest
      permissions:
        contents: read
        pull-requests: write
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-node@v4
          with:
            node-version: 20
            cache: 'npm'

        - run: npm ci && npm run build

        - name: Deploy preview
          id: deploy
          uses: cloudflare/wrangler-action@v3
          with:
            apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
            accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
            command: pages deploy .output/public --project-name=my-app --branch=${{ github.head_ref }}

        - name: Comment preview URL on PR
          uses: actions/github-script@v7
          with:
            script: |
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: `🚀 **Preview deployed!**\n\n🔗 ${{ steps.deploy.outputs.deployment-url }}\n\n_Commit: \`${{ github.sha }}\`_`
              })
  ```
  :::

  :::accordion-item{icon="i-lucide-tag" label="Release Automation with Semantic Versioning"}
  Automatically create releases based on conventional commits:

  ```yaml [.github/workflows/release.yml]
  name: Release

  on:
    push:
      branches: [main]

  permissions:
    contents: write
    pull-requests: write

  jobs:
    release:
      runs-on: ubuntu-latest
      steps:
        - name: Create Release PR or Publish
          uses: googleapis/release-please-action@v4
          id: release
          with:
            release-type: node
            token: ${{ secrets.GITHUB_TOKEN }}

        - name: Checkout code
          if: ${{ steps.release.outputs.release_created }}
          uses: actions/checkout@v4

        - name: Setup Node.js
          if: ${{ steps.release.outputs.release_created }}
          uses: actions/setup-node@v4
          with:
            node-version: 20
            registry-url: 'https://registry.npmjs.org'

        - name: Publish to npm
          if: ${{ steps.release.outputs.release_created }}
          run: npm publish
          env:
            NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
  ```
  :::

  :::accordion-item{icon="i-lucide-clock" label="Scheduled Workflows (Cron Jobs)"}
  Run workflows on a schedule for maintenance tasks:

  ```yaml [.github/workflows/scheduled.yml]
  name: Scheduled Tasks

  on:
    schedule:
      # Run every Monday at 9:00 AM UTC
      - cron: '0 9 * * 1'

    # Also allow manual trigger
    workflow_dispatch:

  jobs:
    dependency-audit:
      name: 🔒 Security Audit
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-node@v4
          with:
            node-version: 20
        - run: npm audit --audit-level=high
        - run: npx licensee --errors-only

    stale-issues:
      name: 🧹 Clean Stale Issues
      runs-on: ubuntu-latest
      permissions:
        issues: write
        pull-requests: write
      steps:
        - uses: actions/stale@v9
          with:
            stale-issue-message: 'This issue has been inactive for 30 days.'
            days-before-stale: 30
            days-before-close: 7
  ```

  Common cron patterns:

  | Schedule | Cron Expression |
  |---|---|
  | Every 15 minutes | `*/15 * * * *` |
  | Every hour | `0 * * * *` |
  | Daily at midnight | `0 0 * * *` |
  | Weekly on Monday | `0 9 * * 1` |
  | Monthly on the 1st | `0 0 1 * *` |
  :::
::

---

## Workflow Security Best Practices

::card-group
  ::card
  ---
  title: Pin Action Versions
  icon: i-lucide-lock
  ---
  Always pin actions to a **full commit SHA** instead of a tag for production workflows:

  ```yaml
  # ✅ Pinned to commit SHA (secure)
  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

  # ⚠️ Tag reference (less secure)
  uses: actions/checkout@v4

  # ❌ Branch reference (insecure)
  uses: actions/checkout@main
  ```
  ::

  ::card
  ---
  title: Minimal Permissions
  icon: i-lucide-shield
  ---
  Set the most restrictive `permissions` possible at the workflow and job level:

  ```yaml
  permissions:
    contents: read       # Only read repo contents
    packages: write      # Push container images
    pull-requests: write # Comment on PRs
    # All other permissions are 'none'
  ```
  ::

  ::card
  ---
  title: Protect Secrets
  icon: i-lucide-key-round
  ---
  - Use **environment protection rules** for production secrets
  - Enable **required reviewers** on production environments
  - Rotate secrets regularly
  - Never echo or log secrets (`${{ secrets.* }}` is auto-masked)
  ::

  ::card
  ---
  title: Limit PR Triggers
  icon: i-lucide-git-pull-request
  ---
  Prevent malicious PRs from exfiltrating secrets:

  ```yaml
  on:
    pull_request_target:  # ⚠️ Has access to secrets
      types: [labeled]    # Only run when labeled

    pull_request:         # ✅ Safe — no secret access
      branches: [main]
  ```
  ::
::

---

## Monitoring & Debugging

### Understanding Workflow Logs

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Debugging Tips"}
  ```yaml [Enable debug logging]
  # Option 1: Add to your steps
  - name: Debug info
    run: |
      echo "Event: ${{ github.event_name }}"
      echo "Ref: ${{ github.ref }}"
      echo "SHA: ${{ github.sha }}"
      echo "Actor: ${{ github.actor }}"
      echo "Runner OS: ${{ runner.os }}"
      echo "Workspace: ${{ github.workspace }}"

  # Option 2: Enable step debug logging
  # Add secret: ACTIONS_STEP_DEBUG = true
  # This prints verbose output for every step
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Useful Commands"}
  ```yaml
  # Print all environment variables
  - run: env | sort

  # Print GitHub context (all available data)
  - run: echo '${{ toJSON(github) }}'

  # Print working directory contents
  - run: ls -la

  # Check disk space
  - run: df -h

  # Check available memory
  - run: free -m
  ```
  :::

  :::tabs-item{icon="i-lucide-workflow" label="Status Badges"}
  Add a status badge to your README:

  ```md [README.md]
  ![CI](https://github.com/USERNAME/REPO/actions/workflows/ci.yml/badge.svg)
  ![Deploy](https://github.com/USERNAME/REPO/actions/workflows/deploy.yml/badge.svg?branch=main)
  ```

  Result: ![CI](https://img.shields.io/badge/CI-passing-brightgreen) ![Deploy](https://img.shields.io/badge/Deploy-success-blue)
  :::
::

---

## Troubleshooting

::accordion
  :::accordion-item{icon="i-lucide-alert-triangle" label="Workflow not triggering"}
  ```yaml
  # Common causes:
  # 1. File not in .github/workflows/
  # 2. YAML syntax error — validate with:
  #    https://rhysd.github.io/actionlint/

  # 3. paths-ignore is filtering out your changes
  on:
    push:
      paths-ignore:
        - '*.md'    # This ignores ALL .md changes

  # 4. Branch name doesn't match
  on:
    push:
      branches: [main]     # Won't trigger on 'master'

  # 5. Workflow is disabled — check Actions tab
  # Go to: Actions → Select workflow → Enable workflow
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Permission denied errors"}
  ```yaml
  # Error: "Resource not accessible by integration"
  # Fix: Add explicit permissions
  permissions:
    contents: read
    packages: write
    pull-requests: write

  # Error: "Permission to X denied to github-actions[bot]"
  # Fix: Check repository Settings → Actions → General
  # Ensure "Read and write permissions" is selected
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Cache not working"}
  ```yaml
  # 1. Ensure cache key changes when dependencies change
  key: deps-${{ hashFiles('**/package-lock.json') }}

  # 2. Check cache size (10 GB limit per repository)
  # 3. Caches expire after 7 days of no access

  # 4. Force cache invalidation by changing the key prefix
  key: v2-deps-${{ hashFiles('**/package-lock.json') }}
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Docker build is slow"}
  ```yaml
  # Use GitHub Actions cache for Docker layers
  - uses: docker/build-push-action@v6
    with:
      context: .
      push: true
      tags: myapp:latest
      cache-from: type=gha          # ← Read cache from GHA
      cache-to: type=gha,mode=max   # ← Write cache to GHA

  # This typically reduces build time by 60-80%
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Out of disk space on runner"}
  ```yaml
  # GitHub-hosted runners have ~14 GB free
  # Free up space before heavy builds:
  - name: Free disk space
    run: |
      sudo rm -rf /usr/share/dotnet
      sudo rm -rf /opt/ghc
      sudo rm -rf /usr/local/share/boost
      sudo rm -rf "$AGENT_TOOLSDIRECTORY"
      df -h
  ```
  :::
::

---

## Complete Pipeline Overview

Here's the final architecture of our CI/CD pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Repository                        │
│                                                             │
│  Push / PR ──→ .github/workflows/ci.yml                     │
│                    │                                        │
│                    ├── 🔍 Lint & Type Check                  │
│                    ├── 🧪 Test + Coverage                    │
│                    ├── 🔄 Compat Matrix (Node 18/20/22)     │
│                    │                                        │
│                    └── 🏗️ Build (needs: lint, test)          │
│                         │                                   │
│         ┌───────────────┴──────────────┐                    │
│         │ main branch only             │                    │
│         ▼                              ▼                    │
│    🐳 Docker Build               🚀 Deploy                  │
│    Push to GHCR                  Vercel / AWS / SSH          │
│         │                              │                    │
│         └──────────┬───────────────────┘                    │
│                    ▼                                        │
│              📢 Notifications                               │
│              Slack / Discord                                │
└─────────────────────────────────────────────────────────────┘
```

---

## Reference & Resources

::card-group
  ::card
  ---
  title: GitHub Actions Documentation
  icon: i-simple-icons-github
  to: https://docs.github.com/en/actions
  target: _blank
  ---
  Official docs — comprehensive guide covering workflows, syntax, runners, and all available features.
  ::

  ::card
  ---
  title: Workflow Syntax Reference
  icon: i-lucide-file-code
  to: https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions
  target: _blank
  ---
  Complete YAML reference for every key, context, expression, and function available in workflows.
  ::

  ::card
  ---
  title: GitHub Actions Marketplace
  icon: i-lucide-shopping-bag
  to: https://github.com/marketplace?type=actions
  target: _blank
  ---
  Browse 20,000+ pre-built actions for testing, deployment, notifications, security scanning, and more.
  ::

  ::card
  ---
  title: Events That Trigger Workflows
  icon: i-lucide-zap
  to: https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows
  target: _blank
  ---
  Complete list of 40+ events — push, PR, schedule, release, issue, label, deployment, and more.
  ::

  ::card
  ---
  title: actionlint — Workflow Linter
  icon: i-lucide-check-circle
  to: https://github.com/rhysd/actionlint
  target: _blank
  ---
  Static analysis tool for GitHub Actions workflow files. Catch YAML errors and misconfigurations before pushing.
  ::

  ::card
  ---
  title: GitHub Actions Examples
  icon: i-simple-icons-github
  to: https://github.com/actions/starter-workflows
  target: _blank
  ---
  Official starter workflow templates for dozens of languages, frameworks, and deployment targets.
  ::
::

---

::tip{to="/guides/docker-compose"}
**Deploying containers?** Check out our guide on running multi-container apps with Docker Compose to complement your CI/CD pipeline.
::