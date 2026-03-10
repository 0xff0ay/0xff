# 0xff — Offensive Security Researcher

> Zero Day Hunter · Bug Bounty Expert · Exploit Developer · Red Teamer

Personal offensive security research hub built to document vulnerabilities, share tools, publish write-ups, and provide free learning resources for the hacker community. Breaking systems to make them stronger.

---

## What Is This?

This is the source code for **[0xff.sh](https://0xff.sh)** — a comprehensive offensive security knowledge base and research portfolio covering:

- **Bug Bounty** — Methodologies, recon automation, and vulnerability chaining techniques
- **Cloud Security** — AWS, Azure, GCP offensive assessments and misconfigurations
- **Red Teaming** — Adversary simulation, C2 operations, and enterprise compromise
- **Zero Day Research** — Original CVE discoveries and responsible disclosure
- **Exploit Development** — Binary exploitation, ROP chains, and modern mitigations bypass
- **Web Application Security** — SSRF, deserialization, request smuggling, auth bypass
- **Mobile Security** — Android/iOS reverse engineering and runtime manipulation
- **Reverse Engineering** — Malware analysis, firmware extraction, binary analysis
- **Network Exploitation** — Infrastructure attacks, VLAN hopping, Wi-Fi hacking
- **Applied Cryptography** — Padding oracle, hash extension, TLS attacks

---

## Stats

| Metric | Count |
|--------|-------|
| Vulnerabilities Reported | **100+** |
| CVEs Published | **15+** |
| Hall of Fame Recognitions | **30+** |
| Total Bounties Earned | **$250K+** |
| Community Members | **10K+** |
| Open Source Tools | **50+** |

---

## Sponsors

This project is proudly supported by the following sponsors. Their support makes this research and free content possible.

<div align="center">

### Platinum Sponsor

<a href="https://1cloudng.com/">
  <img src="https://1cloudng.com/assets/OneCloud-Logo-D4GYoCsV.png" alt="1Cloud Next Generation" width="220" />
</a>

**[1Cloud Next Generation (1CNG)](https://1cloudng.com/)**

Next-generation cloud infrastructure provider powering security research, development environments, and high-performance deployments. 1CNG provides reliable VPS, dedicated servers, and cloud solutions optimized for security professionals and developers.

---

### Gold Sponsors

<table>
  <tr>
    <td align="center" width="200">
      <a href="https://github.com/lily0ng">
        <img src="https://avatars.githubusercontent.com/u/243206330?v=4" alt="Lily Yang" width="100" style="border-radius: 50%;" />
        <br />
        <strong>Lily Yang</strong>
      </a>
      <br />
      Developer & Security Enthusiast
    </td>
    <td align="center" width="200">
      <a href="https://github.com/0xff0ay">
        <img src="https://avatars.githubusercontent.com/u/264521594?v=4" alt="0xff" width="100" style="border-radius: 50%;" />
        <br />
        <strong>0xff</strong>
      </a>
      <br />
      Offensive Security Researcher
    </td>
  </tr>
</table>

---

### Community Sponsor

**Black Root Community**

Underground security research community focused on offensive security, vulnerability research, and knowledge sharing among ethical hackers and security researchers.

</div>

---

### Become a Sponsor

Want to support this project and get your brand in front of thousands of security professionals?

| Tier | Benefits |
|------|----------|
| **Platinum** | Logo on homepage, README, all pages, dedicated sponsor page, social media shoutout |
| **Gold** | Logo on README, sponsor page, social media mention |
| **Silver** | Name on README and sponsor page |
| **Community** | Name listed in README |

Contact **[contact@0xff.sh](mailto:contact@0xff.sh)** for sponsorship inquiries.

---

## Tech Stack

| Technology | Purpose |
|-----------|---------|
| [Nuxt 4](https://nuxt.com) | Web framework |
| [Nuxt Content](https://content.nuxt.com/) | File-based CMS for Markdown content |
| [Nuxt UI](https://ui.nuxt.com) | UI component library |
| [Nuxt Image](https://image.nuxt.com/) | Optimized image handling |
| [Tailwind CSS 4](https://tailwindcss.com/) | Utility-first styling |
| [Docus Layer](https://www.npmjs.com/package/docus) | Documentation theme layer |
| [Shiki](https://shiki.style/) | Syntax highlighting |
| [MDC](https://content.nuxt.com/usage/markdown) | Markdown components |

---

## Quick Start

### Prerequisites

- **Node.js** >= 18.0.0
- **npm** >= 9.0.0 or **pnpm** >= 8.0.0

### Installation

```bash
# Clone the repository
git clone https://github.com/0xff0ay/0xff.git
cd 0xff

# Install dependencies
npm install

# Start development server
npm run dev
```

Site will be running at **`http://localhost:3000`**

### Build for Production

```bash
# Generate production build
npm run build

# Preview production build locally
npm run preview
```

### Generate Static Site

```bash
# Generate static files
npm run generate
```

Output will be in the `.output/public` directory.

---

## Content Guide

### Adding a New Write-Up

Create a new Markdown file in `content/writeups/`:

```markdown
---
title: "Critical SSRF in Target Corp"
description: "Exploiting blind SSRF to access internal AWS metadata and achieve account takeover."
date: 2025-01-15
tags: [ssrf, aws, cloud, account-takeover]
severity: critical
platform: HackerOne
---

# Critical SSRF in Target Corp

## Summary
...

## Reconnaissance
...

## Exploitation
...

## Impact
...

## Remediation
...
```

### Adding a New Tool Page

Create a new Markdown file in `content/tools/`:

```markdown
---
title: "Custom Recon Framework"
description: "Automated reconnaissance pipeline for bug bounty targets."
github: https://github.com/0xff0ay/recon-tool
language: Python
---

# Recon Framework

## Installation
...

## Usage
...
```

---

## Configuration

### Brand and Theme — app.config.ts

```typescript
export default defineAppConfig({
  ui: {
    colors: {
      primary: 'green',
      neutral: 'zinc'
    }
  },
  seo: {
    siteName: '0xff — Offensive Security Researcher'
  },
  header: {
    title: '0xff',
    to: '/',
    logo: {
      light: '/0xff-light.svg',
      dark: '/0xff-dark.svg'
    },
    links: [
      {
        icon: 'i-simple-icons-github',
        to: 'https://github.com/0xff0ay/0xff',
        target: '_blank'
      },
      {
        icon: 'i-simple-icons-x',
        to: 'https://x.com/0xff0ay',
        target: '_blank'
      }
    ]
  },
  footer: {
    credits: '© 2025 0xff. All rights reserved.',
    links: [
      { title: 'GitHub', to: 'https://github.com/0xff0ay/0xff', target: '_blank' },
      { title: 'Twitter/X', to: 'https://x.com/0xff0ay', target: '_blank' },
      { title: 'LinkedIn', to: 'https://linkedin.com/in/0xff0ay', target: '_blank' },
      { title: 'Discord', to: 'https://discord.gg/0xff', target: '_blank' }
    ]
  }
})
```

### Nuxt Config — nuxt.config.ts

```typescript
export default defineNuxtConfig({
  extends: ['docus'],
  modules: [
    '@nuxt/content',
    '@nuxt/ui',
    '@nuxt/image'
  ],
  content: {
    highlight: {
      theme: {
        default: 'github-dark',
        dark: 'github-dark',
        light: 'github-light'
      },
      langs: [
        'python', 'bash', 'javascript', 'typescript',
        'go', 'ruby', 'java', 'php', 'c', 'cpp',
        'yaml', 'json', 'toml', 'sql', 'graphql',
        'dockerfile', 'powershell', 'hcl'
      ]
    }
  }
})
```

---

## Deployment

### 1Cloud Next Generation — 1CNG (Recommended)

**[1CNG](https://1cloudng.com/)** is the recommended deployment platform for 0xff. It provides high-performance cloud VPS instances optimized for Node.js applications with low latency, DDoS protection, and full root access.

<div align="center">
  <a href="https://1cloudng.com/">
    <img src="https://1cloudng.com/assets/OneCloud-Logo-D4GYoCsV.png" alt="Deploy on 1CNG" width="180" />
  </a>
</div>

#### VM Requirements

| Resource | Minimum | Recommended | Production |
|----------|---------|-------------|------------|
| **CPU** | 1 vCPU | 2 vCPU | 4 vCPU |
| **RAM** | 1 GB | 2 GB | 4 GB |
| **Storage** | 20 GB SSD | 40 GB SSD | 80 GB NVMe SSD |
| **Bandwidth** | 1 TB/month | 2 TB/month | 5 TB/month |
| **OS** | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS | Ubuntu 24.04 LTS |
| **Node.js** | v18.x | v20.x | v22.x |
| **Network** | 100 Mbps | 500 Mbps | 1 Gbps |

#### Step-by-Step Deployment on 1CNG

**1. Create a VM on 1CNG**

- Go to [1cloudng.com](https://1cloudng.com/) and sign up
- Create a new VPS instance with the recommended specifications above
- Select Ubuntu 22.04 LTS or Ubuntu 24.04 LTS as the operating system
- Note your server IP address and SSH credentials

**2. Connect to Your Server**

```bash
ssh root@your-server-ip
```

**3. Update System and Install Dependencies**

```bash
# Update system packages
apt update && apt upgrade -y

# Install essential packages
apt install -y curl git build-essential nginx certbot python3-certbot-nginx ufw

# Install Node.js 20.x
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# Verify installations
node -v
npm -v
```

**4. Configure Firewall**

```bash
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw enable
ufw status
```

**5. Clone and Build the Project**

```bash
# Create application directory
mkdir -p /var/www
cd /var/www

# Clone repository
git clone https://github.com/0xff0ay/0xff.git
cd 0xff

# Install dependencies
npm install

# Build for production
npm run build
```

**6. Install and Configure PM2**

```bash
# Install PM2 globally
npm install -g pm2

# Start the application
pm2 start .output/server/index.mjs --name 0xff

# Configure PM2 to start on boot
pm2 startup
pm2 save

# Check application status
pm2 status
pm2 logs 0xff
```

**7. Configure Nginx Reverse Proxy**

```bash
nano /etc/nginx/sites-available/0xff
```

Add the following configuration:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400;
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml text/javascript image/svg+xml;
}
```

Enable the site:

```bash
ln -s /etc/nginx/sites-available/0xff /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

**8. Install SSL Certificate**

```bash
certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

**9. Configure Auto-Renewal**

```bash
# Test renewal
certbot renew --dry-run

# Auto-renewal is configured automatically by certbot
```

**10. Setup Auto-Deploy Script (Optional)**

Create `/var/www/0xff/deploy.sh`:

```bash
#!/bin/bash
cd /var/www/0xff
git pull origin main
npm install
npm run build
pm2 restart 0xff
echo "Deployment complete at $(date)"
```

```bash
chmod +x /var/www/0xff/deploy.sh
```

---


### Vercel (Recommended)

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/0xff0ay/0xff)

```bash
npm i -g vercel
vercel
```

### Netlify

[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/0xff0ay/0xff)



### Cloudflare Pages

```bash
npm run build
npx wrangler pages deploy .output/public
```

### Docker

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
COPY --from=build /app/.output .output
EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
```

```bash
docker build -t 0xff .
docker run -p 3000:3000 0xff
```

### Docker on 1CNG

```bash
# On your 1CNG VPS
apt update && apt install -y docker.io docker-compose
systemctl enable docker

# Clone and build
git clone https://github.com/0xff0ay/0xff.git
cd 0xff
docker build -t 0xff .
docker run -d --name 0xff --restart always -p 3000:3000 0xff
```

Using Docker Compose — create `docker-compose.yml`:

```yaml
version: '3.8'
services:
  0xff:
    build: .
    container_name: 0xff
    restart: always
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - NUXT_HOST=0.0.0.0
      - NUXT_PORT=3000
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:3000"]
      interval: 30s
      timeout: 10s
      retries: 3
```

```bash
docker-compose up -d
```

---

## Contributing

Contributions are welcome. Whether it is fixing a typo, adding a new write-up, or improving tools:

1. **Fork** the repository
2. **Create** your feature branch — `git checkout -b feature/new-writeup`
3. **Commit** your changes — `git commit -m 'Add: new SSRF write-up'`
4. **Push** to the branch — `git push origin feature/new-writeup`
5. **Open** a Pull Request

### Contribution Guidelines

- Write-ups must be for **responsibly disclosed** vulnerabilities only
- Include proper **remediation guidance** in all write-ups
- Follow existing **Markdown formatting** conventions
- Add appropriate **tags and metadata** to frontmatter
- No active exploits against **unpatched** vulnerabilities
- All tools must include a **legal disclaimer**

---

## Legal Disclaimer

> **All content on this site is for educational and authorized security testing purposes only.**
>
> The techniques, tools, and methodologies documented here should only be used on systems you own or have **explicit written authorization** to test. Unauthorized access to computer systems is **illegal** and punishable by law.
>
> The author assumes **no liability** for misuse of any information or tools provided. Always follow **responsible disclosure** practices and applicable laws and regulations in your jurisdiction.
>
> By using this site, you agree to use the information **ethically and legally**.

---

## Contact

| Channel | Link |
|---------|------|
| Email | [contact@0xff.sh](mailto:contact@0xff.sh) |
| GitHub | [@0xff0ay](https://github.com/0xff0ay) |
| Twitter/X | [@0xff0ay](https://x.com/0xff0ay) |
| LinkedIn | [0xff0ay](https://linkedin.com/in/0xff0ay) |
| Discord | [Join Community](https://discord.gg/0xff) |
| RSS | [Feed](https://0xff.sh/rss.xml) |

---

## Support

If this project helps you learn or find bugs, consider supporting:

- **Star** this repository
- **Fork** and contribute
- **Share** with fellow hackers
- **Report** issues and suggest improvements
- **Sponsor** the project — see [Sponsors](#sponsors) section above

---

## License

This project is licensed under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2025 0xff

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

**Built with passion by [0xff](https://github.com/0xff0ay)**

Powered by [1Cloud Next Generation](https://1cloudng.com/)

Happy Hacking!

</div>