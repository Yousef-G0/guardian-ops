#  Guardian-Ops

**Autonomous Security Pipeline with GitHub Actions Integration**

A production-ready DevSecOps platform/tool that automatically scans code for vulnerabilities, enforces security policies, monitors runtime behavior, and performs automatic rollbacks when threats are detected.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Powered-2088FF?logo=github-actions)](https://github.com/features/actions)

##  What Makes This Different

Unlike traditional CI/CD security tools, Guardian-Ops:

- **Uses GitHub Actions as a control plane** for incident response
- **Actively monitors** deployed applications in real-time
- **Automatically rolls back** compromised deployments
- **Enforces policies** before code reaches production
- **Self-healing infrastructure** - detects and responds to threats autonomously

This isn't just a scanner - it's a **self-defending pipeline**.

---

##  Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     GitHub Actions (Brain)                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐  │
│  │  Scan &  │→ │  Build   │→ │  Deploy (if approved)    │  │
│  │  Policy  │  │          │  │                          │  │
│  └──────────┘  └──────────┘  └──────────────────────────┘  │
└────────┬──────────────────────────────────────────┬─────────┘
         │                                           │
         ↓                                           ↓
┌─────────────────────┐                    ┌──────────────────┐
│  Security API (Go)  │                    │  Runtime Agent   │
│  ┌───────────────┐  │                    │  ┌─────────────┐ │
│  │Secret Scanner │  │                    │  │  Anomaly    │ │
│  │CVE Detector   │  │                    │  │  Detection  │ │
│  │Risk Calculator│  │                    │  │             │ │
│  │Policy Engine  │  │                    │  │  - Reverse  │ │
│  └───────────────┘  │                    │  │    Shell    │ │
└─────────────────────┘                    │  │  - Port     │ │
                                           │  │    Scan     │ │
                                           │  │  - Process  │ │
                                           │  │    Monitor  │ │
                                           │  └─────────────┘ │
                                           └────────┬─────────┘
                                                    │
                                           Triggers Rollback
                                                    │
                                                    ↓
                                           GitHub Actions API
```

---

##  What’s included

- Code scanning for secrets, CVEs, and unsafe patterns
- Policy enforcement before deploy
- Runtime monitoring for anomalous activity
- **Smart features**: Context-aware detection, confidence scoring, anomaly detection, caching
- **Advanced patterns**: Negative lookbehinds to avoid false positives
- Automated rollback when threats appear

##  Quick Start

### Requirements

- Go 1.21+
- Docker (optional)
- GitHub repository

### Setup

```bash
git clone https://github.com/Yousef-G0/guardian-ops.git
cd guardian-ops
chmod +x setup.sh
./setup.sh
```

### Run locally

```bash
./bin/security-api
sudo ./bin/runtime-agent
```

Or:

```bash
docker-compose up -d
```

##  Configuration

Update `.env`:

```bash
GITHUB_REPO=owner/repo
GITHUB_TOKEN=ghp_your_token_here
MONITORED_PROCESS=your-app-name
CHECK_INTERVAL=30
SECURITY_API_URL=http://localhost:8080
```

##  GitHub Actions

- `security-deploy.yml`: scan, enforce policy, build, deploy
- `rollback.yml`: rollback on runtime threat
- `security-scan-self-hosted.yml`: self-hosted GitHub Actions runners instead of GitHub's cloud-hosted runners.

##  Project layout

- `cmd/api/` — security API and scan engine
- `cmd/agent/` — runtime monitoring agent
- `policies/` — security rules
- `docker-compose.yml` — local run setup

##  License

MIT License — see [LICENSE](LICENSE)

