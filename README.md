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
- **Rust-Powered Advanced Analysis**: AST-based security scanning for multiple languages
- Automated rollback when threats appear

##   Advanced Security Analysis (Rust-Powered)

Guardian-Ops now includes cutting-edge security analysis powered by Rust and Tree-Sitter:

### Features
- **AST-Based Analysis**: Parses code structure to detect complex vulnerabilities
- **Multi-Language Support**: Rust, Go, Python, JavaScript/TypeScript, Java
- **Data Flow Analysis**: Tracks user input through dangerous functions
- **Cryptographic Analysis**: Detects weak algorithms and insecure practices
- **Performance**: Parallel processing with Rayon, SIMD-accelerated regex
- **Memory Safety**: Rust's guarantees prevent memory-related vulnerabilities

### Advanced Detection Capabilities
- **Unsafe blocks** in Rust code
- **Dynamic code execution** (eval, exec) with context analysis
- **SQL injection** via AST parsing (not just regex)
- **XSS vulnerabilities** through DOM manipulation analysis
- **Command injection** with data flow tracking
- **Cryptographic weaknesses** (MD5, SHA1, weak ciphers)

### API Endpoints
```bash
# Traditional scan (Go-based, always available)
POST /scan

# Advanced AST-based scan (Rust-powered, requires advanced build)
POST /advanced-scan

# Health check
GET /health

# Risk score calculation
POST /risk-score

# Policy validation
POST /validate-policy
```

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

### Build with Advanced Features

For the full Rust-powered analysis experience:

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Run the setup script (includes advanced build)
./setup.sh
```

### Manual Build Steps

If you prefer manual building:

```bash
# Basic version
cd cmd/api
go build -o ../../bin/security-api main.go

# Advanced version (requires Rust)
cd ../../rust-security-analyzer
cargo build --release
cd ../cmd/api
export CGO_LDFLAGS="-L$(pwd)/../../rust-security-analyzer/target/release -lsecurity_analyzer -ldl"
go build -o ../../bin/security-api-advanced main.go
```

### Run locally

```bash
# Basic version
./bin/security-api

# Advanced version with Rust integration
./bin/security-api-advanced

# Runtime agent (requires sudo for system monitoring)
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

##  Contributions

Contribute at - [CONTRIBUTION](CONTRIBUTING.md)

##  License

MIT License — see [LICENSE](LICENSE)

