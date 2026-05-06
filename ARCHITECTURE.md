#  Architecture Deep Dive

## System Overview

Guardian-Ops is a distributed security system with three main components working together to provide continuous security assurance:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         GITHUB ACTIONS (Control Plane)              │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────────────┐  │
│  │  On Push     │───▶│ Security     │───▶│  Deploy (Approved) │  │
│  │  On PR       │    │ Scan & Gate  │    │  Monitor (Active)  │  │
│  │  On Release  │    │              │    │                    │  │
│  └──────────────┘    └──────────────┘    └────────────────────┘  │
│                             │                        │             │
│                             │ Blocks if              │ Triggers    │
│                             │ Risk > 70              │ on anomaly  │
│                             ▼                        ▼             │
│                      ┌──────────────┐    ┌────────────────────┐  │
│                      │  Build       │    │  Rollback          │  │
│                      │  (Skipped)   │    │  (Auto-Execute)    │  │
│                      └──────────────┘    └────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
         │                                                    ▲
         │                                                    │
         ▼                                                    │
┌─────────────────────────┐                    ┌──────────────────────┐
│   Security API (Go)     │                    │  Runtime Agent (Go)  │
│   Port: 8080            │                    │  Runs on: Target     │
│                         │                    │                      │
│  Components:            │                    │  Monitors:           │
│  ├─ Secret Scanner      │                    │  ├─ Processes        │
│  ├─ CVE Detector        │                    │  ├─ Network          │
│  ├─ Code Analyzer       │                    │  ├─ Files            │
│  ├─ Risk Calculator     │                    │  └─ Anomalies        │
│  ├─ Policy Engine       │                    │                      │
│  └─ HTTP API            │                    │  Actions:            │
│                         │                    │  ├─ Log Incident     │
│  Endpoints:             │                    │  ├─ Trigger Rollback │
│  • POST /scan           │                    │  └─ Alert            │
│  • POST /risk-score     │                    │                      │
│  • POST /validate-policy│                    │  Frequency: 30s      │
│  • GET  /health         │                    │                      │
└─────────────────────────┘                    └──────────────────────┘
```

## Component Details

### 1. GitHub Actions (Orchestration Layer)

**Purpose**: Central control plane for security gates and incident response

**Workflows**:

#### `security-deploy.yml`
- **Triggers**: push, pull_request, workflow_dispatch
- **Stages**:
  1. **Security Scan**: Clones repo, starts API, runs full scan
  2. **Policy Gate**: Blocks deployment if violations found
  3. **Build**: Compiles application (only if scan passes)
  4. **Deploy**: Deploys to target (only on main branch)
  5. **Monitor**: Activates runtime agent
  6. **Notify**: Reports results

- **Exit Codes**:
  - `0`: Security passed, deployment allowed
  - `1`: Security failed, deployment blocked

#### `rollback.yml`
- **Triggers**: workflow_dispatch (triggered by agent or manual)
- **Stages**:
  1. **Identify**: Find last stable commit
  2. **Verify**: Check rollback target is safe
  3. **Build**: Rebuild previous version
  4. **Deploy**: Replace current version
  5. **Log**: Create incident report
  6. **Alert**: Notify stakeholders

#### `security-scan-self-hosted.yml`
- **Triggers**: push on `main`/`develop`, pull_request on `main`
- **Runs on**: `self-hosted` runner targets
- **Purpose**: Execute the security scan pipeline on customer-managed infrastructure where control, compliance, or specialized tooling is required
- **Stages**:
  1. **Checkout**: Pull repository source
  2. **Setup Go**: Install Go runtime and cache modules
  3. **Build Security API**: Compile the scanner service
  4. **Start Security API**: Launch the API locally in the workflow
  5. **Run Security Scan**: Call `/scan` against the repository content
  6. **Generate Report**: Emit scan findings to JSON and markdown
  7. **Upload Artifacts**: Preserve report output for review
  8. **Comment on PR**: Attach results to pull requests
  9. **Fail on Policy**: Stop the workflow if security checks fail
  
- **Key Features**:
  - Artifacts stored for later inspection
  - PR comments with scan summary and findings
  - Job summary-friendly output for GitHub Actions UI
  - Self-hosted execution for private or compliant environments

---

### 2. Security API (Golang - Port 8080)

**Purpose**: Comprehensive security analysis engine

#### Architecture

```
┌─────────────────────────────────────────────┐
│         HTTP Server (Gin Framework)         │
├─────────────────────────────────────────────┤
│  Router                                     │
│  ├─ GET  /health                            │
│  ├─ POST /scan                              │
│  ├─ POST /risk-score                        │
│  └─ POST /validate-policy                   │
├─────────────────────────────────────────────┤
│  Security Scanners                          │
│  ├─ Secret Scanner                          │
│  │  └─ Regex patterns for secrets           │
│  ├─ CVE Scanner                             │
│  │  └─ Dependency file analysis             │
│  └─ Code Pattern Scanner                    │
│     └─ Dangerous code detection             │
├─────────────────────────────────────────────┤
│  Analysis Engine                            │
│  ├─ Risk Scoring Algorithm                  │
│  │  └─ Weighted severity calculation        │
│  └─ Policy Engine                           │
│     └─ Rule-based decision making           │
├─────────────────────────────────────────────┤
│  Data Models                                │
│  ├─ ScanRequest                             │
│  ├─ ScanResult                              │
│  ├─ SecretFinding                           │
│  ├─ CVEFinding                              │
│  ├─ CodeIssue                               │
│  └─ PolicyResult                            │
└─────────────────────────────────────────────┘
```

#### Scanning Process

1. **File Discovery**
   - Walks directory tree
   - Filters excluded paths
   - Skips binary files

2. **Secret Detection**
   - Line-by-line regex matching
   - Deduplication via hashing
   - Masking sensitive data
   - Severity classification

3. **CVE Analysis**
   - Identifies dependency files
   - Parses package declarations
   - Matches against CVE database
   - Calculates CVSS scores

4. **Code Analysis**
   - Pattern matching for dangerous code
   - Context-aware detection
   - False positive reduction

5. **Risk Calculation**
   ```
   Risk Score = 
     (CRITICAL secrets × 30) +
     (HIGH secrets × 20) +
     (CVEs × CVSS/10 × 15) +
     (CRITICAL code × 20) +
     (HIGH code × 15)
   
   Capped at 100
   ```

6. **Policy Enforcement**
   - Risk threshold check
   - Critical finding blocker
   - Custom rule evaluation

---

### 3. Runtime Agent (Golang)

**Purpose**: Continuous security monitoring of deployed applications

#### Architecture

```
┌─────────────────────────────────────────────┐
│         Runtime Monitoring Loop              │
│           (Every 30 seconds)                 │
├─────────────────────────────────────────────┤
│  Baseline Establishment                      │
│  ├─ Known ports                              │
│  ├─ Running processes                        │
│  └─ File states                              │
├─────────────────────────────────────────────┤
│  Anomaly Detection                           │
│  ├─ Reverse Shell Detector                   │
│  │  └─ netstat/ss pattern matching           │
│  ├─ Network Monitor                          │
│  │  └─ New port detection                    │
│  ├─ Process Monitor                          │
│  │  └─ Malware signature matching            │
│  └─ File Monitor                             │
│     └─ Critical file change detection        │
├─────────────────────────────────────────────┤
│  Incident Response                           │
│  ├─ Threshold Calculator                     │
│  ├─ Rollback Trigger                         │
│  │  └─ GitHub API workflow_dispatch          │
│  └─ Logging & Alerting                       │
│     ├─ Local logs                            │
│     ├─ GitHub Issues                         │
│     └─ Webhooks                              │
└─────────────────────────────────────────────┘
```

#### Detection Mechanisms

**1. Reverse Shell Detection**
- Monitors network connections
- Looks for shell processes with network sockets
- Patterns: `/bin/bash`, `nc -e`, `python.*socket`

**2. Port Scanning Detection**
- Compares current ports vs baseline
- Flags suspicious ports (4444, 31337, etc.)
- Triggers on rapid port opening

**3. Process Anomalies**
- Detects cryptocurrency miners
- Identifies backdoor processes
- Checks for unauthorized services

**4. File Tampering**
- Monitors `/etc/passwd`, `/etc/shadow`
- Watches SSH authorized_keys
- Tracks sudoers modifications

#### Rollback Mechanism

```
Anomaly Detected
      ↓
Critical? (CVSS ≥ 9 or CRITICAL severity)
      ↓ Yes
Build Rollback Request
      ↓
POST to GitHub API:
  /repos/{owner}/{repo}/actions/workflows/rollback.yml/dispatches
      ↓
Workflow Triggered
      ↓
Previous Version Deployed
      ↓
Issue Created for Investigation
```

---

## Data Flow

### Deployment Flow (Happy Path)

```
1. Developer pushes code
   ↓
2. GitHub Actions triggered
   ↓
3. Security API scans code
   ├─ Secrets: 0 found
   ├─ CVEs: 0 found
   ├─ Code issues: 2 (low severity)
   └─ Risk Score: 15/100 (LOW)
   ↓
4. Policy check: PASSED
   ↓
5. Build application
   ↓
6. Deploy to production
   ↓
7. Runtime agent starts monitoring
   ↓
8. No anomalies detected
   ↓
9.  Deployment successful
```

### Security Block Flow (Risk Detected)

```
1. Developer pushes code with AWS key
   ↓
2. GitHub Actions triggered
   ↓
3. Security API scans code
   ├─ Secrets: 1 CRITICAL (AWS_KEY)
   ├─ CVEs: 0
   ├─ Code issues: 0
   └─ Risk Score: 30/100 (MEDIUM)
   ↓
4. Policy check: BLOCKED (critical secret)
   ↓
5. Build: SKIPPED
   ↓
6. Deploy: BLOCKED
   ↓
7. PR comment added with findings
   ↓
8.  Deployment blocked
```

### Runtime Incident Flow (Attack Detected)

```
1. Application running normally
   ↓
2. Attacker exploits vulnerability
   ├─ Opens reverse shell on port 4444
   ↓
3. Runtime agent detects anomaly
   ├─ Type: REVERSE_SHELL
   ├─ Severity: CRITICAL
   ├─ Action: ROLLBACK_REQUIRED
   ↓
4. Agent calls GitHub API
   ├─ Trigger rollback.yml
   ├─ Payload: incident details
   ↓
5. GitHub Actions workflow starts
   ├─ Find last stable commit
   ├─ Build previous version
   ├─ Deploy rollback
   ↓
6. Create incident issue
   ↓
7. Send alerts
   ↓
8.  Threat neutralized
```

---

## Security Considerations

### API Security
- No authentication required (runs in trusted CI)
- Localhost binding only
- Input validation on all endpoints
- Rate limiting (via Gin middleware)

### Agent Security
- Requires root for system monitoring
- Read-only file access
- Secure token handling
- Encrypted webhook communications

### Data Privacy
- Secrets are masked in output
- Deduplication prevents leakage
- No external API calls with code
- Logs rotated and secured

---

## Performance Characteristics

### Security API
- **Scan Time**: ~5-30 seconds (depends on repo size)
- **Memory**: ~50-100MB
- **CPU**: Low (regex matching)
- **Throughput**: ~10 scans/minute

### Runtime Agent
- **Check Interval**: 30 seconds (configurable)
- **Memory**: ~20-30MB
- **CPU**: Very low (periodic checks)
- **Disk**: Minimal (logs only)

---


## Deployment Topologies

### Topology 1: Single Server
```
[GitHub Actions] ──▶ [Server with API + Agent]
```
Best for: Small projects, testing

### Topology 2: Distributed
```
[GitHub Actions] ──▶ [API Server]
         │
         └──────────▶ [Target Server with Agent]
```
Best for: Production environments

### Topology 3: Multi-Environment
```
[GitHub Actions] ──▶ [API Server]
         │
         ├──────────▶ [Dev Server + Agent]
         ├──────────▶ [Staging Server + Agent]
         └──────────▶ [Prod Server + Agent]
```
Best for: Enterprise deployments




