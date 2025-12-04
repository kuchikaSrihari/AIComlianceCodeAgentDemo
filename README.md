# AI Compliance-as-Code Bot v2.0

> An AI assistant that codifies security and compliance rules into automated checks during development (code reviews, CI/CD, IaC scans).

## 🎯 Key Impact

| Capability | Description |
|------------|-------------|
| **Shift-Left Compliance** | Embeds policy-as-code guardrails into SDLC, catching violations early |
| **Continuous Enforcement** | Real-time checks in CI/CD to enforce standards (encryption, least privilege) |
| **Audit Evidence on Demand** | Auto-collects proof against compliance frameworks |
| **Scale Without Bottlenecks** | Instant AI feedback on every PR - no security team delays |

## 🤖 Why AI is Essential

Traditional rule-based scanners only match patterns. Our AI provides:

| Feature | Rule-Based | AI-Powered |
|---------|-----------|------------|
| Find known patterns | ✅ | ✅ |
| Understand context | ❌ | ✅ |
| Reduce false positives | ❌ | ✅ (70%+ reduction) |
| Provide code fixes | ❌ | ✅ |
| Assess business risk | ❌ | ✅ |
| Detect novel vulnerabilities | ❌ | ✅ |

**The AI doesn't just FIND vulnerabilities - it UNDERSTANDS them, PRIORITIZES by business risk, and FIXES them with context-aware code suggestions.**

## 📋 SCF Controls Implemented

| SCF Control | Description | Implementation |
|-------------|-------------|----------------|
| **SCF-VULN-14** | Cloud & Container VM | SCA scanning for dependencies |
| **SCF-VULN-11** | Vulnerability Identification | Automated scanning in CI/CD |
| **SCF-VULN-04** | Penetration Testing | OWASP Top 10 coverage |
| **SCF-VULN-15** | Risk-Based Patch Mgmt | CVSS + exploitability scoring |
| **SCF-GRC-01** | Technology Risk Classification | Business-contextual risk rating |
| **SCF-GRC-14** | Risk Controls Remediation | SLA-based remediation timelines |
| **SCF-GRC-03** | Control Assessment | Audit evidence & tracking |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AI COMPLIANCE-AS-CODE BOT                        │
├─────────────────────────────────────────────────────────────────────┤
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐        │
│  │  SOURCE   │  │    IaC    │  │  CONFIG   │  │    SCA    │        │
│  │   CODE    │  │  SCANNER  │  │  SCANNER  │  │  SCANNER  │        │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘        │
│        └──────────────┴──────────────┴──────────────┘              │
│                              │                                      │
│               ┌──────────────▼──────────────┐                      │
│               │     AI ANALYSIS ENGINE      │                      │
│               │    (Google Gemini 2.0)      │                      │
│               │  • Contextual Analysis      │                      │
│               │  • CVSS Scoring             │                      │
│               │  • Remediation Generation   │                      │
│               └──────────────┬──────────────┘                      │
│                              │                                      │
│               ┌──────────────▼──────────────┐                      │
│               │    COMPLIANCE MAPPER        │                      │
│               │  • SCF, SOC2, HIPAA, PCI    │                      │
│               │  • OWASP Top 10             │                      │
│               │  • Remediation SLAs         │                      │
│               └─────────────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
.github/
├── scripts/
│   ├── compliance_scanner.py    # Main entry point
│   ├── ai_engine.py             # AI model management
│   ├── report_generator.py      # Report & audit evidence
│   └── scanners/
│       ├── __init__.py
│       ├── base.py              # Base scanner & data structures
│       ├── source_code.py       # Java, Python, JS/TS
│       ├── iac_scanner.py       # Terraform, CloudFormation, K8s
│       ├── sca_scanner.py       # Dependency scanning
│       └── config_scanner.py    # Configuration files
└── workflows/
    └── compliance-scan.yml      # GitHub Action
```

## 🚀 Quick Setup (5 min)

### 1. Get Free API Key
Go to https://aistudio.google.com/app/apikey → Create API Key

### 2. Add Secret to Repo
Settings → Secrets → Actions → New secret:
- Name: `GEMINI_API_KEY`
- Value: Your API key

### 3. Copy Files to Your Repo
Copy the `.github/` folder to your repository.

### 4. Create a PR
The bot will automatically scan and comment!

## 🔍 What It Detects

### Source Code (Java, Python, JS/TS)
| Category | Examples | OWASP | CWE |
|----------|----------|-------|-----|
| Secrets | Hardcoded passwords, API keys | A02 | CWE-798 |
| Injection | SQL, Command, XSS | A03 | CWE-89, CWE-78 |
| Crypto | MD5, SHA1, DES | A02 | CWE-327 |
| Deserialization | ObjectInputStream, pickle | A08 | CWE-502 |
| Auth | Missing checks, weak passwords | A07 | CWE-306 |

### Infrastructure-as-Code (Terraform, K8s, CloudFormation)
| Category | Examples | SCF Control |
|----------|----------|-------------|
| Network | Open security groups, 0.0.0.0/0 | NET-01 |
| Access | Wildcard IAM, admin permissions | IAC-01 |
| Encryption | Unencrypted S3, RDS, EBS | CRY-01 |
| Logging | Missing CloudTrail, VPC logs | LOG-01 |

### Dependencies (SCA)
| Package | CVE | Severity |
|---------|-----|----------|
| log4j < 2.17 | CVE-2021-44228 | Critical |
| spring-core < 5.3.18 | CVE-2022-22965 | Critical |
| jackson-databind | CVE-2017-7525 | High |

## 📊 PR Comment Example

```
## 🚫 Compliance Check Failed

### 📊 Risk Assessment (SCF-GRC-01)
| Severity | Count | SLA |
|----------|-------|-----|
| 🔴 Critical | 5 | Immediate |
| 🟠 High | 3 | 7 days |

### 🎯 OWASP Top 10 Coverage
Categories Detected: A02, A03, A08

### 🏛️ SCF Controls Violated
| Control | Description |
|---------|-------------|
| CRY-03 | Secret Management |
| TDA-02 | Secure Coding |

### ⏰ Remediation Required (SCF-GRC-14)
- 5 issues require immediate remediation
- 3 issues must be fixed within 7 days
```

## 🏛️ Compliance Frameworks

- **SCF** - Secure Controls Framework
- **SOC2** - Service Organization Control 2
- **HIPAA** - Health Insurance Portability and Accountability Act
- **PCI-DSS** - Payment Card Industry Data Security Standard
- **NIST 800-53** - Security and Privacy Controls
- **ISO 27001** - Information Security Management

## 📜 License

MIT
