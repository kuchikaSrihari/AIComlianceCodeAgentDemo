# Test Samples for AI Compliance Bot

This directory contains intentionally vulnerable code samples to demonstrate the AI Compliance Bot's capabilities.

## 🎯 Purpose

These samples showcase **why AI is essential** for security scanning:

| AI Capability | Test File | Scenario |
|---------------|-----------|----------|
| **Contextual Analysis** | `UserAuthService.java` | Distinguishes hardcoded secrets from env vars |
| **Risk Synthesis** | `PaymentProcessor.java` | CVSS scoring + exploitability assessment |
| **Intelligent Remediation** | All files | Code-specific fixes, not generic advice |
| **Novel Detection** | `PaymentProcessor.java` | Log4Shell (CVE-2021-44228) pattern |
| **Cross-file Analysis** | `insecure_aws.tf` | Missing CloudTrail = compliance gap |

## 📁 Test Files

### Java (`java/`)

| File | Vulnerabilities | SCF Controls |
|------|-----------------|--------------|
| `UserAuthService.java` | SQL Injection, Weak Crypto, Hardcoded Creds, Missing Auth | TDA-02, CRY-01, CRY-03, IAC-01 |
| `FileUploadController.java` | Path Traversal, XXE, Command Injection, SSRF | TDA-02, NET-01 |
| `PaymentProcessor.java` | Log4Shell, Deserialization, PCI-DSS violations | VULN-14, CRY-03, LOG-01 |

### Python (`python/`)

| File | Vulnerabilities | SCF Controls |
|------|-----------------|--------------|
| `data_service.py` | Pickle RCE, eval(), YAML load, SQL Injection | TDA-02, CRY-03 |

### JavaScript (`javascript/`)

| File | Vulnerabilities | SCF Controls |
|------|-----------------|--------------|
| `api-controller.js` | NoSQL Injection, Prototype Pollution, XSS, IDOR | TDA-02, IAC-01 |

### Terraform (`terraform/`)

| File | Vulnerabilities | SCF Controls |
|------|-----------------|--------------|
| `insecure_aws.tf` | Public S3, Open SG, Wildcard IAM, Unencrypted RDS | NET-01, IAC-01, CRY-01, LOG-01 |

### Kubernetes (`kubernetes/`)

| File | Vulnerabilities | SCF Controls |
|------|-----------------|--------------|
| `insecure-deployment.yaml` | Privileged containers, Root user, Host network, Secrets in env | IAC-01, CRY-03, NET-01 |

### Configuration (`config/`)

| File | Vulnerabilities | SCF Controls |
|------|-----------------|--------------|
| `application-prod.yaml` | Debug mode, Hardcoded secrets, Missing headers, Exposed actuators | CFG-01, CRY-03, LOG-01 |

### Dependencies (`dependencies/`)

| File | Vulnerabilities | SCF Controls |
|------|-----------------|--------------|
| `package.json` | Vulnerable npm packages (lodash, axios, etc.) | VULN-14, VULN-06 |

## 🧪 How to Test

### Option 1: Create a PR
1. Copy a test file to your repo
2. Create a PR
3. Watch the AI bot analyze and comment

### Option 2: Run Locally
```bash
# Set your API key
export GEMINI_API_KEY="your-key-here"

# Run scanner on a specific file
python .github/scripts/compliance_scanner.py test-samples/java/UserAuthService.java
```

## 📊 Expected AI Output

For each file, the AI should:

1. **Identify all vulnerabilities** with accurate line numbers
2. **Assign CVSS scores** based on exploitability
3. **Map to OWASP Top 10** categories
4. **Map to SCF controls** (CRY-03, TDA-02, etc.)
5. **Provide specific remediation** with code examples
6. **Assess business impact** (data breach, RCE, compliance violation)
7. **Assign remediation SLAs** (Immediate, 7 days, 30 days)

## 🔍 AI Differentiation Examples

### Example 1: Context-Aware Secret Detection

**Rule-based scanner:** Flags ALL strings containing "password"
```java
String passwordPolicy = "Password must be 8+ chars";  // FALSE POSITIVE
```

**AI scanner:** Understands context
```java
String DB_PASSWORD = "actual_password_123";  // TRUE POSITIVE - hardcoded
String password = System.getenv("DB_PASSWORD");  // OK - from environment
```

### Example 2: Risk Synthesis

**Rule-based:** "SQL Injection found" → Severity: High

**AI scanner:**
```
SQL Injection in public API endpoint
- CVSS: 9.8 (Critical)
- Exploitability: High (public endpoint, no auth required)
- Business Impact: Full database access, PII exposure
- Compliance: PCI-DSS violation, HIPAA violation
- SLA: Immediate remediation required
```

### Example 3: Intelligent Remediation

**Rule-based:** "Use prepared statements"

**AI scanner:**
```java
// Current vulnerable code:
String query = "SELECT * FROM users WHERE id = '" + userId + "'";

// AI-generated fix:
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);
ResultSet rs = ps.executeQuery();
```

## ⚠️ Warning

**DO NOT deploy these files to production!** They contain intentional security vulnerabilities for testing purposes only.
