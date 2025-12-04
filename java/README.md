# Vulnerable Java Demo Application

⚠️ **WARNING: This code contains intentional security vulnerabilities for demonstration purposes. DO NOT use in production!**

## Purpose

This Java project demonstrates the AI Compliance-as-Code Bot by containing various security issues that will be detected and blocked during PR review.

## Project Structure

```
java/
├── pom.xml
├── README.md
└── src/main/java/com/example/
    ├── auth/
    │   └── AuthService.java      # Authentication with SQL injection, weak crypto
    ├── api/
    │   └── ApiController.java    # API with code injection, hardcoded secrets
    └── config/
        └── AppConfig.java        # Configuration with hardcoded credentials
```

## Security Issues by Severity

### 🔴 CRITICAL (PR will be BLOCKED)

| Issue | File | SCF Control | SOC2 |
|-------|------|-------------|------|
| Hardcoded DB password | AuthService.java:18 | CRY-03 | CC6.1 |
| Hardcoded API key | AuthService.java:19 | CRY-03 | CC6.1 |
| SQL Injection | AuthService.java:38-40 | TDA-02 | CC8.1 |
| Command Injection | AuthService.java:52 | TDA-02 | CC8.1 |
| Hardcoded AWS keys | AppConfig.java:26-27 | CRY-03 | CC6.1 |
| Code Injection (eval) | ApiController.java:44 | TDA-02 | CC8.1 |

### 🟠 HIGH (PR will be BLOCKED)

| Issue | File | SCF Control | SOC2 |
|-------|------|-------------|------|
| MD5 hash usage | AuthService.java:65 | CRY-02 | CC6.1 |
| SHA1 hash usage | AuthService.java:79 | CRY-02 | CC6.1 |
| Insecure deserialization | AuthService.java:90 | TDA-03 | CC8.1 |

### 🟡 MEDIUM (Suggestions only)

| Issue | File | SCF Control | SOC2 |
|-------|------|-------------|------|
| DEBUG = true | AuthService.java:102 | CFG-01 | CC6.1 |
| HTTP without TLS | AuthService.java:106 | CRY-04 | CC6.7 |
| HTTP endpoints | AppConfig.java:38-40 | CRY-04 | CC6.7 |

### 🔵 LOW (Informational)

| Issue | File |
|-------|------|
| TODO comments | Multiple files |
| FIXME comments | Multiple files |

## Expected Scan Result

When you create a PR with this code:

```
🚫 PR BLOCKED

Reason: 8 CRITICAL and 3 HIGH security issues found

Blocking Issues:
- CRITICAL: Hardcoded credentials in AuthService.java
- CRITICAL: SQL Injection in AuthService.java:38
- CRITICAL: Command Injection in AuthService.java:52
- HIGH: Weak cryptography (MD5) in AuthService.java:65
...
```

## How to Test

1. Add this `java/` folder to your repository
2. Create a new branch: `git checkout -b feature/add-java-auth`
3. Commit the files: `git add . && git commit -m "Add Java authentication service"`
4. Push and create PR: `git push origin feature/add-java-auth`
5. Watch the compliance bot block the PR!
