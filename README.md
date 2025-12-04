# Test Project for AI Compliance-as-Code Bot

This project contains **intentional security vulnerabilities** to demonstrate the AI Compliance-as-Code Bot.

## ⚠️ WARNING

**DO NOT use this code in production!** This is for demonstration purposes only.

## Files with Issues

| File | Critical | High | Medium | Low |
|------|----------|------|--------|-----|
| `src/auth.py` | 4 | 2 | 3 | 2 |
| `src/api.js` | 3 | 2 | 3 | 3 |
| `infra/main.tf` | 3 | 3 | 2 | 0 |

## Expected Scan Results

When you create a PR with these files, the compliance bot will:

1. **🚫 BLOCK the PR** due to Critical/High issues
2. **Comment** with detailed findings and remediation steps
3. **Map** each issue to SCF and SOC2 controls

## Issues Demonstrated

### Critical (PR Blocked)
- Hardcoded secrets/credentials
- SQL Injection vulnerabilities
- Command Injection (eval, os.system)
- Public S3 buckets
- Wildcard IAM permissions

### High (PR Blocked)
- Open security groups (0.0.0.0/0)
- Weak cryptography (MD5, SHA1)
- Insecure deserialization (pickle)
- Unencrypted storage

### Medium (Suggestions)
- Debug mode enabled
- HTTP without TLS
- Missing logging

### Low (Info)
- TODO/FIXME comments

## How to Test

1. Create a new branch
2. Add these files
3. Create a PR to main
4. Watch the compliance bot block the PR!
