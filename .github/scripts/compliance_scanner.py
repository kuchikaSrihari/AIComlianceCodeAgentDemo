#!/usr/bin/env python3
"""
GitHub Actions Compliance Scanner
Scans changed files and enforces security policies
"""

import os
import re
import json
import sys
from pathlib import Path

# Policy definitions (embedded for standalone execution)
POLICIES = {
    # CRITICAL - Block PR
    "hardcoded_secret": {
        "severity": "critical",
        "patterns": [
            r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
            r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?i)(secret|token)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?i)AWS_SECRET_ACCESS_KEY\s*=\s*["\'][^"\']+["\']',
            r'(?i)(private_key|privatekey)\s*=\s*["\'][^"\']+["\']',
            r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        ],
        "scf_control": "CRY-03",
        "soc2_control": "CC6.1",
        "title": "Hardcoded Secret/Credential",
        "description": "Secrets must never be hardcoded in source code",
        "remediation": "Use environment variables or secrets manager (AWS Secrets Manager, HashiCorp Vault, GitHub Secrets)"
    },
    "sql_injection": {
        "severity": "critical",
        "patterns": [
            r'execute\s*\(\s*["\'].*%s.*["\'].*%',
            r'execute\s*\(\s*f["\'].*\{',
            r'cursor\.execute\s*\([^,]+\+',
            r'\.query\s*\(\s*["\'].*\$\{',
        ],
        "scf_control": "TDA-02",
        "soc2_control": "CC8.1",
        "title": "SQL Injection Vulnerability",
        "description": "User input directly concatenated in SQL query",
        "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    },
    "command_injection": {
        "severity": "critical",
        "patterns": [
            r'os\.system\s*\(',
            r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
            r'(?<!#.*)eval\s*\(',
            r'(?<!#.*)exec\s*\(',
        ],
        "scf_control": "TDA-02",
        "soc2_control": "CC8.1",
        "title": "Command Injection Risk",
        "description": "Potential command injection via shell execution",
        "remediation": "Use subprocess with shell=False: subprocess.run(['cmd', 'arg1'], shell=False)"
    },
    "public_s3": {
        "severity": "critical",
        "patterns": [
            r'acl\s*=\s*["\']public-read["\']',
            r'acl\s*=\s*["\']public-read-write["\']',
            r'block_public_acls\s*=\s*false',
            r'block_public_policy\s*=\s*false',
        ],
        "scf_control": "DAT-01",
        "soc2_control": "CC6.1",
        "title": "Public S3 Bucket",
        "description": "S3 bucket allows public access",
        "remediation": "Set acl = 'private' and enable S3 Block Public Access"
    },
    "wildcard_iam": {
        "severity": "critical",
        "patterns": [
            r'Action\s*[=:]\s*["\']?\*["\']?',
            r'"Action"\s*:\s*"\*"',
            r'Resource\s*[=:]\s*["\']?\*["\']?',
        ],
        "scf_control": "IAC-01",
        "soc2_control": "CC6.2",
        "title": "Overly Permissive IAM Policy",
        "description": "IAM policy uses wildcard (*) permissions",
        "remediation": "Apply least privilege - specify exact actions: Action = ['s3:GetObject', 's3:PutObject']"
    },

    # HIGH - Block PR
    "open_security_group": {
        "severity": "high",
        "patterns": [
            r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']',
            r'CidrIp:\s*["\']?0\.0\.0\.0/0',
            r'from_port\s*=\s*0.*to_port\s*=\s*65535',
            r'ingress.*0\.0\.0\.0/0',
        ],
        "scf_control": "NET-01",
        "soc2_control": "CC6.6",
        "title": "Unrestricted Network Access",
        "description": "Security group allows traffic from anywhere (0.0.0.0/0)",
        "remediation": "Restrict to specific CIDR: cidr_blocks = ['10.0.0.0/8'] or use security group references"
    },
    "unencrypted_storage": {
        "severity": "high",
        "patterns": [
            r'encrypted\s*=\s*false',
            r'storage_encrypted\s*=\s*false',
            r'kms_key_id\s*=\s*""',
        ],
        "scf_control": "CRY-01",
        "soc2_control": "CC6.1",
        "title": "Unencrypted Storage",
        "description": "Storage resource does not have encryption enabled",
        "remediation": "Enable encryption: encrypted = true, kms_key_id = aws_kms_key.main.arn"
    },
    "weak_crypto": {
        "severity": "high",
        "patterns": [
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'MD5\s*\(',
            r'SHA1\s*\(',
            r'DES\.',
            r'Blowfish',
        ],
        "scf_control": "CRY-02",
        "soc2_control": "CC6.1",
        "title": "Weak Cryptographic Algorithm",
        "description": "Use of deprecated/weak cryptographic algorithm (MD5, SHA1, DES)",
        "remediation": "Use SHA-256+: hashlib.sha256(data).hexdigest() or bcrypt for passwords"
    },
    "insecure_deserialization": {
        "severity": "high",
        "patterns": [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*\)(?!.*Loader)',
            r'yaml\.unsafe_load',
            r'marshal\.loads?\s*\(',
        ],
        "scf_control": "TDA-03",
        "soc2_control": "CC8.1",
        "title": "Insecure Deserialization",
        "description": "Unsafe deserialization can lead to remote code execution",
        "remediation": "Use yaml.safe_load() or JSON for serialization"
    },

    # MEDIUM - Warn only
    "debug_enabled": {
        "severity": "medium",
        "patterns": [
            r'DEBUG\s*=\s*True',
            r'debug\s*[=:]\s*true',
            r'\.setLevel\s*\(\s*logging\.DEBUG\s*\)',
        ],
        "scf_control": "CFG-01",
        "soc2_control": "CC6.1",
        "title": "Debug Mode Enabled",
        "description": "Debug mode should be disabled in production",
        "remediation": "Use environment variable: DEBUG = os.getenv('DEBUG', 'False') == 'True'"
    },
    "missing_logging": {
        "severity": "medium",
        "patterns": [
            r'logging\s*[=:]\s*\{\s*\}',
            r'enable_logging\s*=\s*false',
            r'access_logs\s*\{\s*enabled\s*=\s*false',
        ],
        "scf_control": "LOG-01",
        "soc2_control": "CC7.2",
        "title": "Logging Disabled",
        "description": "Audit logging is not enabled",
        "remediation": "Enable logging for compliance: enable_logging = true"
    },
    "http_no_tls": {
        "severity": "medium",
        "patterns": [
            r'http://(?!localhost|127\.0\.0\.1)',
            r'protocol\s*=\s*["\']HTTP["\']',
            r'ssl\s*=\s*false',
            r'verify\s*=\s*False',
        ],
        "scf_control": "CRY-04",
        "soc2_control": "CC6.7",
        "title": "Unencrypted HTTP",
        "description": "Using HTTP instead of HTTPS",
        "remediation": "Use HTTPS with TLS 1.2+: https:// and verify=True"
    },

    # LOW - Info only
    "todo_fixme": {
        "severity": "low",
        "patterns": [
            r'#\s*TODO[:\s]',
            r'#\s*FIXME[:\s]',
            r'//\s*TODO[:\s]',
            r'//\s*FIXME[:\s]',
        ],
        "scf_control": "TDA-01",
        "soc2_control": "CC8.1",
        "title": "Unresolved TODO/FIXME",
        "description": "Code contains unresolved development notes",
        "remediation": "Review and resolve before production"
    },
}

def scan_file(filepath: str, content: str) -> list:
    """Scan a single file for policy violations"""
    findings = []
    lines = content.split('\n')

    for policy_id, policy in POLICIES.items():
        for pattern in policy["patterns"]:
            try:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for i, line in enumerate(lines, 1):
                    if regex.search(line):
                        # Skip if it's a comment explaining the issue
                        if line.strip().startswith('#') or line.strip().startswith('//'):
                            if 'noqa' in line.lower() or 'nosec' in line.lower():
                                continue

                        findings.append({
                            "id": f"{policy_id}_{filepath}_{i}",
                            "policy_id": policy_id,
                            "severity": policy["severity"],
                            "title": policy["title"],
                            "description": policy["description"],
                            "remediation": policy["remediation"],
                            "scf_control": policy["scf_control"],
                            "soc2_control": policy["soc2_control"],
                            "file": filepath,
                            "line": i,
                            "code_snippet": line.strip()[:100]
                        })
                        break  # One finding per policy per file
            except re.error:
                continue

    return findings

def evaluate_findings(findings: list) -> dict:
    """Evaluate all findings and determine PR decision"""
    critical = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]
    low = [f for f in findings if f["severity"] == "low"]

    should_block = len(critical) > 0 or len(high) > 0

    if critical:
        reason = f"🚫 PR BLOCKED: {len(critical)} CRITICAL security issue(s) must be fixed"
    elif high:
        reason = f"🚫 PR BLOCKED: {len(high)} HIGH severity issue(s) must be fixed"
    elif medium:
        reason = f"✅ PR ALLOWED with {len(medium)} suggestion(s)"
    else:
        reason = "✅ PR ALLOWED: No security issues detected"

    return {
        "decision": "BLOCK" if should_block else "ALLOW",
        "reason": reason,
        "summary": {
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "total": len(findings)
        },
        "blocking_issues": [
            {
                "severity": f["severity"].upper(),
                "title": f["title"],
                "file": f["file"],
                "line": f["line"],
                "scf_control": f["scf_control"],
                "soc2_control": f["soc2_control"],
                "description": f["description"],
                "remediation": f["remediation"],
                "code_snippet": f.get("code_snippet", "")
            }
            for f in critical + high
        ],
        "suggestions": [
            {
                "severity": "MEDIUM",
                "title": f["title"],
                "file": f["file"],
                "line": f["line"],
                "scf_control": f["scf_control"],
                "description": f["description"],
                "remediation": f["remediation"]
            }
            for f in medium
        ],
        "informational": [
            {
                "severity": "LOW",
                "title": f["title"],
                "file": f["file"],
                "line": f["line"]
            }
            for f in low
        ]
    }

def main():
    """Main entry point for GitHub Actions"""
    changed_files = os.environ.get("CHANGED_FILES", "").split()

    if not changed_files:
        print("No relevant files changed")
        # Set outputs for GitHub Actions
        with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a") as f:
            f.write("decision=ALLOW\n")
            f.write("has_suggestions=false\n")
        return

    all_findings = []

    for filepath in changed_files:
        if not os.path.exists(filepath):
            continue

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            findings = scan_file(filepath, content)
            all_findings.extend(findings)
        except Exception as e:
            print(f"Error scanning {filepath}: {e}")

    # Evaluate and generate report
    report = evaluate_findings(all_findings)

    # Save report for GitHub Actions
    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    print("\n" + "="*60)
    print("AI COMPLIANCE-AS-CODE SCAN RESULTS")
    print("="*60)
    print(f"\nDecision: {report['decision']}")
    print(f"Reason: {report['reason']}")
    print(f"\nSummary:")
    print(f"  🔴 Critical: {report['summary']['critical']}")
    print(f"  🟠 High:     {report['summary']['high']}")
    print(f"  🟡 Medium:   {report['summary']['medium']}")
    print(f"  🔵 Low:      {report['summary']['low']}")

    if report['blocking_issues']:
        print("\n🚨 BLOCKING ISSUES:")
        for issue in report['blocking_issues']:
            print(f"\n  [{issue['severity']}] {issue['title']}")
            print(f"  File: {issue['file']}:{issue['line']}")
            print(f"  SCF: {issue['scf_control']} | SOC2: {issue['soc2_control']}")
            print(f"  Fix: {issue['remediation']}")

    if report['suggestions']:
        print("\n💡 SUGGESTIONS:")
        for sug in report['suggestions']:
            print(f"  - {sug['title']} ({sug['file']}:{sug['line']})")
            print(f"    {sug['remediation']}")

    print("\n" + "="*60)

    # Set GitHub Actions outputs
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"decision={report['decision']}\n")
            f.write(f"has_suggestions={'true' if report['suggestions'] else 'false'}\n")

    # Exit with error if blocked (fails the GitHub Action)
    if report['decision'] == 'BLOCK':
        sys.exit(1)

if __name__ == "__main__":
    main()
