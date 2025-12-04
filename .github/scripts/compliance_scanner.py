#!/usr/bin/env python3
"""
AI-Powered Compliance Scanner for GitHub Actions

This scanner uses a HYBRID approach:
1. RULE-BASED DETECTION: Fast regex patterns for known vulnerability signatures
2. AI/LLM ANALYSIS: OpenAI GPT for contextual understanding, false positive reduction,
   and intelligent remediation suggestions

AI Features:
- Contextual code analysis beyond pattern matching
- Intelligent severity assessment based on code context
- AI-generated fix suggestions with actual code
- False positive filtering using semantic understanding
- Risk scoring with business impact analysis
"""

import os
import re
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Optional AI imports - graceful fallback if not available
try:
    import openai
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("⚠️ OpenAI not installed - running in rule-based mode only")

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


# =============================================================================
# AI ENGINE - LLM-Powered Analysis
# =============================================================================

class AIComplianceEngine:
    """
    AI-powered compliance analysis using OpenAI GPT.
    
    This engine provides:
    1. Contextual vulnerability analysis
    2. False positive reduction
    3. AI-generated remediation code
    4. Risk assessment with reasoning
    """
    
    SYSTEM_PROMPT = """You are an expert security code reviewer and compliance analyst.
Your role is to analyze code for security vulnerabilities and compliance issues.

For each finding, you must:
1. Assess if it's a TRUE POSITIVE or FALSE POSITIVE based on context
2. Explain WHY it's a security risk (or why it's not)
3. Provide SPECIFIC remediation code
4. Map to compliance frameworks (SCF, SOC2, HIPAA, PCI-DSS)
5. Estimate business impact and risk score (1-10)

Be precise and actionable. Developers should be able to fix issues immediately from your suggestions."""

    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.model = os.environ.get("AI_MODEL", "gpt-4o-mini")  # Cost-effective default
        self.enabled = AI_AVAILABLE and bool(self.api_key)
        
        if self.enabled:
            openai.api_key = self.api_key
            print(f"🤖 AI Engine initialized with model: {self.model}")
        else:
            print("⚠️ AI Engine disabled - no API key or OpenAI not installed")
    
    def analyze_code(self, code: str, filepath: str, rule_findings: List[Dict]) -> Dict[str, Any]:
        """
        Use AI to analyze code and enhance rule-based findings.
        
        Args:
            code: The source code content
            filepath: Path to the file
            rule_findings: Findings from rule-based scanner
            
        Returns:
            AI-enhanced analysis with validated findings and suggestions
        """
        if not self.enabled:
            return self._fallback_analysis(rule_findings)
        
        try:
            # Prepare context for AI
            findings_summary = "\n".join([
                f"- Line {f['line']}: {f['title']} ({f['severity']})" 
                for f in rule_findings[:10]  # Limit to avoid token overflow
            ])
            
            prompt = f"""Analyze this code for security vulnerabilities and compliance issues.

File: {filepath}

Code:
```
{code[:4000]}  # Truncate to manage tokens
```

Rule-based scanner found these potential issues:
{findings_summary if findings_summary else "No issues detected by rules"}

Provide your analysis in this JSON format:
{{
    "validated_findings": [
        {{
            "original_title": "<from rule findings>",
            "is_true_positive": true/false,
            "confidence": 0.0-1.0,
            "reasoning": "<why this is/isn't a real issue>",
            "severity_adjustment": "<same/upgrade/downgrade>",
            "ai_remediation": "<specific code fix>"
        }}
    ],
    "additional_findings": [
        {{
            "title": "<issue title>",
            "severity": "critical/high/medium/low",
            "line": <line number or 0>,
            "description": "<what's wrong>",
            "remediation": "<how to fix>",
            "scf_control": "<SCF code>",
            "soc2_control": "<SOC2 code>"
        }}
    ],
    "risk_score": 1-10,
    "risk_reasoning": "<overall risk assessment>",
    "compliance_summary": "<frameworks affected and gaps>",
    "executive_summary": "<2-3 sentence summary for management>"
}}"""

            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Low temperature for consistent analysis
                max_tokens=2000,
                response_format={"type": "json_object"}
            )
            
            ai_result = json.loads(response.choices[0].message.content)
            ai_result["ai_powered"] = True
            ai_result["model_used"] = self.model
            
            print(f"🤖 AI Analysis complete - Risk Score: {ai_result.get('risk_score', 'N/A')}/10")
            return ai_result
            
        except Exception as e:
            print(f"⚠️ AI analysis failed: {e}")
            return self._fallback_analysis(rule_findings)
    
    def generate_fix(self, code_snippet: str, vulnerability: str) -> str:
        """Generate AI-powered code fix for a specific vulnerability."""
        if not self.enabled:
            return "AI fix generation not available"
        
        try:
            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert. Provide ONLY the fixed code, no explanations."},
                    {"role": "user", "content": f"Fix this {vulnerability} vulnerability:\n```\n{code_snippet}\n```"}
                ],
                temperature=0.1,
                max_tokens=500
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Fix generation failed: {e}"
    
    def _fallback_analysis(self, rule_findings: List[Dict]) -> Dict[str, Any]:
        """Fallback when AI is not available - use rule-based analysis only."""
        return {
            "ai_powered": False,
            "validated_findings": [
                {
                    "original_title": f["title"],
                    "is_true_positive": True,  # Assume true without AI validation
                    "confidence": 0.7,
                    "reasoning": "Rule-based detection (AI validation unavailable)",
                    "severity_adjustment": "same",
                    "ai_remediation": f["remediation"]
                }
                for f in rule_findings
            ],
            "additional_findings": [],
            "risk_score": self._calculate_rule_risk(rule_findings),
            "risk_reasoning": "Risk calculated from rule-based findings only",
            "compliance_summary": "AI compliance analysis unavailable",
            "executive_summary": f"Rule-based scan found {len(rule_findings)} potential issues."
        }
    
    def _calculate_rule_risk(self, findings: List[Dict]) -> int:
        """Calculate risk score from rule-based findings."""
        score = 0
        for f in findings:
            if f["severity"] == "critical":
                score += 3
            elif f["severity"] == "high":
                score += 2
            elif f["severity"] == "medium":
                score += 1
        return min(10, score)


# Initialize global AI engine
ai_engine = AIComplianceEngine()

def scan_file(filepath: str, content: str, use_ai: bool = True) -> Dict[str, Any]:
    """
    Scan a single file using HYBRID approach:
    1. Rule-based pattern matching (fast, deterministic)
    2. AI analysis for context and validation (intelligent, adaptive)
    
    Args:
        filepath: Path to the file
        content: File content
        use_ai: Whether to use AI enhancement
        
    Returns:
        Dict with rule_findings, ai_analysis, and merged results
    """
    # PHASE 1: Rule-based scanning (always runs)
    rule_findings = []
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
                        
                        rule_findings.append({
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
    
    # PHASE 2: AI-powered analysis (if enabled and findings exist)
    ai_analysis = None
    if use_ai and (rule_findings or len(content) > 100):
        ai_analysis = ai_engine.analyze_code(content, filepath, rule_findings)
    
    # PHASE 3: Merge and enhance findings
    enhanced_findings = _merge_findings(rule_findings, ai_analysis)
    
    return {
        "rule_findings": rule_findings,
        "ai_analysis": ai_analysis,
        "enhanced_findings": enhanced_findings,
        "ai_powered": ai_analysis.get("ai_powered", False) if ai_analysis else False
    }


def _merge_findings(rule_findings: List[Dict], ai_analysis: Optional[Dict]) -> List[Dict]:
    """
    Merge rule-based findings with AI analysis.
    AI can validate, adjust severity, or filter false positives.
    """
    if not ai_analysis:
        return rule_findings
    
    enhanced = []
    validated = {v["original_title"]: v for v in ai_analysis.get("validated_findings", [])}
    
    for finding in rule_findings:
        validation = validated.get(finding["title"], {})
        
        # Skip false positives identified by AI
        if validation.get("is_true_positive") == False and validation.get("confidence", 0) > 0.8:
            print(f"  🤖 AI filtered false positive: {finding['title']}")
            continue
        
        # Enhance with AI insights
        enhanced_finding = finding.copy()
        if validation:
            enhanced_finding["ai_confidence"] = validation.get("confidence", 0.7)
            enhanced_finding["ai_reasoning"] = validation.get("reasoning", "")
            enhanced_finding["ai_remediation"] = validation.get("ai_remediation", finding["remediation"])
            
            # Adjust severity if AI recommends
            if validation.get("severity_adjustment") == "upgrade":
                severity_order = ["low", "medium", "high", "critical"]
                current_idx = severity_order.index(finding["severity"])
                if current_idx < 3:
                    enhanced_finding["severity"] = severity_order[current_idx + 1]
                    enhanced_finding["severity_upgraded_by_ai"] = True
        
        enhanced.append(enhanced_finding)
    
    # Add AI-discovered findings not caught by rules
    for additional in ai_analysis.get("additional_findings", []):
        enhanced.append({
            "id": f"ai_finding_{additional.get('line', 0)}",
            "policy_id": "ai_detected",
            "severity": additional.get("severity", "medium"),
            "title": additional.get("title", "AI-Detected Issue"),
            "description": additional.get("description", ""),
            "remediation": additional.get("remediation", ""),
            "scf_control": additional.get("scf_control", "TDA-02"),
            "soc2_control": additional.get("soc2_control", "CC8.1"),
            "file": "<analyzed file>",
            "line": additional.get("line", 0),
            "code_snippet": "",
            "ai_discovered": True
        })
    
    return enhanced

def evaluate_findings(findings: list, ai_analyses: List[Dict] = None) -> dict:
    """
    Evaluate all findings and determine PR decision.
    Incorporates AI analysis for risk scoring and executive summary.
    """
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
    
    # Aggregate AI insights
    ai_powered = any(a.get("ai_powered", False) for a in (ai_analyses or []))
    ai_risk_scores = [a.get("risk_score", 0) for a in (ai_analyses or []) if a.get("ai_powered")]
    avg_risk_score = sum(ai_risk_scores) / len(ai_risk_scores) if ai_risk_scores else None
    
    executive_summaries = [a.get("executive_summary", "") for a in (ai_analyses or []) if a.get("executive_summary")]
    compliance_summaries = [a.get("compliance_summary", "") for a in (ai_analyses or []) if a.get("compliance_summary")]
    
    return {
        "decision": "BLOCK" if should_block else "ALLOW",
        "reason": reason,
        "ai_powered": ai_powered,
        "summary": {
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "total": len(findings)
        },
        "ai_insights": {
            "risk_score": avg_risk_score,
            "executive_summary": " ".join(executive_summaries) if executive_summaries else None,
            "compliance_summary": " ".join(compliance_summaries) if compliance_summaries else None,
            "false_positives_filtered": sum(
                1 for a in (ai_analyses or [])
                for v in a.get("validated_findings", [])
                if v.get("is_true_positive") == False
            )
        } if ai_powered else None,
        "blocking_issues": [
            {
                "severity": f["severity"].upper(),
                "title": f["title"],
                "file": f["file"],
                "line": f["line"],
                "scf_control": f["scf_control"],
                "soc2_control": f["soc2_control"],
                "description": f["description"],
                "remediation": f.get("ai_remediation", f["remediation"]),  # Prefer AI remediation
                "code_snippet": f.get("code_snippet", ""),
                "ai_confidence": f.get("ai_confidence"),
                "ai_reasoning": f.get("ai_reasoning")
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
                "remediation": f.get("ai_remediation", f["remediation"])
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
    """
    Main entry point for GitHub Actions.
    
    Runs hybrid scanning:
    1. Rule-based detection on all changed files
    2. AI analysis for context and validation (if OPENAI_API_KEY is set)
    """
    changed_files = os.environ.get("CHANGED_FILES", "").split()
    use_ai = os.environ.get("ENABLE_AI", "true").lower() == "true"
    
    print("\n" + "="*60)
    print("🤖 AI COMPLIANCE-AS-CODE SCANNER")
    print("="*60)
    print(f"\nMode: {'AI-Enhanced' if ai_engine.enabled and use_ai else 'Rule-Based Only'}")
    print(f"Files to scan: {len(changed_files)}")
    
    if not changed_files:
        print("No relevant files changed")
        with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a") as f:
            f.write("decision=ALLOW\n")
            f.write("has_suggestions=false\n")
        return
    
    all_findings = []
    all_ai_analyses = []
    
    for filepath in changed_files:
        if not os.path.exists(filepath):
            continue
        
        try:
            print(f"\n📄 Scanning: {filepath}")
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Hybrid scan: rules + AI
            scan_result = scan_file(filepath, content, use_ai=use_ai and ai_engine.enabled)
            
            # Collect enhanced findings
            all_findings.extend(scan_result["enhanced_findings"])
            
            # Collect AI analyses for aggregation
            if scan_result["ai_analysis"]:
                all_ai_analyses.append(scan_result["ai_analysis"])
            
            # Print per-file summary
            rule_count = len(scan_result["rule_findings"])
            enhanced_count = len(scan_result["enhanced_findings"])
            print(f"   Rules found: {rule_count} | After AI: {enhanced_count}")
            
        except Exception as e:
            print(f"❌ Error scanning {filepath}: {e}")
    
    # Evaluate with AI insights
    report = evaluate_findings(all_findings, all_ai_analyses)
    
    # Save report for GitHub Actions
    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\n" + "="*60)
    print("📊 SCAN RESULTS")
    print("="*60)
    print(f"\n🎯 Decision: {report['decision']}")
    print(f"📝 Reason: {report['reason']}")
    print(f"\n📈 Summary:")
    print(f"   🔴 Critical: {report['summary']['critical']}")
    print(f"   🟠 High:     {report['summary']['high']}")
    print(f"   🟡 Medium:   {report['summary']['medium']}")
    print(f"   🔵 Low:      {report['summary']['low']}")
    
    # AI Insights section
    if report.get("ai_powered") and report.get("ai_insights"):
        ai = report["ai_insights"]
        print(f"\n🤖 AI INSIGHTS:")
        if ai.get("risk_score"):
            print(f"   Risk Score: {ai['risk_score']}/10")
        if ai.get("false_positives_filtered"):
            print(f"   False Positives Filtered: {ai['false_positives_filtered']}")
        if ai.get("executive_summary"):
            print(f"   Summary: {ai['executive_summary'][:200]}...")
    
    if report['blocking_issues']:
        print("\n🚨 BLOCKING ISSUES:")
        for issue in report['blocking_issues']:
            print(f"\n   [{issue['severity']}] {issue['title']}")
            print(f"   File: {issue['file']}:{issue['line']}")
            print(f"   SCF: {issue['scf_control']} | SOC2: {issue['soc2_control']}")
            print(f"   Fix: {issue['remediation']}")
            if issue.get("ai_reasoning"):
                print(f"   🤖 AI: {issue['ai_reasoning'][:100]}...")
    
    if report['suggestions']:
        print("\n💡 SUGGESTIONS:")
        for sug in report['suggestions']:
            print(f"   - {sug['title']} ({sug['file']}:{sug['line']})")
            print(f"     {sug['remediation']}")
    
    print("\n" + "="*60)
    
    # Set GitHub Actions outputs
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"decision={report['decision']}\n")
            f.write(f"has_suggestions={'true' if report['suggestions'] else 'false'}\n")
            f.write(f"ai_powered={'true' if report.get('ai_powered') else 'false'}\n")
    
    # Exit with error if blocked
    if report['decision'] == 'BLOCK':
        sys.exit(1)


if __name__ == "__main__":
    main()
