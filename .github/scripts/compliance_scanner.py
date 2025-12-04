#!/usr/bin/env python3
"""
AI Compliance-as-Code Bot
=========================
Shift-left compliance scanner that embeds policy-as-code into your SDLC.

Features:
- Scans PRs for security/compliance violations
- Maps findings to SCF, SOC2, HIPAA, PCI-DSS frameworks
- Provides AI-powered remediation suggestions
- Comments directly on code lines in PRs

Supports: Java, Python, JavaScript, TypeScript, Terraform, YAML, JSON

Usage: Add this to any repo's .github/scripts/ folder along with the workflow.
"""

import os
import json
import sys
from typing import List, Dict, Any

# =============================================================================
# AI ENGINE - Google Gemini (FREE)
# =============================================================================

class AIComplianceScanner:
    """
    AI-powered compliance scanner using Google Gemini.
    
    SCF Control Mappings:
    - CPL (Compliance): Policy enforcement and audit evidence
    - CFG (Configuration Management): Secure configurations
    - TDA (Technology Development & Acquisition): Secure SDLC
    - CRY (Cryptography): Encryption and key management
    - IAC (Identity & Access Control): Least privilege
    - NET (Network Security): Network configurations
    """
    
    PROMPT = """You are an expert security and compliance code reviewer.

Analyze this code for security vulnerabilities and compliance violations.

FILE: {filepath}

CODE:
```
{code}
```

Find ALL issues and return ONLY valid JSON (no markdown, no code blocks):
{{
    "findings": [
        {{
            "title": "Issue title",
            "severity": "critical|high|medium|low",
            "line": <line number where issue occurs>,
            "description": "What's wrong and why it's a compliance risk",
            "remediation": "Specific code fix or configuration change",
            "scf_control": "SCF control code (e.g., CRY-03, TDA-02, CFG-01)",
            "soc2_control": "SOC2 control (e.g., CC6.1, CC7.2)",
            "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"]
        }}
    ],
    "risk_score": <1-10>,
    "executive_summary": "2-3 sentence summary for management"
}}

COMPLIANCE FOCUS AREAS:
1. SECRETS (CRY-03): Hardcoded passwords, API keys, tokens, private keys
2. INJECTION (TDA-02): SQL injection, command injection, XSS
3. CRYPTO (CRY-01/02): Weak algorithms (MD5, SHA1, DES), missing encryption
4. ACCESS (IAC-01): Overly permissive IAM, wildcard permissions
5. NETWORK (NET-01): Open security groups, public resources, 0.0.0.0/0
6. CONFIG (CFG-01): Debug mode, missing logging, insecure defaults
7. DATA (DAT-01): Public S3 buckets, unencrypted storage

Return findings for ALL issues found. Be thorough."""

    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.enabled = False
        self.model_name = "gemini-2.0-flash"
        
        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel(self.model_name)
                self.enabled = True
                print(f"🤖 AI Engine: Google Gemini ({self.model_name}) - FREE")
            except Exception as e:
                print(f"⚠️ Failed to initialize Gemini: {e}")
        else:
            print("⚠️ No GEMINI_API_KEY found")
            print("   Add GEMINI_API_KEY to repository secrets to enable AI scanning")

    def analyze(self, filepath: str, code: str) -> Dict[str, Any]:
        """Analyze code using AI for compliance violations."""
        if not self.enabled:
            return {"findings": [], "ai_powered": False}
        
        try:
            prompt = self.PROMPT.format(filepath=filepath, code=code[:10000])
            response = self.model.generate_content(prompt)
            
            # Parse JSON from response
            text = response.text.strip()
            
            # Remove markdown code blocks if present
            if "```" in text:
                # Extract content between code blocks
                parts = text.split("```")
                for part in parts:
                    if part.strip().startswith("json"):
                        text = part.strip()[4:].strip()
                        break
                    elif part.strip().startswith("{"):
                        text = part.strip()
                        break
            
            result = json.loads(text)
            result["ai_powered"] = True
            
            findings_count = len(result.get("findings", []))
            risk = result.get("risk_score", "N/A")
            print(f"   🤖 AI found {findings_count} issues | Risk Score: {risk}/10")
            
            return result
            
        except json.JSONDecodeError as e:
            print(f"   ⚠️ Failed to parse AI response: {e}")
            print(f"   Raw response: {text[:200]}...")
            return {"findings": [], "ai_powered": False, "error": str(e)}
        except Exception as e:
            print(f"   ⚠️ AI analysis failed: {e}")
            return {"findings": [], "ai_powered": False, "error": str(e)}


# =============================================================================
# MAIN SCANNER
# =============================================================================

def main():
    """Main entry point for GitHub Actions."""
    
    print("\n" + "="*70)
    print("🛡️  AI COMPLIANCE-AS-CODE BOT")
    print("    Shift-left compliance scanning for your SDLC")
    print("="*70)
    
    # Initialize AI scanner
    scanner = AIComplianceScanner()
    
    # Get changed files
    changed_files_env = os.environ.get("CHANGED_FILES", "")
    changed_files = changed_files_env.split() if changed_files_env else []
    
    print(f"\n📁 Files to scan: {len(changed_files)}")
    
    if not changed_files:
        print("   No files changed")
        write_output("ALLOW", False)
        save_report({"decision": "ALLOW", "reason": "No files to scan", "findings": []})
        return
    
    # File extensions to scan
    CODE_EXTENSIONS = ('.java', '.py', '.js', '.ts', '.jsx', '.tsx', '.tf', '.yaml', '.yml', '.json', '.xml', '.properties')
    SKIP_PATHS = ('.github/workflows/', '.github/scripts/', 'node_modules/', 'target/', 'build/', '.git/')
    
    # Scan files
    all_findings = []
    risk_scores = []
    summaries = []
    files_scanned = 0
    
    for filepath in changed_files:
        # Skip non-existent
        if not os.path.exists(filepath):
            continue
        
        # Skip excluded paths
        if any(skip in filepath for skip in SKIP_PATHS):
            print(f"   ⏭️  Skip: {filepath}")
            continue
        
        # Only scan code files
        if not filepath.endswith(CODE_EXTENSIONS):
            continue
        
        print(f"\n📄 Scanning: {filepath}")
        files_scanned += 1
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            result = scanner.analyze(filepath, code)
            
            # Add filepath to findings
            for finding in result.get("findings", []):
                finding["file"] = filepath
                all_findings.append(finding)
            
            if result.get("risk_score"):
                risk_scores.append(result["risk_score"])
            if result.get("executive_summary"):
                summaries.append(result["executive_summary"])
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Build report
    report = build_report(all_findings, risk_scores, summaries, scanner.enabled, files_scanned)
    
    # Save and output
    save_report(report)
    print_report(report)
    write_output(report["decision"], len(report.get("suggestions", [])) > 0)
    
    # Exit with error if blocked
    if report["decision"] == "BLOCK":
        sys.exit(1)


def build_report(findings: List[Dict], risk_scores: List, summaries: List, ai_powered: bool, files_scanned: int) -> Dict:
    """Build compliance report from findings."""
    
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    blocking = []
    suggestions = []
    
    for f in findings:
        sev = f.get("severity", "low").lower()
        summary[sev] = summary.get(sev, 0) + 1
        
        if sev in ["critical", "high"]:
            blocking.append(f)
        else:
            suggestions.append(f)
    
    decision = "BLOCK" if blocking else "ALLOW"
    
    return {
        "decision": decision,
        "reason": f"Found {len(blocking)} blocking issues (critical/high)" if blocking else "No blocking issues",
        "summary": summary,
        "blocking_issues": blocking,
        "suggestions": suggestions,
        "ai_powered": ai_powered,
        "ai_insights": {
            "risk_score": max(risk_scores) if risk_scores else 0,
            "executive_summary": summaries[0] if summaries else "",
            "files_scanned": files_scanned,
            "total_findings": len(findings)
        }
    }


def print_report(report: Dict):
    """Print formatted report."""
    
    print("\n" + "="*70)
    print("📊 COMPLIANCE SCAN RESULTS")
    print("="*70)
    
    decision_icon = "🚫" if report["decision"] == "BLOCK" else "✅"
    print(f"\n{decision_icon} Decision: {report['decision']}")
    print(f"📝 {report['reason']}")
    
    s = report["summary"]
    print(f"\n📈 Findings by Severity:")
    print(f"   🔴 Critical: {s['critical']}")
    print(f"   🟠 High:     {s['high']}")
    print(f"   🟡 Medium:   {s['medium']}")
    print(f"   🔵 Low:      {s['low']}")
    
    ai = report.get("ai_insights", {})
    print(f"\n🤖 AI Analysis:")
    print(f"   Risk Score: {ai.get('risk_score', 0)}/10")
    print(f"   Files Scanned: {ai.get('files_scanned', 0)}")
    if ai.get("executive_summary"):
        print(f"   Summary: {ai['executive_summary'][:200]}")
    
    if report["blocking_issues"]:
        print(f"\n🚨 BLOCKING ISSUES ({len(report['blocking_issues'])}):")
        for issue in report["blocking_issues"][:10]:
            print(f"\n   [{issue.get('severity', 'unknown').upper()}] {issue.get('title', 'Unknown')}")
            print(f"   📁 {issue.get('file', '?')}:{issue.get('line', '?')}")
            print(f"   📋 SCF: {issue.get('scf_control', 'N/A')} | SOC2: {issue.get('soc2_control', 'N/A')}")
            print(f"   ✅ Fix: {issue.get('remediation', 'Review manually')[:100]}")
    
    print("\n" + "="*70)


def save_report(report: Dict):
    """Save report to JSON file."""
    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=2)


def write_output(decision: str, has_suggestions: bool):
    """Write GitHub Actions output."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"decision={decision}\n")
            f.write(f"has_suggestions={'true' if has_suggestions else 'false'}\n")


if __name__ == "__main__":
    main()
