#!/usr/bin/env python3
"""
AI-Powered Compliance Scanner for GitHub Actions
Uses Google Gemini (FREE) for intelligent code security analysis.
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
    AI-powered code security scanner using Google Gemini.
    
    What the AI does:
    1. Analyzes code for security vulnerabilities
    2. Maps findings to compliance frameworks (SCF, SOC2, HIPAA, PCI-DSS)
    3. Provides specific remediation code
    4. Assesses risk with business impact reasoning
    """
    
    PROMPT = """You are an expert security code reviewer. Analyze this code for security vulnerabilities.

FILE: {filepath}

CODE:
```
{code}
```

Find ALL security issues and return ONLY valid JSON (no markdown):
{{
    "findings": [
        {{
            "title": "Issue title",
            "severity": "critical|high|medium|low",
            "line": <line number>,
            "description": "What's wrong",
            "remediation": "Specific code fix",
            "scf_control": "SCF control code",
            "soc2_control": "SOC2 control code"
        }}
    ],
    "risk_score": 1-10,
    "executive_summary": "2-3 sentence summary for management"
}}

Focus on: hardcoded secrets, SQL injection, command injection, weak crypto, insecure deserialization, public cloud resources, overly permissive IAM."""

    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.enabled = False
        
        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel("gemini-2.0-flash")
                self.enabled = True
                print(f"🤖 AI Engine: Google Gemini ({self.model.model_name}) - FREE")
            except Exception as e:
                print(f"⚠️ Failed to initialize Gemini: {e}")
        else:
            print("⚠️ No GEMINI_API_KEY found - AI analysis disabled")
            print("   Add GEMINI_API_KEY to GitHub Secrets to enable AI")

    def analyze(self, filepath: str, code: str) -> Dict[str, Any]:
        """Analyze code using AI and return findings."""
        if not self.enabled:
            return {"findings": [], "ai_powered": False}
        
        try:
            prompt = self.PROMPT.format(filepath=filepath, code=code[:8000])
            response = self.model.generate_content(prompt)
            
            # Parse JSON from response
            text = response.text.strip()
            # Remove markdown code blocks if present
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            
            result = json.loads(text)
            result["ai_powered"] = True
            print(f"   🤖 AI found {len(result.get('findings', []))} issues, Risk: {result.get('risk_score', 'N/A')}/10")
            return result
            
        except Exception as e:
            print(f"   ⚠️ AI analysis failed: {e}")
            return {"findings": [], "ai_powered": False, "error": str(e)}


# =============================================================================
# MAIN - GitHub Actions Entry Point
# =============================================================================

def main():
    """Scan changed files using AI and report findings."""
    
    print("\n" + "="*60)
    print("🤖 AI COMPLIANCE SCANNER (Powered by Google Gemini)")
    print("="*60)
    
    # Initialize AI
    scanner = AIComplianceScanner()
    
    # Get changed files from GitHub Actions
    changed_files_env = os.environ.get("CHANGED_FILES", "")
    print(f"\nCHANGED_FILES env: {changed_files_env[:200]}..." if len(changed_files_env) > 200 else f"\nCHANGED_FILES env: {changed_files_env}")
    
    changed_files = changed_files_env.split()
    print(f"Files to scan: {len(changed_files)}")
    
    # Print all files for debugging
    for f in changed_files:
        exists = "✅" if os.path.exists(f) else "❌"
        print(f"   {exists} {f}")
    
    if not changed_files:
        print("No files to scan")
        write_output("ALLOW", False)
        return
    
    # Scan each file
    all_findings = []
    risk_scores = []
    summaries = []
    
    # Extensions to scan (skip .github workflow files)
    SCAN_EXTENSIONS = ('.java', '.py', '.js', '.ts', '.tf')
    SKIP_PATHS = ('.github/workflows/', '.github/scripts/')
    
    for filepath in changed_files:
        # Skip non-existent files
        if not os.path.exists(filepath):
            print(f"\n⚠️ Skipping (not found): {filepath}")
            continue
        
        # Skip workflow/script files
        if any(skip in filepath for skip in SKIP_PATHS):
            print(f"\n⏭️ Skipping (workflow/script): {filepath}")
            continue
            
        # Only scan code files
        if not filepath.endswith(SCAN_EXTENSIONS):
            print(f"\n⏭️ Skipping (not code): {filepath}")
            continue
        
        print(f"\n📄 Scanning: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            result = scanner.analyze(filepath, code)
            
            # Add filepath to each finding
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
    report = build_report(all_findings, risk_scores, summaries, scanner.enabled)
    
    # Save report
    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    # Print results
    print_report(report)
    
    # Set GitHub Actions output
    write_output(report["decision"], len(report["suggestions"]) > 0)
    
    # Exit with error if blocked
    if report["decision"] == "BLOCK":
        sys.exit(1)


def build_report(findings: List[Dict], risk_scores: List, summaries: List, ai_powered: bool) -> Dict:
    """Build the final report from all findings."""
    
    # Count by severity
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
    
    # Determine decision
    decision = "BLOCK" if blocking else "ALLOW"
    reason = f"Found {len(blocking)} blocking issues" if blocking else "No critical/high issues found"
    
    return {
        "decision": decision,
        "reason": reason,
        "summary": summary,
        "blocking_issues": blocking,
        "suggestions": suggestions,
        "ai_powered": ai_powered,
        "ai_insights": {
            "risk_score": max(risk_scores) if risk_scores else 0,
            "executive_summary": summaries[0] if summaries else "",
            "files_analyzed": len(set(f.get("file") for f in findings))
        }
    }


def print_report(report: Dict):
    """Print formatted report to console."""
    
    print("\n" + "="*60)
    print("📊 SCAN RESULTS")
    print("="*60)
    
    print(f"\n🎯 Decision: {report['decision']}")
    print(f"📝 Reason: {report['reason']}")
    
    s = report["summary"]
    print(f"\n📈 Summary:")
    print(f"   🔴 Critical: {s['critical']}")
    print(f"   🟠 High:     {s['high']}")
    print(f"   🟡 Medium:   {s['medium']}")
    print(f"   🔵 Low:      {s['low']}")
    
    if report.get("ai_powered"):
        ai = report.get("ai_insights", {})
        print(f"\n🤖 AI INSIGHTS:")
        print(f"   Risk Score: {ai.get('risk_score', 0)}/10")
        if ai.get("executive_summary"):
            print(f"   Summary: {ai['executive_summary'][:150]}...")
    
    if report["blocking_issues"]:
        print("\n🚨 BLOCKING ISSUES (Must Fix):")
        for issue in report["blocking_issues"]:
            print(f"\n   [{issue['severity'].upper()}] {issue['title']}")
            print(f"   📁 {issue.get('file', 'unknown')}:{issue.get('line', 0)}")
            print(f"   📋 {issue.get('description', '')[:100]}")
            print(f"   ✅ Fix: {issue.get('remediation', '')[:100]}")
    
    if report["suggestions"]:
        print("\n💡 SUGGESTIONS:")
        for s in report["suggestions"][:5]:
            print(f"   - [{s['severity']}] {s['title']} ({s.get('file', '')})")
    
    print("\n" + "="*60)


def write_output(decision: str, has_suggestions: bool):
    """Write output for GitHub Actions."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"decision={decision}\n")
            f.write(f"has_suggestions={'true' if has_suggestions else 'false'}\n")


if __name__ == "__main__":
    main()
