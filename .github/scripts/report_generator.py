"""
Report Generator Module
=======================
Generates compliance reports and audit evidence.

SCF Controls:
- SCF-GRC-03: Control Assessment Repository
- SCF-GRC-14: Remediation Timelines

This module:
- Aggregates findings from all scanners
- Calculates risk metrics
- Maps to compliance frameworks
- Generates audit evidence
- Outputs JSON reports for GitHub Actions
"""

import json
from typing import List, Dict, Any, Set
from datetime import datetime


class ReportGenerator:
    """
    Generates comprehensive compliance reports.
    
    Implements SCF-GRC-03: Control Assessment Repository
    - Tracks findings with remediation plans
    - Maps to compliance frameworks
    - Provides audit evidence
    """
    
    def __init__(self):
        self.findings: List[Dict] = []
        self.scan_metadata: List[Dict] = []
    
    def add_findings(self, findings: List[Dict], metadata: Dict = None):
        """Add findings from a scanner."""
        self.findings.extend(findings)
        if metadata:
            self.scan_metadata.append(metadata)
    
    def generate_report(self, files_scanned: int) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report.
        
        Returns:
            Dict with decision, findings, metrics, and audit evidence
        """
        # Categorize by severity
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        blocking = []
        suggestions = []
        
        # Collect unique controls and categories
        scf_controls: Set[str] = set()
        owasp_categories: Set[str] = set()
        cve_ids: Set[str] = set()
        cvss_scores: List[float] = []
        
        for f in self.findings:
            sev = f.get("severity", "low").lower()
            summary[sev] = summary.get(sev, 0) + 1
            
            # Track compliance mappings
            if f.get("scf_control"):
                scf_controls.add(f["scf_control"])
            if f.get("owasp_category"):
                owasp_categories.add(f["owasp_category"])
            if f.get("cve_id"):
                cve_ids.add(f["cve_id"])
            if f.get("cvss_score"):
                cvss_scores.append(float(f["cvss_score"]))
            
            # Categorize blocking vs suggestions
            if sev in ["critical", "high"]:
                blocking.append(f)
            else:
                suggestions.append(f)
        
        # Calculate risk metrics
        decision = "BLOCK" if blocking else "ALLOW"
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        max_cvss = max(cvss_scores) if cvss_scores else 0
        risk_score = self._calculate_risk_score(summary, max_cvss)
        
        # Build report
        report = {
            "decision": decision,
            "reason": f"Found {len(blocking)} blocking issues (critical/high)" if blocking else "No blocking issues",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            
            # Findings
            "summary": summary,
            "blocking_issues": blocking,
            "suggestions": suggestions,
            "total_findings": len(self.findings),
            
            # Risk metrics (SCF-GRC-01)
            "risk_metrics": {
                "risk_score": risk_score,
                "max_cvss": max_cvss,
                "avg_cvss": round(avg_cvss, 1),
                "exploitable_critical": len([f for f in self.findings 
                    if f.get("exploitability") == "High" and f.get("severity") == "critical"]),
                "cve_count": len(cve_ids)
            },
            
            # Compliance mapping (SCF-GRC-03)
            "compliance": {
                "scf_controls_violated": sorted(list(scf_controls)),
                "owasp_categories": sorted(list(owasp_categories)),
                "cve_ids": sorted(list(cve_ids)),
                "frameworks_checked": ["SCF", "SOC2", "HIPAA", "PCI-DSS", "NIST"]
            },
            
            # Remediation SLAs (SCF-GRC-14)
            "remediation_slas": {
                "immediate": summary["critical"],
                "7_days": summary["high"],
                "30_days": summary["medium"],
                "90_days": summary["low"]
            },
            
            # Scan metadata
            "scan_info": {
                "files_scanned": files_scanned,
                "scanners_used": [m.get("scan_type", "unknown") for m in self.scan_metadata],
                "ai_powered": True
            }
        }
        
        return report
    
    def _calculate_risk_score(self, summary: Dict, max_cvss: float) -> int:
        """Calculate overall risk score (1-10)."""
        # Base score from severity counts
        score = (
            summary["critical"] * 3 +
            summary["high"] * 2 +
            summary["medium"] * 1 +
            summary["low"] * 0.5
        )
        
        # Factor in max CVSS
        if max_cvss >= 9.0:
            score += 3
        elif max_cvss >= 7.0:
            score += 2
        elif max_cvss >= 4.0:
            score += 1
        
        # Normalize to 1-10
        return min(10, max(1, int(score)))
    
    def print_report(self, report: Dict):
        """Print formatted report to console."""
        print("\n" + "=" * 70)
        print("📊 AI COMPLIANCE SCAN RESULTS")
        print("   SCF-GRC-03: Control Assessment Repository")
        print("=" * 70)
        
        decision_icon = "🚫" if report["decision"] == "BLOCK" else "✅"
        print(f"\n{decision_icon} Decision: {report['decision']}")
        print(f"📝 {report['reason']}")
        
        # Severity breakdown
        s = report["summary"]
        print(f"\n📈 Findings by Severity (SCF-GRC-01: Risk Classification):")
        print(f"   🔴 Critical: {s['critical']} (Immediate fix required)")
        print(f"   🟠 High:     {s['high']} (Fix within 7 days)")
        print(f"   🟡 Medium:   {s['medium']} (Fix within 30 days)")
        print(f"   🔵 Low:      {s['low']} (Fix within 90 days)")
        
        # Risk metrics
        rm = report.get("risk_metrics", {})
        print(f"\n📊 Risk Metrics (SCF-VULN-15: Risk-Based Prioritization):")
        print(f"   Risk Score: {rm.get('risk_score', 0)}/10")
        print(f"   Max CVSS:   {rm.get('max_cvss', 0)}")
        print(f"   Avg CVSS:   {rm.get('avg_cvss', 0)}")
        print(f"   CVEs Found: {rm.get('cve_count', 0)}")
        
        # Compliance mapping
        comp = report.get("compliance", {})
        print(f"\n🏛️ Compliance Mapping (SCF-GRC-03):")
        print(f"   SCF Controls: {', '.join(comp.get('scf_controls_violated', [])) or 'None'}")
        print(f"   OWASP: {', '.join(comp.get('owasp_categories', [])) or 'None'}")
        if comp.get('cve_ids'):
            print(f"   CVEs: {', '.join(comp['cve_ids'])}")
        
        # Blocking issues
        if report["blocking_issues"]:
            print(f"\n🚨 BLOCKING ISSUES ({len(report['blocking_issues'])}):")
            for issue in report["blocking_issues"][:10]:
                sev = issue.get('severity', 'unknown').upper()
                print(f"\n   [{sev}] {issue.get('title', 'Unknown')}")
                print(f"   📁 {issue.get('file', '?')}:{issue.get('line', '?')}")
                
                cvss = issue.get('cvss_score', 'N/A')
                owasp = issue.get('owasp_category', 'N/A')
                print(f"   📊 CVSS: {cvss} | OWASP: {owasp}")
                
                sla = issue.get('remediation_sla', 'Review manually')
                print(f"   ⏰ SLA: {sla}")
        
        print("\n" + "=" * 70)
    
    def save_report(self, report: Dict, filepath: str = "scan_report.json"):
        """Save report to JSON file."""
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        print(f"📄 Report saved to {filepath}")
