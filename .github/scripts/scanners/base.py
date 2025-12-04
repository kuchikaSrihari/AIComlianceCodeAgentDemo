"""
Base Scanner Module
===================
Core classes and data structures for all scanners.

SCF Controls:
- SCF-GRC-01: Technology Risk Classification
- SCF-GRC-14: Remediation Timelines (SLAs)
- SCF-GRC-03: Control Assessment Repository
"""

import os
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
from abc import ABC, abstractmethod


class RiskLevel(Enum):
    """Risk classification levels per SCF-GRC-01."""
    CRITICAL = "critical"  # CVSS 9.0-10.0 - Immediate remediation
    HIGH = "high"          # CVSS 7.0-8.9  - 7 days
    MEDIUM = "medium"      # CVSS 4.0-6.9  - 30 days
    LOW = "low"            # CVSS 0.1-3.9  - 90 days


@dataclass
class RemediationSLA:
    """
    SCF-GRC-14: Technology Risk Controls Remediation
    
    Defines remediation timelines based on risk severity:
    - Critical: Immediate remediation or documented compensating control
    - High: Remediation within 7 days
    - Medium: Remediation within 30 days
    - Low: Remediation within 90 days
    """
    level: RiskLevel
    days: int
    action: str
    
    @staticmethod
    def get_sla(severity: str) -> 'RemediationSLA':
        """Get SLA based on severity level."""
        slas = {
            "critical": RemediationSLA(RiskLevel.CRITICAL, 0, "Immediate remediation or documented compensating control"),
            "high": RemediationSLA(RiskLevel.HIGH, 7, "Remediation within 7 days"),
            "medium": RemediationSLA(RiskLevel.MEDIUM, 30, "Remediation within 30 days"),
            "low": RemediationSLA(RiskLevel.LOW, 90, "Remediation within 90 days")
        }
        return slas.get(severity.lower(), slas["medium"])


@dataclass
class Finding:
    """
    Structured security finding with full compliance context.
    
    Implements SCF-GRC-03: Control Assessment Repository
    - Tracks findings with remediation plans
    - Maps to compliance frameworks
    - Provides audit evidence
    """
    # Core identification
    title: str
    severity: str
    line: int
    file: str = ""
    category: str = ""
    
    # Description
    description: str = ""
    business_impact: str = ""
    evidence: str = ""
    
    # Remediation
    remediation: str = ""
    code_fix: str = ""
    remediation_sla: str = ""
    sla_days: int = 30
    
    # Risk metrics (SCF-VULN-15)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    exploitability: str = ""  # High/Medium/Low
    
    # Compliance mapping
    scf_control: str = ""
    soc2_control: str = ""
    owasp_category: str = ""
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    compliance_frameworks: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Auto-calculate SLA based on severity."""
        if not self.compliance_frameworks:
            self.compliance_frameworks = []
        sla = RemediationSLA.get_sla(self.severity)
        self.remediation_sla = sla.action
        self.sla_days = sla.days
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


# =============================================================================
# SCF CONTROL MAPPINGS
# =============================================================================

SCF_CONTROLS = {
    # Vulnerability Management
    "VULN-14": {"name": "Cloud & Container VM", "desc": "SCA for containerized apps"},
    "VULN-11": {"name": "Vulnerability Identification", "desc": "Automated scanning"},
    "VULN-04": {"name": "Penetration Testing", "desc": "OWASP Top 10 coverage"},
    "VULN-15": {"name": "Risk-Based Patch Mgmt", "desc": "CVSS + exploitability"},
    
    # GRC Controls
    "GRC-01": {"name": "Technology Risk Classification", "desc": "Business-contextual risk rating"},
    "GRC-14": {"name": "Risk Controls Remediation", "desc": "SLA-based remediation"},
    "GRC-03": {"name": "Control Assessment", "desc": "Tracking findings & ownership"},
    
    # Security Controls
    "CRY-01": {"name": "Cryptographic Controls", "desc": "Strong encryption"},
    "CRY-03": {"name": "Secret Management", "desc": "No hardcoded secrets"},
    "TDA-02": {"name": "Secure Coding", "desc": "Injection prevention"},
    "IAC-01": {"name": "Least Privilege", "desc": "Minimal permissions"},
    "NET-01": {"name": "Network Security", "desc": "Secure configurations"},
    "LOG-01": {"name": "Audit Logging", "desc": "Security event logging"},
}

OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Auth Failures",
    "A08": "Data Integrity Failures",
    "A09": "Logging Failures",
    "A10": "SSRF"
}


class BaseScanner(ABC):
    """
    Abstract base class for all scanners.
    
    Provides common functionality for AI-powered analysis.
    """
    
    def __init__(self, model=None):
        self.model = model
        self.scan_type = "generic"
    
    @abstractmethod
    def get_prompt(self, filepath: str, code: str) -> str:
        """Generate the analysis prompt for this scanner type."""
        pass
    
    @abstractmethod
    def get_file_types(self) -> List[str]:
        """Return list of file extensions this scanner handles."""
        pass
    
    def can_scan(self, filepath: str) -> bool:
        """Check if this scanner can handle the given file."""
        ext = filepath.lower().split('.')[-1] if '.' in filepath else ''
        return ext in self.get_file_types()
    
    def analyze(self, filepath: str, code: str) -> Dict[str, Any]:
        """
        Analyze code using AI.
        
        Returns dict with findings, risk_score, executive_summary.
        """
        if not self.model:
            return {"findings": [], "ai_powered": False}
        
        try:
            prompt = self.get_prompt(filepath, code)
            response = self.model.generate_content(prompt)
            
            # Parse JSON from response
            text = response.text.strip()
            
            # Remove markdown code blocks if present
            if "```" in text:
                parts = text.split("```")
                for part in parts:
                    clean = part.strip()
                    if clean.startswith("json"):
                        text = clean[4:].strip()
                        break
                    elif clean.startswith("{"):
                        text = clean
                        break
            
            result = json.loads(text)
            result["ai_powered"] = True
            result["scan_type"] = self.scan_type
            
            # Enrich findings with SLA information
            for finding in result.get("findings", []):
                sla = RemediationSLA.get_sla(finding.get("severity", "medium"))
                finding["remediation_sla"] = sla.action
                finding["sla_days"] = sla.days
            
            return result
            
        except json.JSONDecodeError as e:
            print(f"   ⚠️ Failed to parse AI response: {e}")
            return {"findings": [], "ai_powered": False, "error": str(e)}
        except Exception as e:
            print(f"   ⚠️ AI analysis failed: {e}")
            return {"findings": [], "ai_powered": False, "error": str(e)}
