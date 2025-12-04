"""
Software Composition Analysis (SCA) Scanner
============================================
AI-powered scanner for dependency files to detect vulnerable components.

SCF Controls:
- SCF-VULN-14: Cloud & Container VM (SCA for containerized apps)
- SCF-VULN-06: Vulnerable & Outdated Components

WHY AI IS ESSENTIAL HERE:
1. CONTEXTUAL VULNERABILITY ASSESSMENT:
   - Is this dependency used in production or just dev/test?
   - Is the vulnerable function actually called in the codebase?
   - What's the actual attack surface?

2. TRANSITIVE DEPENDENCY ANALYSIS:
   - AI can identify vulnerable transitive dependencies
   - Understands dependency trees and conflict resolution

3. UPGRADE PATH RECOMMENDATIONS:
   - AI suggests safe upgrade versions
   - Identifies breaking changes
   - Provides migration guidance

4. PRIORITIZATION:
   - Not all CVEs are equal - AI assesses actual exploitability
   - Considers if the vulnerable code path is reachable
"""

from typing import List, Dict, Any
from .base import BaseScanner


class SCAScanner(BaseScanner):
    """
    Scanner for dependency/package files.
    
    Supports:
    - package.json (npm/Node.js)
    - pom.xml (Maven/Java)
    - requirements.txt (pip/Python)
    - Gemfile (Ruby)
    - go.mod (Go)
    - Cargo.toml (Rust)
    
    Detects:
    - Known CVEs in dependencies
    - Outdated packages with security fixes
    - Deprecated/unmaintained packages
    - License compliance issues
    - Typosquatting attacks
    """
    
    PROMPT_TEMPLATE = """You are an expert in software supply chain security analyzing dependency files.

## CONTEXT
FILE: {filepath}
PACKAGE MANAGER: {package_manager}
SCAN TYPE: Software Composition Analysis (SCA)

## DEPENDENCY FILE
```{lang}
{code}
```

## ANALYSIS REQUIREMENTS

### 1. KNOWN CVE DETECTION
Check for these critical vulnerabilities:

**JavaScript/Node.js:**
- lodash < 4.17.21 (CVE-2021-23337, CVE-2020-8203)
- axios < 0.21.1 (CVE-2020-28168)
- minimist < 1.2.6 (CVE-2021-44906)
- node-fetch < 2.6.7 (CVE-2022-0235)
- express < 4.17.3 (various CVEs)
- jsonwebtoken < 9.0.0 (CVE-2022-23529)

**Java:**
- log4j < 2.17.0 (CVE-2021-44228 - Log4Shell)
- spring-core < 5.3.18 (CVE-2022-22965 - Spring4Shell)
- jackson-databind < 2.13.2.1 (multiple CVEs)
- commons-collections < 3.2.2 (CVE-2015-7501)
- struts2 < 2.5.30 (multiple RCE CVEs)
- fastjson < 1.2.83 (CVE-2022-25845)

**Python:**
- django < 4.0.6 (multiple CVEs)
- flask < 2.0.0 (CVE-2019-1010083)
- requests < 2.31.0 (CVE-2023-32681)
- pyyaml < 5.4 (CVE-2020-14343)
- pillow < 9.3.0 (multiple CVEs)
- cryptography < 39.0.1 (CVE-2023-23931)

### 2. OUTDATED PACKAGES
- Packages more than 2 major versions behind
- Packages with known security fixes in newer versions
- End-of-life packages

### 3. SUPPLY CHAIN RISKS
- Typosquatting (similar names to popular packages)
- Packages with very few downloads/stars
- Recently published packages (< 30 days)
- Packages with no recent updates (> 2 years)

### 4. LICENSE COMPLIANCE
- GPL in commercial projects
- License conflicts
- Missing licenses

## OUTPUT FORMAT (JSON only, no markdown)
{{
    "findings": [
        {{
            "title": "Vulnerable dependency: [package]@[version]",
            "severity": "critical|high|medium|low",
            "line": <line number where dependency is declared>,
            "category": "sca",
            
            "description": "Vulnerability details",
            "business_impact": "What could happen if exploited",
            
            "owasp_category": "A06:Vulnerable Components",
            "cwe_id": "CWE-1035",
            "cve_id": "CVE-YYYY-NNNNN",
            
            "cvss_score": <0.0-10.0>,
            "exploitability": "High|Medium|Low (are there public exploits?)",
            
            "scf_control": "VULN-14",
            "soc2_control": "CC6.1",
            "compliance_frameworks": ["SOC2", "PCI-DSS"],
            
            "evidence": "package@version in dependency file",
            "remediation": "Upgrade to [package]@[safe_version]",
            "code_fix": "Updated dependency declaration"
        }}
    ],
    "risk_score": <1-10>,
    "executive_summary": "Summary of dependency risks",
    "scan_metadata": {{
        "package_manager": "{package_manager}",
        "total_dependencies": <count>,
        "vulnerable_dependencies": <count>,
        "scf_controls_checked": ["VULN-14", "VULN-06"]
    }}
}}

## SEVERITY GUIDELINES
- CRITICAL: RCE vulnerabilities (Log4Shell, Spring4Shell), auth bypass
- HIGH: SQL injection, XSS, SSRF in dependencies
- MEDIUM: DoS vulnerabilities, information disclosure
- LOW: Minor issues, outdated but no known CVEs

Flag ALL vulnerable dependencies. Prioritize by exploitability."""

    PACKAGE_MANAGERS = {
        'package.json': ('json', 'npm/Node.js'),
        'package-lock.json': ('json', 'npm/Node.js'),
        'yarn.lock': ('yaml', 'Yarn'),
        'pom.xml': ('xml', 'Maven/Java'),
        'build.gradle': ('groovy', 'Gradle/Java'),
        'requirements.txt': ('text', 'pip/Python'),
        'Pipfile': ('toml', 'Pipenv/Python'),
        'pyproject.toml': ('toml', 'Poetry/Python'),
        'Gemfile': ('ruby', 'Bundler/Ruby'),
        'Gemfile.lock': ('text', 'Bundler/Ruby'),
        'go.mod': ('go', 'Go Modules'),
        'Cargo.toml': ('toml', 'Cargo/Rust'),
        'composer.json': ('json', 'Composer/PHP'),
    }

    def __init__(self, model=None):
        super().__init__(model)
        self.scan_type = "software_composition_analysis"
    
    def get_file_types(self) -> List[str]:
        # SCA scanner checks by filename, not extension
        return []
    
    def can_scan(self, filepath: str) -> bool:
        """Check if this is a dependency file."""
        filename = filepath.split('/')[-1].split('\\')[-1].lower()
        return filename in [k.lower() for k in self.PACKAGE_MANAGERS.keys()]
    
    def get_package_manager(self, filepath: str) -> tuple:
        """Determine package manager from filename."""
        filename = filepath.split('/')[-1].split('\\')[-1]
        for pm_file, (lang, pm_name) in self.PACKAGE_MANAGERS.items():
            if filename.lower() == pm_file.lower():
                return (lang, pm_name)
        return ('text', 'Unknown')
    
    def get_prompt(self, filepath: str, code: str) -> str:
        lang, package_manager = self.get_package_manager(filepath)
        return self.PROMPT_TEMPLATE.format(
            filepath=filepath,
            package_manager=package_manager,
            lang=lang,
            code=code[:15000]
        )
