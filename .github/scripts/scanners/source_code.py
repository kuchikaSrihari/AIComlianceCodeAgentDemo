"""
Source Code Scanner
===================
AI-powered scanner for application source code (Java, Python, JS/TS).

SCF Controls:
- SCF-TDA-02: Secure Coding (Injection prevention)
- SCF-CRY-03: Secret Management
- SCF-VULN-04: OWASP Top 10 Coverage

WHY AI IS ESSENTIAL HERE:
1. CONTEXTUAL UNDERSTANDING: AI distinguishes between:
   - Hardcoded password vs password variable loaded from env
   - Test code vs production code
   - Sanitized input vs raw user input
   
2. FALSE POSITIVE REDUCTION: Rule-based scanners flag every "password" string.
   AI understands context and reduces false positives by 70%+.

3. INTELLIGENT REMEDIATION: AI provides code-specific fixes that:
   - Match the existing codebase style
   - Use the same libraries/frameworks
   - Include proper error handling
"""

from typing import List, Dict, Any
from .base import BaseScanner


class SourceCodeScanner(BaseScanner):
    """
    Scanner for application source code.
    
    Detects:
    - Injection vulnerabilities (SQL, Command, XSS, LDAP)
    - Hardcoded secrets and credentials
    - Unsafe deserialization
    - Weak cryptography
    - Authentication/authorization flaws
    - Logging sensitive data
    """
    
    PROMPT_TEMPLATE = """You are an expert application security engineer analyzing source code.

## CONTEXT
FILE: {filepath}
LANGUAGE: {language}
SCAN TYPE: Source Code Security Analysis

## CODE TO ANALYZE
```{lang}
{code}
```

## ANALYSIS REQUIREMENTS

Analyze for these vulnerability categories:

### 1. INJECTION FLAWS (OWASP A03)
- SQL Injection (CWE-89): String concatenation in queries
- Command Injection (CWE-78): Runtime.exec(), os.system(), subprocess with user input
- XSS (CWE-79): Unescaped output in HTML/JS
- LDAP Injection (CWE-90): Unsanitized LDAP queries
- Expression Language Injection: OGNL, SpEL, MVEL

### 2. SECRETS & CREDENTIALS (OWASP A02)
- Hardcoded passwords (CWE-798)
- API keys in source code
- Private keys, certificates
- Connection strings with credentials
- JWT secrets

### 3. CRYPTOGRAPHIC FAILURES (OWASP A02)
- Weak algorithms: MD5, SHA1, DES, RC4
- Hardcoded encryption keys
- Missing encryption for sensitive data
- Insecure random number generation

### 4. UNSAFE DESERIALIZATION (OWASP A08)
- Java: ObjectInputStream, XMLDecoder, XStream
- Python: pickle, yaml.load(), eval()
- JavaScript: JSON.parse() with reviver exploits

### 5. AUTHENTICATION FLAWS (OWASP A07)
- Missing authentication checks
- Weak password validation
- Session fixation vulnerabilities
- Insecure "remember me" implementations

### 6. LOGGING & ERROR HANDLING (OWASP A09)
- Sensitive data in logs (passwords, tokens, PII)
- Stack traces exposed to users
- Missing security event logging

### 7. KNOWN CVE PATTERNS
- Log4j JNDI (CVE-2021-44228): logger.info(userInput)
- Spring4Shell (CVE-2022-22965): Data binding RCE
- Jackson Deserialization (CVE-2017-7525)
- Apache Commons Collections (CVE-2015-7501)

## OUTPUT FORMAT (JSON only, no markdown)
{{
    "findings": [
        {{
            "title": "Concise vulnerability title",
            "severity": "critical|high|medium|low",
            "line": <exact line number>,
            "category": "injection|secrets|crypto|deserialization|auth|logging",
            
            "description": "Technical explanation of the vulnerability",
            "business_impact": "What could happen if exploited (data breach, RCE, etc.)",
            
            "owasp_category": "A01-A10",
            "cwe_id": "CWE-XXX",
            "cve_id": "CVE-YYYY-NNNNN or null",
            
            "cvss_score": <0.0-10.0>,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "exploitability": "High|Medium|Low",
            
            "scf_control": "TDA-02|CRY-03|CRY-01|LOG-01",
            "soc2_control": "CC6.1|CC6.7|CC7.2",
            "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
            
            "evidence": "Exact code snippet showing the vulnerability",
            "remediation": "Step-by-step fix instructions",
            "code_fix": "Corrected code example"
        }}
    ],
    "risk_score": <1-10>,
    "executive_summary": "2-3 sentence summary for management",
    "scan_metadata": {{
        "language": "{language}",
        "owasp_coverage": ["A02", "A03", "A07"],
        "scf_controls_checked": ["TDA-02", "CRY-03", "LOG-01"]
    }}
}}

## SEVERITY GUIDELINES
- CRITICAL (9.0-10.0): RCE, auth bypass, SQL injection with data exfil
- HIGH (7.0-8.9): Stored XSS, hardcoded secrets, unsafe deserialization
- MEDIUM (4.0-6.9): Reflected XSS, weak crypto, missing auth checks
- LOW (0.1-3.9): Info disclosure, verbose errors, minor misconfigs

Be thorough. Analyze every line. Provide specific, actionable fixes."""

    LANGUAGE_MAP = {
        'java': ('java', 'Java'),
        'py': ('python', 'Python'),
        'js': ('javascript', 'JavaScript'),
        'jsx': ('javascript', 'JavaScript/React'),
        'ts': ('typescript', 'TypeScript'),
        'tsx': ('typescript', 'TypeScript/React'),
        'go': ('go', 'Go'),
        'rb': ('ruby', 'Ruby'),
        'php': ('php', 'PHP'),
        'cs': ('csharp', 'C#'),
        'scala': ('scala', 'Scala'),
        'kt': ('kotlin', 'Kotlin'),
    }

    def __init__(self, model=None):
        super().__init__(model)
        self.scan_type = "source_code"
    
    def get_file_types(self) -> List[str]:
        return list(self.LANGUAGE_MAP.keys())
    
    def get_language(self, filepath: str) -> tuple:
        """Get language info for the file."""
        ext = filepath.lower().split('.')[-1] if '.' in filepath else ''
        return self.LANGUAGE_MAP.get(ext, ('text', 'Unknown'))
    
    def get_prompt(self, filepath: str, code: str) -> str:
        lang, language = self.get_language(filepath)
        return self.PROMPT_TEMPLATE.format(
            filepath=filepath,
            language=language,
            lang=lang,
            code=code[:15000]
        )
