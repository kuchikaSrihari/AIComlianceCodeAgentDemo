"""
Configuration Scanner
=====================
AI-powered scanner for application configuration files.

SCF Controls:
- SCF-CFG-01: Configuration Management
- SCF-CRY-03: Secret Management
- SCF-LOG-01: Audit Logging Configuration

WHY AI IS ESSENTIAL HERE:
1. ENVIRONMENT AWARENESS:
   - Is this a development config (debug ok) or production (debug critical)?
   - AI understands config inheritance and overrides

2. SECRET DETECTION IN CONTEXT:
   - Distinguishes between placeholder values and real secrets
   - Understands environment variable references vs hardcoded values

3. SECURITY HEADER ANALYSIS:
   - Validates security header configurations
   - Suggests missing headers based on application type

4. COMPLIANCE MAPPING:
   - Maps config issues to specific compliance requirements
   - Identifies PCI-DSS, HIPAA, SOC2 violations
"""

from typing import List, Dict, Any
from .base import BaseScanner


class ConfigScanner(BaseScanner):
    """
    Scanner for application configuration files.
    
    Supports:
    - YAML/YML config files
    - JSON config files
    - .properties files
    - .env files
    - XML config files
    - INI files
    
    Detects:
    - Hardcoded secrets in config
    - Debug mode enabled
    - Insecure default values
    - Missing security headers
    - Overly permissive CORS
    - Insecure cookie settings
    - Missing rate limiting
    - Verbose error messages
    """
    
    PROMPT_TEMPLATE = """You are an expert in application security configuration analysis.

## CONTEXT
FILE: {filepath}
CONFIG TYPE: {config_type}
SCAN TYPE: Configuration Security Analysis

## CONFIGURATION FILE
```{lang}
{code}
```

## ANALYSIS REQUIREMENTS

### 1. SECRETS IN CONFIGURATION (SCF-CRY-03)
- Hardcoded passwords
- API keys and tokens
- Database connection strings with credentials
- Private keys or certificates
- JWT secrets
- Encryption keys

**Note:** Distinguish between:
- Actual hardcoded secrets (CRITICAL)
- Environment variable references like ${{DB_PASSWORD}} (OK)
- Placeholder values like "changeme" or "xxx" (MEDIUM - should be env var)

### 2. DEBUG & DEVELOPMENT SETTINGS
- Debug mode enabled (debug: true, DEBUG=1)
- Development/test databases in production config
- Verbose logging of sensitive data
- Stack traces enabled
- Profiling/debugging endpoints exposed

### 3. SECURITY HEADERS (Web Applications)
Missing or misconfigured:
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

### 4. CORS CONFIGURATION
- Access-Control-Allow-Origin: * (overly permissive)
- Credentials allowed with wildcard origin
- Missing CORS configuration (if needed)

### 5. SESSION & COOKIE SECURITY
- Missing Secure flag
- Missing HttpOnly flag
- Missing SameSite attribute
- Long session timeouts
- Weak session ID generation

### 6. AUTHENTICATION SETTINGS
- Weak password policies
- Missing account lockout
- Insecure "remember me" duration
- Missing MFA configuration

### 7. RATE LIMITING & THROTTLING
- Missing rate limits on auth endpoints
- Missing API throttling
- No brute force protection

### 8. LOGGING CONFIGURATION (SCF-LOG-01)
- Sensitive data being logged
- Missing security event logging
- Logs not being rotated/retained properly

### 9. TLS/SSL CONFIGURATION
- Weak cipher suites
- Old TLS versions (TLS 1.0, 1.1)
- Missing certificate validation
- Self-signed certificates in production

## OUTPUT FORMAT (JSON only, no markdown)
{{
    "findings": [
        {{
            "title": "Configuration issue title",
            "severity": "critical|high|medium|low",
            "line": <line number>,
            "category": "secrets|debug|headers|cors|session|auth|logging|tls",
            
            "description": "What's wrong and why it matters",
            "business_impact": "Security/compliance impact",
            
            "owasp_category": "A05:Security Misconfiguration",
            "cwe_id": "CWE-XXX",
            
            "cvss_score": <0.0-10.0>,
            "exploitability": "High|Medium|Low",
            
            "scf_control": "CFG-01|CRY-03|LOG-01",
            "soc2_control": "CC6.1|CC6.7",
            "compliance_frameworks": ["SOC2", "PCI-DSS", "HIPAA"],
            
            "evidence": "Exact config line/section",
            "remediation": "How to fix",
            "code_fix": "Corrected configuration"
        }}
    ],
    "risk_score": <1-10>,
    "executive_summary": "Summary of configuration risks",
    "scan_metadata": {{
        "config_type": "{config_type}",
        "environment_detected": "production|staging|development|unknown",
        "scf_controls_checked": ["CFG-01", "CRY-03", "LOG-01"]
    }}
}}

## SEVERITY GUIDELINES
- CRITICAL: Hardcoded production secrets, debug mode in prod
- HIGH: Missing security headers, overly permissive CORS, weak TLS
- MEDIUM: Missing rate limiting, verbose errors, placeholder secrets
- LOW: Minor misconfigs, missing optional headers

Analyze every setting. Flag ALL security issues."""

    CONFIG_TYPES = {
        'yaml': 'YAML Configuration',
        'yml': 'YAML Configuration',
        'json': 'JSON Configuration',
        'properties': 'Java Properties',
        'env': 'Environment Variables',
        'ini': 'INI Configuration',
        'toml': 'TOML Configuration',
        'xml': 'XML Configuration',
        'conf': 'Configuration File',
        'cfg': 'Configuration File',
    }

    def __init__(self, model=None):
        super().__init__(model)
        self.scan_type = "configuration"
    
    def get_file_types(self) -> List[str]:
        return list(self.CONFIG_TYPES.keys())
    
    def can_scan(self, filepath: str) -> bool:
        """Check if this is a config file."""
        ext = filepath.lower().split('.')[-1] if '.' in filepath else ''
        name = filepath.lower()
        
        # Check by extension
        if ext in self.CONFIG_TYPES:
            # Exclude IaC files (handled by IaC scanner)
            if any(k in name for k in ['terraform', 'cloudformation', 'kubernetes', 'k8s', 'ansible']):
                return False
            # Exclude dependency files (handled by SCA scanner)
            if any(k in name for k in ['package.json', 'pom.xml', 'requirements', 'gemfile', 'cargo']):
                return False
            return True
        
        # Check for .env files
        if '.env' in name or name.endswith('env'):
            return True
        
        # Check for common config file patterns
        if any(k in name for k in ['config', 'settings', 'application', 'appsettings']):
            return True
        
        return False
    
    def get_config_type(self, filepath: str) -> tuple:
        """Determine config type from filepath."""
        ext = filepath.lower().split('.')[-1] if '.' in filepath else ''
        name = filepath.lower()
        
        if '.env' in name:
            return ('bash', 'Environment Variables')
        
        config_type = self.CONFIG_TYPES.get(ext, 'Configuration File')
        return (ext if ext in ['yaml', 'yml', 'json', 'xml', 'toml'] else 'text', config_type)
    
    def get_prompt(self, filepath: str, code: str) -> str:
        lang, config_type = self.get_config_type(filepath)
        return self.PROMPT_TEMPLATE.format(
            filepath=filepath,
            config_type=config_type,
            lang=lang,
            code=code[:15000]
        )
