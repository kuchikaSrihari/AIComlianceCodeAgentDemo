"""
Infrastructure-as-Code (IaC) Scanner
====================================
AI-powered scanner for Terraform, CloudFormation, Kubernetes YAML.

SCF Controls:
- SCF-NET-01: Network Security
- SCF-IAC-01: Least Privilege (Identity & Access)
- SCF-CRY-01: Encryption at Rest/Transit
- SCF-LOG-01: Audit Logging

WHY AI IS ESSENTIAL HERE:
1. CONTEXT-AWARE ANALYSIS: AI understands:
   - Is this a dev/staging/prod environment?
   - Is the open security group for a load balancer (acceptable) or database (critical)?
   - Are the IAM permissions for a CI/CD role (broader ok) or user role (should be minimal)?

2. CROSS-RESOURCE ANALYSIS: AI can detect:
   - S3 bucket is public AND contains sensitive data references
   - Security group allows 0.0.0.0/0 AND is attached to a database
   - IAM role has admin access AND is assumable by external accounts

3. COMPLIANCE MAPPING: AI maps findings to specific compliance requirements:
   - PCI-DSS: Encryption requirements for cardholder data
   - HIPAA: PHI protection requirements
   - SOC2: Access control requirements
"""

from typing import List, Dict, Any
from .base import BaseScanner


class IaCScanner(BaseScanner):
    """
    Scanner for Infrastructure-as-Code files.
    
    Supports:
    - Terraform (.tf, .tfvars)
    - CloudFormation (YAML/JSON)
    - Kubernetes manifests
    - Docker Compose
    - Ansible playbooks
    
    Detects:
    - Open security groups (0.0.0.0/0)
    - Overly permissive IAM policies
    - Unencrypted storage (S3, RDS, EBS)
    - Public resources
    - Missing logging/monitoring
    - Privileged containers
    - Insecure network configurations
    """
    
    PROMPT_TEMPLATE = """You are an expert cloud security architect analyzing Infrastructure-as-Code.

## CONTEXT
FILE: {filepath}
IAC TYPE: {iac_type}
SCAN TYPE: Infrastructure Security Analysis

## CODE TO ANALYZE
```{lang}
{code}
```

## ANALYSIS REQUIREMENTS

### 1. NETWORK SECURITY (SCF-NET-01)
- Open security groups: 0.0.0.0/0 or ::/0 ingress
- Unrestricted egress rules
- Public subnets for sensitive resources
- Missing network ACLs
- Exposed management ports (22, 3389, 5432, 3306)

### 2. IDENTITY & ACCESS (SCF-IAC-01)
- Wildcard IAM permissions ("*")
- Overly permissive policies (AdministratorAccess)
- Missing resource constraints
- Cross-account access without conditions
- Service accounts with excessive permissions
- Missing MFA requirements

### 3. ENCRYPTION (SCF-CRY-01)
- Unencrypted S3 buckets
- Unencrypted RDS instances
- Unencrypted EBS volumes
- Missing KMS key rotation
- Unencrypted data in transit (HTTP endpoints)
- Self-signed or expired certificates

### 4. LOGGING & MONITORING (SCF-LOG-01)
- Missing CloudTrail
- Missing VPC Flow Logs
- Disabled S3 access logging
- Missing CloudWatch alarms
- No audit logging for databases

### 5. CONTAINER SECURITY
- Privileged containers
- Running as root
- Host network/PID namespace
- Missing resource limits
- Writable root filesystem
- Missing security contexts

### 6. DATA PROTECTION
- Public S3 buckets
- Public RDS instances
- Missing backup configurations
- No versioning on critical buckets
- Missing deletion protection

### 7. COMPLIANCE-SPECIFIC CHECKS
- PCI-DSS: Encryption, access logging, network segmentation
- HIPAA: PHI encryption, audit trails, access controls
- SOC2: Change management, access reviews, monitoring

## OUTPUT FORMAT (JSON only, no markdown)
{{
    "findings": [
        {{
            "title": "Concise issue title",
            "severity": "critical|high|medium|low",
            "line": <line number>,
            "category": "network|access|encryption|logging|container|data",
            
            "description": "Technical explanation",
            "business_impact": "Risk if exploited (data exposure, compliance violation)",
            
            "owasp_category": "A01|A05|A06",
            "cwe_id": "CWE-XXX",
            
            "cvss_score": <0.0-10.0>,
            "exploitability": "High|Medium|Low",
            
            "scf_control": "NET-01|IAC-01|CRY-01|LOG-01",
            "soc2_control": "CC6.1|CC6.6|CC7.1",
            "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS", "NIST"],
            
            "evidence": "Exact config snippet",
            "remediation": "Step-by-step fix",
            "code_fix": "Corrected configuration"
        }}
    ],
    "risk_score": <1-10>,
    "executive_summary": "Summary for management",
    "scan_metadata": {{
        "iac_type": "{iac_type}",
        "cloud_provider": "AWS|Azure|GCP|Kubernetes",
        "scf_controls_checked": ["NET-01", "IAC-01", "CRY-01", "LOG-01"]
    }}
}}

## SEVERITY GUIDELINES
- CRITICAL: Public database, wildcard admin IAM, no encryption on PII/PHI
- HIGH: Open security groups on sensitive ports, missing CloudTrail
- MEDIUM: Missing encryption on non-sensitive data, verbose logging
- LOW: Missing tags, non-critical misconfigurations

Analyze every resource. Flag ALL security issues."""

    IAC_TYPES = {
        'tf': ('hcl', 'Terraform'),
        'tfvars': ('hcl', 'Terraform Variables'),
        'yaml': ('yaml', 'YAML Config'),
        'yml': ('yaml', 'YAML Config'),
        'json': ('json', 'JSON Config'),
    }

    def __init__(self, model=None):
        super().__init__(model)
        self.scan_type = "infrastructure_as_code"
    
    def get_file_types(self) -> List[str]:
        return ['tf', 'tfvars']
    
    def can_scan(self, filepath: str) -> bool:
        """Check if this is an IaC file."""
        ext = filepath.lower().split('.')[-1] if '.' in filepath else ''
        name = filepath.lower()
        
        # Terraform files
        if ext in ['tf', 'tfvars']:
            return True
        
        # CloudFormation
        if ext in ['yaml', 'yml', 'json']:
            if any(k in name for k in ['cloudformation', 'cfn', 'sam', 'stack']):
                return True
        
        # Kubernetes
        if ext in ['yaml', 'yml']:
            if any(k in name for k in ['kubernetes', 'k8s', 'deployment', 'service', 'pod', 'helm']):
                return True
        
        return False
    
    def get_iac_type(self, filepath: str) -> tuple:
        """Determine IaC type from filepath."""
        ext = filepath.lower().split('.')[-1] if '.' in filepath else ''
        name = filepath.lower()
        
        if ext in ['tf', 'tfvars']:
            return ('hcl', 'Terraform')
        elif 'cloudformation' in name or 'cfn' in name:
            return ('yaml', 'CloudFormation')
        elif any(k in name for k in ['kubernetes', 'k8s', 'deployment', 'service']):
            return ('yaml', 'Kubernetes')
        elif 'docker-compose' in name:
            return ('yaml', 'Docker Compose')
        elif 'ansible' in name or 'playbook' in name:
            return ('yaml', 'Ansible')
        else:
            return ('yaml', 'Infrastructure Config')
    
    def get_prompt(self, filepath: str, code: str) -> str:
        lang, iac_type = self.get_iac_type(filepath)
        return self.PROMPT_TEMPLATE.format(
            filepath=filepath,
            iac_type=iac_type,
            lang=lang,
            code=code[:15000]
        )
