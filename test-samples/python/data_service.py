"""
Data Service Module

TEST SCENARIO: AI should detect Python-specific vulnerabilities
- Pickle deserialization (RCE)
- eval() injection
- YAML unsafe load
- SQL injection with f-strings
- Hardcoded secrets
"""

import pickle
import yaml
import sqlite3
import subprocess
import os

# VULNERABILITY: Hardcoded credentials (CWE-798)
# AI CONTEXT TEST: Should distinguish from environment variable usage
DATABASE_PASSWORD = "super_secret_db_pass_123"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "my-super-secret-jwt-key-do-not-share"


class DataService:
    """Service for handling data operations with multiple vulnerabilities."""
    
    def __init__(self):
        # VULNERABILITY: Hardcoded connection string
        self.db_url = f"postgresql://admin:{DATABASE_PASSWORD}@prod-db.internal:5432/app"
    
    def get_user_data(self, user_id: str) -> dict:
        """
        VULNERABILITY: SQL Injection with f-string (CWE-89)
        AI CONTEXT TEST: Should detect f-string SQL as injection risk
        """
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        # CRITICAL: User input in f-string SQL query
        query = f"SELECT * FROM users WHERE id = '{user_id}'"
        cursor.execute(query)
        
        return cursor.fetchone()
    
    def load_user_session(self, session_data: bytes) -> object:
        """
        VULNERABILITY: Unsafe Pickle Deserialization (CWE-502)
        AI CONTEXT TEST: Should flag pickle.loads as critical RCE risk
        """
        # CRITICAL: Pickle can execute arbitrary code during deserialization
        # Attacker can craft malicious pickle payload for RCE
        return pickle.loads(session_data)
    
    def load_config(self, yaml_content: str) -> dict:
        """
        VULNERABILITY: Unsafe YAML Load (CVE-2020-14343)
        AI CONTEXT TEST: Should detect yaml.load without SafeLoader
        """
        # CRITICAL: yaml.load can execute arbitrary Python code
        # Should use: yaml.safe_load(yaml_content)
        return yaml.load(yaml_content)  # Vulnerable!
    
    def calculate_formula(self, user_formula: str) -> float:
        """
        VULNERABILITY: eval() Injection (CWE-94)
        AI CONTEXT TEST: Should detect eval with user input as critical
        """
        # CRITICAL: eval() executes arbitrary Python code
        # Attacker can inject: __import__('os').system('rm -rf /')
        return eval(user_formula)
    
    def run_report(self, report_name: str) -> str:
        """
        VULNERABILITY: Command Injection (CWE-78)
        AI CONTEXT TEST: Should detect shell=True with user input
        """
        # CRITICAL: User input in shell command
        command = f"python generate_report.py --name {report_name}"
        
        # shell=True makes this exploitable
        result = subprocess.run(command, shell=True, capture_output=True)
        return result.stdout.decode()
    
    def get_file_content(self, filename: str) -> str:
        """
        VULNERABILITY: Path Traversal (CWE-22)
        AI CONTEXT TEST: Should detect unvalidated file path
        """
        # CRITICAL: No validation - attacker can use ../../../etc/passwd
        base_path = "/app/data/"
        file_path = base_path + filename  # No sanitization!
        
        with open(file_path, 'r') as f:
            return f.read()


# VULNERABILITY: Sensitive data in exception (CWE-209)
def connect_to_database():
    """AI CONTEXT TEST: Should detect credentials in error message."""
    try:
        # Connection attempt
        pass
    except Exception as e:
        # CRITICAL: Exposing credentials in error message
        raise Exception(f"Failed to connect with password: {DATABASE_PASSWORD}")


# VULNERABILITY: Insecure random for security (CWE-330)
import random

def generate_reset_token() -> str:
    """AI CONTEXT TEST: Should detect weak random for security token."""
    # CRITICAL: random module is not cryptographically secure
    # Should use: secrets.token_urlsafe()
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
