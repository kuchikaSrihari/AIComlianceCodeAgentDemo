# User Authentication Module
# This file contains intentional security issues for demo purposes

import os
import hashlib
import pickle
import sqlite3

# ============================================
# CRITICAL ISSUES - Will BLOCK the PR
# ============================================

# CRITICAL: Hardcoded credentials
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "sk-proj-1234567890abcdefghijklmnop"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def authenticate_user(username, password):
    """Authenticate user - VULNERABLE TO SQL INJECTION"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # CRITICAL: SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    
    return cursor.fetchone() is not None

def run_system_command(user_input):
    """Execute command - VULNERABLE TO COMMAND INJECTION"""
    # CRITICAL: Command injection
    os.system(f"echo {user_input}")
    
def load_user_session(session_data):
    """Load session - VULNERABLE TO INSECURE DESERIALIZATION"""
    # HIGH: Insecure deserialization
    return pickle.loads(session_data)

def hash_password(password):
    """Hash password - USING WEAK ALGORITHM"""
    # HIGH: Weak cryptographic hash
    return hashlib.md5(password.encode()).hexdigest()


# ============================================
# MEDIUM ISSUES - Will show as SUGGESTIONS
# ============================================

# MEDIUM: Debug mode enabled in production
DEBUG = True
VERBOSE_LOGGING = True

def fetch_data(url):
    """Fetch data - USING HTTP"""
    # MEDIUM: Unencrypted HTTP
    import requests
    return requests.get(f"http://api.example.com/{url}")

# MEDIUM: Missing proper logging
def process_payment(amount):
    # No audit logging for sensitive operation
    return {"status": "processed", "amount": amount}


# ============================================
# LOW ISSUES - Informational only
# ============================================

# TODO: Add proper input validation
# FIXME: This needs security review
def validate_input(data):
    return data  # Placeholder
