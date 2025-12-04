# Test file with intentional vulnerabilities for AI Compliance Scanner

import os
import hashlib
import pickle

# CRITICAL: Hardcoded credentials
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# CRITICAL: SQL Injection vulnerability
def get_user(user_id):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: string concatenation
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    return cursor.fetchone()

# CRITICAL: Command injection
def run_backup(filename):
    os.system("tar -czf backup.tar.gz " + filename)  # Dangerous!

# HIGH: Weak cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is weak!

# HIGH: Insecure deserialization
def load_user_data(data):
    return pickle.loads(data)  # Pickle is unsafe!

# MEDIUM: Debug mode enabled
DEBUG = True

# MEDIUM: Insecure HTTP
API_URL = "http://api.example.com/data"

# LOW: TODO comment
# TODO: Add proper authentication later

if __name__ == "__main__":
    print("This file contains intentional vulnerabilities for testing")
