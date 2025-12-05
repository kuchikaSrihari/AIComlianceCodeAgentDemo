package com.example.auth;

import java.sql.*;
import java.security.MessageDigest;
import javax.servlet.http.*;

/**
 * User Authentication Service
 * 
 * TEST SCENARIO: AI should detect context-aware vulnerabilities
 * - SQL Injection in login
 * - Weak password hashing (MD5)
 * - Hardcoded credentials
 * - Missing authentication checks
 */
public class UserAuthService {
    
    // VULNERABILITY: Hardcoded database credentials (CWE-798)
    // AI CONTEXT TEST: Should detect this as hardcoded, not env var reference
    private static final String DB_URL = "jdbc:mysql://prod-db.company.com:3306/users";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "Pr0d_P@ssw0rd_2024!";
    
    // VULNERABILITY: Hardcoded API key
    private static final String PAYMENT_API_KEY = "sk_test_FAKE_KEY_FOR_TESTING_12345";
    
    /**
     * VULNERABILITY: SQL Injection (CWE-89, OWASP A03)
     * AI CONTEXT TEST: Should understand string concatenation = injection risk
     */
    public User authenticateUser(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        
        // CRITICAL: SQL Injection - user input directly concatenated
        String query = "SELECT * FROM users WHERE username = '" + username + 
                       "' AND password = '" + password + "'";
        
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        if (rs.next()) {
            return new User(rs.getString("username"), rs.getString("email"));
        }
        return null;
    }
    
    /**
     * VULNERABILITY: Weak cryptography (CWE-327, OWASP A02)
     * AI CONTEXT TEST: Should flag MD5 as weak for password hashing
     */
    public String hashPassword(String password) throws Exception {
        // CRITICAL: MD5 is cryptographically broken for passwords
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
    
    /**
     * VULNERABILITY: Missing authentication check (CWE-306, OWASP A07)
     * AI CONTEXT TEST: Should detect admin function without auth verification
     */
    public void deleteUser(HttpServletRequest request, String userId) throws SQLException {
        // CRITICAL: No authentication check before admin operation
        // Should verify: request.getSession().getAttribute("isAdmin")
        
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        String query = "DELETE FROM users WHERE id = '" + userId + "'";  // Also SQL injection!
        conn.createStatement().executeUpdate(query);
    }
    
    /**
     * VULNERABILITY: Sensitive data in logs (CWE-532, OWASP A09)
     */
    public void logLoginAttempt(String username, String password, boolean success) {
        // CRITICAL: Logging password in plain text
        System.out.println("Login attempt: user=" + username + ", password=" + password + ", success=" + success);
    }
}

class User {
    private String username;
    private String email;
    
    public User(String username, String email) {
        this.username = username;
        this.email = email;
    }
}
