package com.example.api;

import java.sql.*;
import java.security.MessageDigest;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

/**
 * API Controller
 * Contains intentional security vulnerabilities for compliance demo
 */
public class ApiController {

    // CRITICAL: Hardcoded API secrets
    private static final String JWT_SECRET = "my-jwt-signing-secret-key";
    private static final String ENCRYPTION_KEY = "aes-256-encryption-key-here";
    private static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    
    private Connection dbConnection;
    
    // CRITICAL: SQL Injection in user lookup
    public String getUserById(String userId) throws SQLException {
        // Vulnerable: Direct concatenation
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = dbConnection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return rs.getString("name");
    }
    
    // CRITICAL: SQL Injection in search
    public void searchUsers(String searchTerm) throws SQLException {
        // Vulnerable: User input in LIKE clause
        String query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
        Statement stmt = dbConnection.createStatement();
        stmt.executeQuery(query);
    }
    
    // CRITICAL: Code injection via ScriptEngine
    public Object evaluateExpression(String expression) {
        try {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            // CRITICAL: Evaluating user input
            return engine.eval(expression);
        } catch (Exception e) {
            return null;
        }
    }
    
    // HIGH: Weak hash for sensitive data
    public String hashSensitiveData(String data) {
        try {
            // HIGH: MD5 is cryptographically broken
            MessageDigest md = MessageDigest.getInstance("MD5");
            return bytesToHex(md.digest(data.getBytes()));
        } catch (Exception e) {
            return null;
        }
    }
    
    // MEDIUM: Debug configuration
    public static final boolean DEBUG_MODE = true;
    
    // MEDIUM: Insecure HTTP endpoints
    private static final String PAYMENT_API = "http://payment.internal.com/process";
    private static final String NOTIFICATION_URL = "http://notify.example.com/send";
    
    // TODO: Implement proper authentication
    // FIXME: Add request validation
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
