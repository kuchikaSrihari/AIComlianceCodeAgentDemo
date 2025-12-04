package com.example.test;

import java.sql.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Test file with intentional vulnerabilities for AI Compliance Scanner testing.
 * DO NOT USE IN PRODUCTION - This is for demonstration purposes only.
 */
public class VulnerableService {

    // CRITICAL: Hardcoded credentials - violates CRY-03, CC6.1
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
    private static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    
    // CRITICAL: SQL Injection vulnerability - violates APP-05, CC6.1
    public User getUserById(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/users", "admin", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        
        // Vulnerable: String concatenation in SQL query
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
        
        return parseUser(rs);
    }
    
    // CRITICAL: Command Injection - violates APP-05, CC6.1
    public void backupDatabase(String filename) throws IOException {
        // Vulnerable: User input directly in command
        Runtime.getRuntime().exec("mysqldump -u admin -p" + DB_PASSWORD + " db > " + filename);
    }
    
    // HIGH: Weak cryptography (MD5) - violates CRY-01, CC6.1
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");  // MD5 is cryptographically broken
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    // HIGH: Weak cryptography (DES) - violates CRY-01
    public byte[] encryptData(String data) throws Exception {
        // DES is deprecated and insecure
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec("12345678".getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }
    
    // HIGH: Insecure deserialization - violates APP-05
    public Object loadUserSession(byte[] data) throws Exception {
        // Deserializing untrusted data is dangerous
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();  // Can lead to RCE
    }
    
    // MEDIUM: Debug mode enabled - violates OPS-01
    private static final boolean DEBUG_MODE = true;
    
    // MEDIUM: Insecure HTTP endpoint - violates NET-03
    private static final String API_ENDPOINT = "http://api.example.com/sensitive-data";
    
    // MEDIUM: Hardcoded IP address - violates NET-01
    private static final String DATABASE_HOST = "192.168.1.100";
    
    // LOW: TODO comment indicating incomplete security
    // TODO: Add proper input validation and authentication
    
    // LOW: Empty catch block - poor error handling
    public void processPayment(String cardNumber) {
        try {
            // Process payment
            System.out.println("Processing: " + cardNumber);  // Logging sensitive data!
        } catch (Exception e) {
            // Swallowing exception - bad practice
        }
    }
    
    private User parseUser(ResultSet rs) {
        return null; // Stub
    }
    
    class User {
        String id;
        String name;
    }
}
