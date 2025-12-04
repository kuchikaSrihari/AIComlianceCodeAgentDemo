package com.example;

import java.sql.*;
import java.io.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * INTENTIONALLY VULNERABLE CODE FOR TESTING
 * DO NOT USE IN PRODUCTION
 */
public class VulnerableCode {
    
    // CVE-2021-44228: Log4j JNDI Injection
    private static final Logger logger = LogManager.getLogger(VulnerableCode.class);
    
    // CRY-03: Hardcoded credentials
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_KEY = "sk-1234567890abcdef";
    
    // TDA-02: SQL Injection vulnerability
    public User findUser(String username) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // VULNERABLE: Direct string concatenation
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
        return null;
    }
    
    // CVE-2021-44228: Log4j vulnerability - user input in log
    public void processRequest(String userInput) {
        // VULNERABLE: User input logged directly - enables JNDI injection
        logger.info("Processing request: " + userInput);
        logger.error("User provided: {}", userInput);
    }
    
    // CWE-611: XXE Vulnerability
    public void parseXml(String xmlData) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // VULNERABLE: XXE not disabled
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new InputSource(new StringReader(xmlData)));
    }
    
    // CWE-502: Unsafe Deserialization
    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        // VULNERABLE: Deserializing untrusted data
        return ois.readObject();
    }
    
    // TDA-02: Command Injection
    public void runCommand(String userCommand) throws IOException {
        // VULNERABLE: Direct command execution with user input
        Runtime.getRuntime().exec("cmd /c " + userCommand);
    }
    
    // CWE-22: Path Traversal
    public String readFile(String filename) throws IOException {
        // VULNERABLE: No path validation
        File file = new File("/data/" + filename);
        return new String(java.nio.file.Files.readAllBytes(file.toPath()));
    }
    
    // CRY-01: Weak cryptography
    public String hashPassword(String password) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        // VULNERABLE: MD5 is cryptographically broken
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }
    
    // IAC-01: Overly permissive - returns all data
    public void grantAccess() {
        // VULNERABLE: Wildcard permissions
        String policy = "{\"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}";
    }
}
