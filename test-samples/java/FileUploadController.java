package com.example.upload;

import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

/**
 * File Upload Controller
 * 
 * TEST SCENARIO: AI should detect file handling vulnerabilities
 * - Path Traversal
 * - XXE (XML External Entity)
 * - Command Injection
 * - Unrestricted File Upload
 */
public class FileUploadController {
    
    private static final String UPLOAD_DIR = "/var/uploads/";
    
    /**
     * VULNERABILITY: Path Traversal (CWE-22, OWASP A01)
     * AI CONTEXT TEST: Should detect "../" manipulation possibility
     */
    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("file");
        
        // CRITICAL: No validation - attacker can use ../../etc/passwd
        File file = new File(UPLOAD_DIR + filename);
        
        FileInputStream fis = new FileInputStream(file);
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            response.getOutputStream().write(buffer, 0, bytesRead);
        }
        fis.close();
    }
    
    /**
     * VULNERABILITY: XXE - XML External Entity (CVE-2014-3529, CWE-611)
     * AI CONTEXT TEST: Should detect unsafe XML parsing configuration
     */
    public Document parseXmlUpload(InputStream xmlInput) throws Exception {
        // CRITICAL: Default DocumentBuilder is vulnerable to XXE
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Missing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(xmlInput);  // XXE vulnerability!
    }
    
    /**
     * VULNERABILITY: Command Injection (CWE-78, OWASP A03)
     * AI CONTEXT TEST: Should detect user input in system command
     */
    public void convertImage(String uploadedFile, String format) throws IOException {
        // CRITICAL: User-controlled input in shell command
        String command = "convert " + uploadedFile + " -format " + format + " output.png";
        
        // Attacker can inject: "; rm -rf /" or "| cat /etc/passwd"
        Runtime.getRuntime().exec(command);
    }
    
    /**
     * VULNERABILITY: Unrestricted File Upload (CWE-434, OWASP A04)
     * AI CONTEXT TEST: Should detect missing file type validation
     */
    public String uploadFile(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        
        // CRITICAL: No validation of file extension or content type
        // Attacker can upload malicious.jsp or shell.php
        
        Path destination = Paths.get(UPLOAD_DIR, fileName);
        Files.copy(filePart.getInputStream(), destination);
        
        return "File uploaded: " + fileName;
    }
    
    /**
     * VULNERABILITY: SSRF - Server Side Request Forgery (CWE-918, OWASP A10)
     * AI CONTEXT TEST: Should detect unvalidated URL in server request
     */
    public String fetchRemoteFile(String url) throws IOException {
        // CRITICAL: User-controlled URL - can access internal services
        // Attacker can use: http://169.254.169.254/latest/meta-data/ (AWS metadata)
        // Or: http://localhost:8080/admin/delete-all
        
        java.net.URL remoteUrl = new java.net.URL(url);
        BufferedReader reader = new BufferedReader(new InputStreamReader(remoteUrl.openStream()));
        
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        return content.toString();
    }
}
