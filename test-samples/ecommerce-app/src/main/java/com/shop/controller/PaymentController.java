package com.shop.controller;

import com.shop.service.PaymentService;
import com.shop.model.*;
import org.springframework.web.bind.annotation.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * E-Commerce Application - Payment Processing Flow
 * 
 * FLOW: Enter Payment → Validate Card → Process Payment → Send Receipt
 * 
 * Demonstrates PCI-DSS violations and payment security issues.
 * This is the most critical flow - handles real money and card data.
 */
@RestController
@RequestMapping("/api/payments")
public class PaymentController {
    
    private static final Logger logger = LogManager.getLogger(PaymentController.class);
    
    // VULNERABILITY: Hardcoded encryption key (CWE-321)
    // PCI-DSS VIOLATION: Encryption keys must be securely managed
    private static final String ENCRYPTION_KEY = "PCI-DSS-Key-1234";
    
    // VULNERABILITY: Hardcoded payment gateway credentials
    private static final String STRIPE_SECRET_KEY = "sk_test_FAKE_KEY_FOR_TESTING_12345";
    private static final String STRIPE_WEBHOOK_SECRET = "whsec_test_secret_123";
    
    private final PaymentService paymentService;
    
    public PaymentController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }
    
    /**
     * STEP 1: Submit Payment
     * VULNERABILITY: PCI-DSS Violation - Logging card data (Req 3.2)
     * FLOW IMPACT: Card data exposed in logs, compliance failure
     */
    @PostMapping("/process")
    public ResponseEntity<PaymentResult> processPayment(@RequestBody PaymentRequest request) {
        
        // CRITICAL PCI-DSS VIOLATION: Logging full card number and CVV
        logger.info("Processing payment: card=" + request.getCardNumber() + 
                   ", cvv=" + request.getCvv() + 
                   ", expiry=" + request.getExpiry() +
                   ", amount=" + request.getAmount());
        
        // VULNERABILITY: Log4Shell in user-controlled field
        logger.info("Customer name: " + request.getCardholderName());  // JNDI injection!
        
        try {
            // VULNERABILITY: Weak card validation
            if (!isValidCard(request.getCardNumber())) {
                return ResponseEntity.badRequest().body(
                    new PaymentResult("FAILED", "Invalid card")
                );
            }
            
            // Process the payment
            String transactionId = paymentService.charge(
                request.getCardNumber(),
                request.getCvv(),
                request.getAmount()
            );
            
            // VULNERABILITY: Storing full card number (PCI-DSS Req 3.4)
            saveTransactionLog(request, transactionId);
            
            return ResponseEntity.ok(new PaymentResult("SUCCESS", transactionId));
            
        } catch (Exception e) {
            // VULNERABILITY: Exposing internal errors
            return ResponseEntity.status(500).body(
                new PaymentResult("ERROR", e.getMessage() + "\n" + e.getStackTrace()[0])
            );
        }
    }
    
    /**
     * STEP 2: Encrypt Card Data
     * VULNERABILITY: Weak Cryptography (CWE-327)
     * PCI-DSS VIOLATION: Must use strong encryption (AES-256, not ECB mode)
     */
    private byte[] encryptCardData(String cardNumber) throws Exception {
        // CRITICAL: Using weak encryption
        // 1. ECB mode is insecure (patterns visible)
        // 2. Hardcoded key
        // 3. No IV/nonce
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // ECB is weak!
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        return cipher.doFinal(cardNumber.getBytes());
    }
    
    /**
     * STEP 3: Hash Card for Storage
     * VULNERABILITY: Weak Hashing (CWE-328)
     * FLOW IMPACT: Card numbers can be reversed from hashes
     */
    private String hashCardNumber(String cardNumber) throws Exception {
        // CRITICAL: MD5 is cryptographically broken
        // Card numbers have low entropy - can be brute-forced
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(cardNumber.getBytes());
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
    
    /**
     * STEP 4: Store Transaction
     * VULNERABILITY: PCI-DSS Violation - Storing CVV (Req 3.2.2)
     * FLOW IMPACT: Compliance failure, massive fines
     */
    private void saveTransactionLog(PaymentRequest request, String transactionId) {
        // CRITICAL PCI-DSS VIOLATION: Never store CVV after authorization
        String logEntry = String.format(
            "Transaction: %s, Card: %s, CVV: %s, Amount: %.2f",
            transactionId,
            request.getCardNumber(),  // Should be masked: **** **** **** 1234
            request.getCvv(),         // NEVER store CVV!
            request.getAmount()
        );
        
        // Writing to file - even worse!
        try {
            java.io.FileWriter fw = new java.io.FileWriter("transactions.log", true);
            fw.write(logEntry + "\n");
            fw.close();
        } catch (Exception e) {
            logger.error("Failed to log transaction", e);
        }
    }
    
    /**
     * STEP 5: Refund Payment
     * VULNERABILITY: Missing Authorization (CWE-862)
     * FLOW IMPACT: Anyone can refund any transaction
     */
    @PostMapping("/refund")
    public ResponseEntity<PaymentResult> refundPayment(@RequestBody RefundRequest request) {
        // CRITICAL: No authorization check
        // Any user can refund any transaction by knowing the ID
        
        String refundId = paymentService.refund(
            request.getTransactionId(),
            request.getAmount()
        );
        
        // VULNERABILITY: Logging refund with sensitive data
        logger.info("Refund processed: txn=" + request.getTransactionId() + 
                   ", amount=" + request.getAmount() +
                   ", card=" + request.getOriginalCard());  // Logging card again!
        
        return ResponseEntity.ok(new PaymentResult("REFUNDED", refundId));
    }
    
    /**
     * STEP 6: Payment Webhook (from Stripe)
     * VULNERABILITY: Missing Signature Verification (CWE-347)
     * FLOW IMPACT: Attacker can fake payment confirmations
     */
    @PostMapping("/webhook")
    public ResponseEntity<String> handleWebhook(@RequestBody String payload,
                                                 @RequestHeader("Stripe-Signature") String signature) {
        // CRITICAL: Not verifying webhook signature
        // Attacker can send fake "payment_succeeded" events
        
        // Should verify: Stripe.Webhook.constructEvent(payload, signature, WEBHOOK_SECRET)
        // But we're just trusting the payload!
        
        WebhookEvent event = parseWebhook(payload);
        
        if ("payment_intent.succeeded".equals(event.getType())) {
            // Marking order as paid without verification!
            paymentService.markOrderPaid(event.getOrderId());
        }
        
        return ResponseEntity.ok("Received");
    }
    
    /**
     * STEP 7: Send Receipt via HTTP
     * VULNERABILITY: Insecure Transmission (CWE-319)
     * PCI-DSS VIOLATION: Card data must be encrypted in transit
     */
    @PostMapping("/send-receipt")
    public ResponseEntity<String> sendReceipt(@RequestBody ReceiptRequest request) {
        try {
            // CRITICAL: Using HTTP instead of HTTPS for payment data
            java.net.URL url = new java.net.URL(
                "http://receipt-service.internal/send"  // HTTP, not HTTPS!
            );
            
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            
            // Sending card data over unencrypted connection
            String receiptData = "card=" + request.getMaskedCard() + 
                                "&amount=" + request.getAmount();
            conn.getOutputStream().write(receiptData.getBytes());
            
            return ResponseEntity.ok("Receipt sent");
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Failed to send receipt");
        }
    }
    
    // Simple card validation (also flawed)
    private boolean isValidCard(String cardNumber) {
        // VULNERABILITY: Weak validation - only checks length
        return cardNumber != null && cardNumber.length() >= 13;
    }
    
    private WebhookEvent parseWebhook(String payload) {
        // Simplified parsing
        return new WebhookEvent();
    }
}

// DTOs
class PaymentRequest {
    private String cardNumber;
    private String cvv;
    private String expiry;
    private String cardholderName;
    private double amount;
    
    public String getCardNumber() { return cardNumber; }
    public String getCvv() { return cvv; }
    public String getExpiry() { return expiry; }
    public String getCardholderName() { return cardholderName; }
    public double getAmount() { return amount; }
}

class PaymentResult {
    private String status;
    private String message;
    
    public PaymentResult(String status, String message) {
        this.status = status;
        this.message = message;
    }
}

class RefundRequest {
    private String transactionId;
    private double amount;
    private String originalCard;
    
    public String getTransactionId() { return transactionId; }
    public double getAmount() { return amount; }
    public String getOriginalCard() { return originalCard; }
}

class ReceiptRequest {
    private String maskedCard;
    private double amount;
    
    public String getMaskedCard() { return maskedCard; }
    public double getAmount() { return amount; }
}

class WebhookEvent {
    private String type;
    private String orderId;
    
    public String getType() { return type; }
    public String getOrderId() { return orderId; }
}
