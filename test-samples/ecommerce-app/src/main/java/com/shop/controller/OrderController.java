package com.shop.controller;

import com.shop.service.OrderService;
import com.shop.model.*;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;

/**
 * E-Commerce Application - Order Management Flow
 * 
 * FLOW: Create Order → Track Order → Download Invoice → Admin Export
 * 
 * Demonstrates vulnerabilities in post-purchase operations.
 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    
    private final OrderService orderService;
    
    // VULNERABILITY: Hardcoded admin credentials
    private static final String ADMIN_API_KEY = "admin-secret-key-12345";
    
    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }
    
    /**
     * STEP 1: Create Order from Cart
     * VULNERABILITY: Race Condition in Inventory (CWE-362)
     * FLOW IMPACT: Overselling, negative inventory
     */
    @PostMapping("/create")
    public ResponseEntity<Order> createOrder(@RequestBody CreateOrderRequest request) {
        // CRITICAL: Race condition - no inventory locking
        // 100 users buy the last item simultaneously
        // All 100 orders succeed, inventory goes to -99
        
        // Check inventory (but no lock!)
        if (orderService.checkInventory(request.getProductId(), request.getQuantity())) {
            // Time gap allows race condition
            Order order = orderService.createOrder(request);
            orderService.decrementInventory(request.getProductId(), request.getQuantity());
            return ResponseEntity.ok(order);
        }
        
        return ResponseEntity.badRequest().body(null);
    }
    
    /**
     * STEP 2: Get Order Details
     * VULNERABILITY: Broken Access Control (CWE-639, OWASP A01)
     * FLOW IMPACT: View any customer's order, PII exposure
     */
    @GetMapping("/{orderId}")
    public ResponseEntity<Order> getOrder(@PathVariable String orderId) {
        // CRITICAL: No authorization check
        // Any user can view any order by guessing/enumerating orderId
        // Exposes: name, address, email, phone, order contents
        
        Order order = orderService.getOrder(orderId);
        
        // Returning ALL data including sensitive PII
        return ResponseEntity.ok(order);
    }
    
    /**
     * STEP 3: Track Order (External API)
     * VULNERABILITY: SSRF via tracking URL (CWE-918)
     * FLOW IMPACT: Access internal services, cloud metadata
     */
    @GetMapping("/{orderId}/track")
    public ResponseEntity<String> trackOrder(@PathVariable String orderId,
                                              @RequestParam String carrierUrl) {
        try {
            // CRITICAL: SSRF - user controls the URL
            // Attacker: carrierUrl=http://169.254.169.254/latest/meta-data/
            // Attacker: carrierUrl=http://internal-db:5432/
            
            java.net.URL url = new java.net.URL(carrierUrl + "?tracking=" + orderId);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream())
            );
            
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            
            return ResponseEntity.ok(response.toString());
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Tracking failed: " + e.getMessage());
        }
    }
    
    /**
     * STEP 4: Download Invoice
     * VULNERABILITY: Path Traversal (CWE-22)
     * FLOW IMPACT: Read any file on server
     */
    @GetMapping("/{orderId}/invoice")
    public ResponseEntity<byte[]> downloadInvoice(@PathVariable String orderId,
                                                   @RequestParam String format) {
        try {
            // CRITICAL: Path traversal
            // format: ../../../etc/passwd
            // format: ....//....//....//etc/passwd (bypass attempt)
            
            String invoicePath = "/var/invoices/" + orderId + "." + format;
            
            byte[] content = Files.readAllBytes(Paths.get(invoicePath));
            
            return ResponseEntity.ok(content);
            
        } catch (IOException e) {
            return ResponseEntity.status(404).body(null);
        }
    }
    
    /**
     * STEP 5: Update Shipping Address
     * VULNERABILITY: Mass Assignment (CWE-915)
     * FLOW IMPACT: Modify order status, price, or other users' orders
     */
    @PutMapping("/{orderId}")
    public ResponseEntity<Order> updateOrder(@PathVariable String orderId,
                                              @RequestBody Order orderUpdate) {
        // CRITICAL: Mass assignment vulnerability
        // Attacker sends: {"shippingAddress": "new address", "status": "SHIPPED", "totalPrice": 0.01}
        // All fields get updated including status and price!
        
        Order updated = orderService.updateOrder(orderId, orderUpdate);
        
        return ResponseEntity.ok(updated);
    }
    
    /**
     * STEP 6: Cancel Order
     * VULNERABILITY: Business Logic Flaw (CWE-840)
     * FLOW IMPACT: Cancel shipped orders, get refund + keep product
     */
    @PostMapping("/{orderId}/cancel")
    public ResponseEntity<String> cancelOrder(@PathVariable String orderId) {
        // CRITICAL: No status check before cancellation
        // User can cancel order AFTER it's shipped
        // Gets refund but keeps the product
        
        Order order = orderService.getOrder(orderId);
        
        // Missing: if (order.getStatus() == "SHIPPED") { return error; }
        
        orderService.cancelOrder(orderId);
        orderService.processRefund(orderId);  // Automatic refund!
        
        return ResponseEntity.ok("Order cancelled and refunded");
    }
    
    /**
     * STEP 7: Admin Export (All Orders)
     * VULNERABILITY: Broken Authentication (CWE-287)
     * FLOW IMPACT: Export all customer data without proper auth
     */
    @GetMapping("/admin/export")
    public ResponseEntity<String> exportAllOrders(@RequestHeader("X-API-Key") String apiKey,
                                                   @RequestParam String format) {
        // CRITICAL: Weak API key comparison (timing attack vulnerable)
        // Also: hardcoded API key
        if (!apiKey.equals(ADMIN_API_KEY)) {
            return ResponseEntity.status(401).body("Unauthorized");
        }
        
        // VULNERABILITY: Command injection in export
        // format: csv; cat /etc/passwd
        try {
            String command = "python export_orders.py --format " + format;
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return ResponseEntity.ok(output.toString());
            
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Export failed");
        }
    }
    
    /**
     * STEP 8: Bulk Order Import
     * VULNERABILITY: XXE in order import (CWE-611)
     * FLOW IMPACT: File read, SSRF, DoS
     */
    @PostMapping("/admin/import")
    public ResponseEntity<String> importOrders(@RequestBody String xmlData) {
        try {
            // CRITICAL: XXE vulnerability
            javax.xml.parsers.DocumentBuilderFactory factory = 
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            // Missing secure configuration!
            
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(
                new ByteArrayInputStream(xmlData.getBytes())
            );
            
            int imported = orderService.importOrders(doc);
            
            return ResponseEntity.ok("Imported " + imported + " orders");
            
        } catch (Exception e) {
            // VULNERABILITY: Detailed error exposure
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return ResponseEntity.status(500).body("Error: " + sw.toString());
        }
    }
}

// DTOs
class CreateOrderRequest {
    private String productId;
    private int quantity;
    private String shippingAddress;
    
    public String getProductId() { return productId; }
    public int getQuantity() { return quantity; }
    public String getShippingAddress() { return shippingAddress; }
}
