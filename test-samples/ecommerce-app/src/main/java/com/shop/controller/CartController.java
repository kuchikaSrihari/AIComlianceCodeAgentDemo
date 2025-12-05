package com.shop.controller;

import com.shop.service.CartService;
import com.shop.model.*;
import org.springframework.web.bind.annotation.*;
import java.io.*;

/**
 * E-Commerce Application - Shopping Cart Flow
 * 
 * FLOW: Add to Cart → Update Quantity → Apply Coupon → View Cart
 * 
 * Demonstrates business logic vulnerabilities in the shopping flow.
 */
@RestController
@RequestMapping("/api/cart")
public class CartController {
    
    private final CartService cartService;
    
    public CartController(CartService cartService) {
        this.cartService = cartService;
    }
    
    /**
     * STEP 1: Add Item to Cart
     * VULNERABILITY: Insecure Direct Object Reference (CWE-639)
     * FLOW IMPACT: Add items to other users' carts, manipulate their orders
     */
    @PostMapping("/{cartId}/items")
    public ResponseEntity<Cart> addToCart(@PathVariable String cartId,
                                          @RequestBody CartItemRequest request) {
        // CRITICAL: No authorization check
        // Any user can add items to any cart by guessing cartId
        
        Cart cart = cartService.addItem(cartId, request.getProductId(), request.getQuantity());
        
        return ResponseEntity.ok(cart);
    }
    
    /**
     * STEP 2: Update Cart Item Quantity
     * VULNERABILITY: Business Logic Flaw - Negative Quantity (CWE-840)
     * FLOW IMPACT: Negative prices, free products, money generation
     */
    @PutMapping("/{cartId}/items/{itemId}")
    public ResponseEntity<Cart> updateQuantity(@PathVariable String cartId,
                                                @PathVariable String itemId,
                                                @RequestBody QuantityUpdate update) {
        // CRITICAL: No validation of quantity
        // Attacker sends quantity: -10
        // Result: Negative total, or credit to account
        
        int quantity = update.getQuantity();  // Could be negative!
        
        Cart cart = cartService.updateItemQuantity(cartId, itemId, quantity);
        
        return ResponseEntity.ok(cart);
    }
    
    /**
     * STEP 3: Apply Coupon Code
     * VULNERABILITY: Race Condition (CWE-362)
     * FLOW IMPACT: Apply same coupon multiple times, unlimited discounts
     */
    @PostMapping("/{cartId}/coupon")
    public ResponseEntity<Cart> applyCoupon(@PathVariable String cartId,
                                            @RequestBody CouponRequest request) {
        // CRITICAL: Race condition - no locking
        // Attacker sends 100 parallel requests with same coupon
        // Coupon gets applied multiple times before "used" flag is set
        
        String couponCode = request.getCouponCode();
        
        // Check if coupon is valid (but no lock!)
        if (cartService.isCouponValid(couponCode)) {
            // Time gap here allows race condition
            Cart cart = cartService.applyCoupon(cartId, couponCode);
            cartService.markCouponUsed(couponCode);  // Too late!
            return ResponseEntity.ok(cart);
        }
        
        return ResponseEntity.badRequest().body(null);
    }
    
    /**
     * STEP 4: Price Manipulation
     * VULNERABILITY: Client-Side Price Trust (CWE-602)
     * FLOW IMPACT: Buy products at any price
     */
    @PostMapping("/{cartId}/checkout-preview")
    public ResponseEntity<CheckoutPreview> previewCheckout(
            @PathVariable String cartId,
            @RequestBody CheckoutRequest request) {
        
        // CRITICAL: Trusting client-provided price
        // Attacker intercepts request and changes price from 999.99 to 0.01
        double totalPrice = request.getTotalPrice();  // From client!
        
        CheckoutPreview preview = new CheckoutPreview();
        preview.setCartId(cartId);
        preview.setTotal(totalPrice);  // Using attacker-controlled price
        preview.setTax(totalPrice * 0.1);
        
        return ResponseEntity.ok(preview);
    }
    
    /**
     * STEP 5: Export Cart (Share with friend)
     * VULNERABILITY: Unsafe Deserialization (CWE-502)
     * FLOW IMPACT: Remote code execution when importing shared cart
     */
    @PostMapping("/import")
    public ResponseEntity<Cart> importSharedCart(@RequestBody byte[] cartData) {
        try {
            // CRITICAL: Deserializing untrusted data
            // Attacker creates malicious serialized object
            ByteArrayInputStream bis = new ByteArrayInputStream(cartData);
            ObjectInputStream ois = new ObjectInputStream(bis);
            
            Cart importedCart = (Cart) ois.readObject();  // RCE!
            
            return ResponseEntity.ok(importedCart);
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body(null);
        }
    }
    
    /**
     * STEP 6: Cart Analytics (Internal)
     * VULNERABILITY: SSRF - Server Side Request Forgery (CWE-918)
     * FLOW IMPACT: Access internal services, cloud metadata
     */
    @GetMapping("/analytics")
    public ResponseEntity<String> getAnalytics(@RequestParam String webhookUrl) {
        try {
            // CRITICAL: SSRF - attacker controls URL
            // webhookUrl: http://169.254.169.254/latest/meta-data/iam/security-credentials/
            // webhookUrl: http://internal-admin-panel:8080/delete-all-users
            
            java.net.URL url = new java.net.URL(webhookUrl);
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
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
}

// DTOs
class CartItemRequest {
    private String productId;
    private int quantity;
    public String getProductId() { return productId; }
    public int getQuantity() { return quantity; }
}

class QuantityUpdate {
    private int quantity;
    public int getQuantity() { return quantity; }
}

class CouponRequest {
    private String couponCode;
    public String getCouponCode() { return couponCode; }
}

class CheckoutRequest {
    private double totalPrice;
    public double getTotalPrice() { return totalPrice; }
}

class CheckoutPreview {
    private String cartId;
    private double total;
    private double tax;
    public void setCartId(String id) { this.cartId = id; }
    public void setTotal(double t) { this.total = t; }
    public void setTax(double t) { this.tax = t; }
}
