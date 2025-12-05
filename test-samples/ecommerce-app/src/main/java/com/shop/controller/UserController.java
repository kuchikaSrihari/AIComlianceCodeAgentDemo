package com.shop.controller;

import com.shop.service.UserService;
import com.shop.model.User;
import org.springframework.web.bind.annotation.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.http.*;

/**
 * E-Commerce Application - User Registration & Login Flow
 * 
 * FLOW: User Registration → Email Verification → Login → Session Management
 * 
 * This demonstrates how vulnerabilities chain together in a real application flow.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    private static final Logger logger = LogManager.getLogger(UserController.class);
    
    // VULNERABILITY 1: Hardcoded JWT secret (CWE-798)
    // FLOW IMPACT: Compromises ALL user sessions
    private static final String JWT_SECRET = "ecommerce-jwt-secret-key-2024";
    
    private final UserService userService;
    
    public UserController(UserService userService) {
        this.userService = userService;
    }
    
    /**
     * STEP 1: User Registration
     * VULNERABILITY: Log4j JNDI Injection (CVE-2021-44228)
     * FLOW IMPACT: RCE at the very first step of user journey
     */
    @PostMapping("/register")
    public ResponseEntity<User> registerUser(@RequestBody RegistrationRequest request) {
        // CRITICAL: User-Agent header logged - Log4Shell vulnerability!
        String userAgent = request.getUserAgent();
        logger.info("New registration from: " + userAgent);  // JNDI injection point!
        
        // VULNERABILITY 2: No input validation
        // FLOW IMPACT: Malicious data enters the system from the start
        User user = userService.createUser(
            request.getEmail(),
            request.getPassword(),
            request.getName()
        );
        
        // VULNERABILITY 3: Sensitive data in response
        // Returns password hash and internal IDs
        return ResponseEntity.ok(user);
    }
    
    /**
     * STEP 2: Email Verification
     * VULNERABILITY: Insecure Direct Object Reference (CWE-639)
     * FLOW IMPACT: Attacker can verify any account
     */
    @GetMapping("/verify")
    public ResponseEntity<String> verifyEmail(@RequestParam String token, 
                                               @RequestParam String userId) {
        // CRITICAL: No validation that token belongs to userId
        // Attacker can verify any account with any valid token
        userService.verifyUser(userId);
        
        logger.info("User verified: " + userId);  // Also Log4Shell if userId is controlled
        return ResponseEntity.ok("Email verified");
    }
    
    /**
     * STEP 3: User Login
     * VULNERABILITY: SQL Injection (CWE-89)
     * FLOW IMPACT: Authentication bypass, access to all accounts
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request,
                                                HttpServletResponse response) {
        // CRITICAL: SQL Injection in authentication
        User user = userService.authenticateUser(request.getEmail(), request.getPassword());
        
        if (user != null) {
            // VULNERABILITY 4: Weak session management
            String token = generateWeakToken(user);
            
            // VULNERABILITY 5: Insecure cookie settings
            Cookie sessionCookie = new Cookie("session", token);
            sessionCookie.setHttpOnly(false);  // XSS can steal cookie
            sessionCookie.setSecure(false);    // Sent over HTTP
            sessionCookie.setMaxAge(60 * 60 * 24 * 30);  // 30 days - too long!
            response.addCookie(sessionCookie);
            
            // VULNERABILITY 6: Logging sensitive data
            logger.info("Login successful: email=" + request.getEmail() + 
                       ", password=" + request.getPassword());  // CRITICAL!
            
            return ResponseEntity.ok(new LoginResponse(token, user));
        }
        
        // VULNERABILITY 7: User enumeration
        return ResponseEntity.status(401).body(
            new LoginResponse(null, "Invalid password for " + request.getEmail())
        );
    }
    
    /**
     * STEP 4: Password Reset
     * VULNERABILITY: Weak token generation (CWE-330)
     * FLOW IMPACT: Predictable reset tokens = account takeover
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        // CRITICAL: No rate limiting - brute force possible
        
        // VULNERABILITY 8: Weak random for security token
        String resetToken = String.valueOf(System.currentTimeMillis());  // Predictable!
        
        userService.saveResetToken(request.getEmail(), resetToken);
        
        // VULNERABILITY 9: Token in URL (will be logged, cached, in referrer)
        String resetLink = "https://shop.com/reset?token=" + resetToken + 
                          "&email=" + request.getEmail();
        
        return ResponseEntity.ok("Reset link sent");
    }
    
    /**
     * STEP 5: Update Profile
     * VULNERABILITY: Mass Assignment (CWE-915)
     * FLOW IMPACT: User can elevate to admin
     */
    @PutMapping("/profile")
    public ResponseEntity<User> updateProfile(@RequestBody User userUpdate,
                                               HttpServletRequest request) {
        String userId = (String) request.getAttribute("userId");
        
        // CRITICAL: Mass assignment - user can set ANY field including "role"
        // Attacker sends: {"name": "Hacker", "role": "ADMIN", "verified": true}
        User updated = userService.updateUser(userId, userUpdate);
        
        return ResponseEntity.ok(updated);
    }
    
    // Weak token generation
    private String generateWeakToken(User user) {
        // CRITICAL: Predictable token using timestamp and user ID
        return user.getId() + "-" + System.currentTimeMillis();
    }
}

// Request/Response DTOs
class RegistrationRequest {
    private String email;
    private String password;
    private String name;
    private String userAgent;
    // getters and setters
    public String getEmail() { return email; }
    public String getPassword() { return password; }
    public String getName() { return name; }
    public String getUserAgent() { return userAgent; }
}

class LoginRequest {
    private String email;
    private String password;
    public String getEmail() { return email; }
    public String getPassword() { return password; }
}

class ForgotPasswordRequest {
    private String email;
    public String getEmail() { return email; }
}

class LoginResponse {
    private String token;
    private Object data;
    public LoginResponse(String token, Object data) {
        this.token = token;
        this.data = data;
    }
}
