package com.example.config;

/**
 * Application Configuration
 * Contains intentional security vulnerabilities for compliance demo
 */
public class AppConfig {

    // ============================================
    // CRITICAL: Hardcoded secrets
    // ============================================
    
    // Database credentials
    public static final String DB_HOST = "prod-db.company.com";
    public static final String DB_USER = "admin";
    public static final String DB_PASSWORD = "Pr0duct10n_P@ssw0rd!";
    
    // API Keys
    public static final String STRIPE_SECRET_KEY = "sk_live_1234567890abcdefghij";
    public static final String SENDGRID_API_KEY = "SG.abcdefghijklmnopqrstuvwxyz";
    public static final String TWILIO_AUTH_TOKEN = "your_auth_token_here_12345";
    
    // Encryption keys
    public static final String AES_SECRET_KEY = "MySecretEncryptionKey123";
    public static final String JWT_SIGNING_KEY = "jwt-secret-do-not-share";
    
    // Cloud credentials
    public static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    public static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    
    
    // ============================================
    // MEDIUM: Debug and development settings
    // ============================================
    
    public static final boolean DEBUG = true;
    public static final boolean ENABLE_STACK_TRACES = true;
    public static final boolean VERBOSE_SQL_LOGGING = true;
    
    // MEDIUM: HTTP endpoints (should be HTTPS)
    public static final String API_BASE_URL = "http://api.company.com";
    public static final String WEBHOOK_ENDPOINT = "http://webhooks.company.com/receive";
    public static final String METRICS_SERVER = "http://metrics.internal.com:9090";
    
    
    // ============================================
    // LOW: Development notes
    // ============================================
    
    // TODO: Move all secrets to environment variables
    // TODO: Implement secrets manager integration
    // FIXME: Remove hardcoded credentials before production
    // TODO: Add SSL certificate validation
}
