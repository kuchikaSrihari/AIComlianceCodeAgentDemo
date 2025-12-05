/**
 * API Controller
 * 
 * TEST SCENARIO: AI should detect JavaScript-specific vulnerabilities
 * - NoSQL Injection
 * - Prototype Pollution
 * - XSS in responses
 * - Insecure JWT handling
 * - Hardcoded secrets
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { exec } = require('child_process');

const router = express.Router();

// VULNERABILITY: Hardcoded secrets (CWE-798)
// AI CONTEXT TEST: Should detect these as hardcoded, not env references
const JWT_SECRET = 'super-secret-jwt-key-never-share';
const API_KEY = 'sk-prod-1234567890abcdef';
const DB_PASSWORD = 'MongoDBPassword123!';

// VULNERABILITY: Insecure MongoDB connection
mongoose.connect(`mongodb://admin:${DB_PASSWORD}@prod-mongo:27017/app`);

/**
 * VULNERABILITY: NoSQL Injection (CWE-943)
 * AI CONTEXT TEST: Should detect user input directly in query
 */
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // CRITICAL: NoSQL injection - attacker can send {"$gt": ""}
    const user = await User.findOne({
        username: username,      // Can be {"$ne": null}
        password: password       // Can be {"$gt": ""}
    });
    
    if (user) {
        // VULNERABILITY: Weak JWT configuration
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            JWT_SECRET,
            { expiresIn: '30d' }  // Too long!
        );
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

/**
 * VULNERABILITY: Prototype Pollution (CVE-2019-10744)
 * AI CONTEXT TEST: Should detect unsafe object merge
 */
router.post('/settings', (req, res) => {
    const userSettings = {};
    
    // CRITICAL: Prototype pollution via __proto__
    // Attacker can send: {"__proto__": {"isAdmin": true}}
    Object.assign(userSettings, req.body);
    
    // Or even worse - recursive merge
    merge(userSettings, req.body);
    
    res.json({ settings: userSettings });
});

function merge(target, source) {
    // CRITICAL: Unsafe recursive merge - prototype pollution!
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

/**
 * VULNERABILITY: Reflected XSS (CWE-79, OWASP A03)
 * AI CONTEXT TEST: Should detect unsanitized user input in response
 */
router.get('/search', (req, res) => {
    const query = req.query.q;
    
    // CRITICAL: User input directly in HTML response
    res.send(`
        <html>
            <body>
                <h1>Search Results for: ${query}</h1>
                <p>No results found for "${query}"</p>
            </body>
        </html>
    `);
});

/**
 * VULNERABILITY: Command Injection (CWE-78)
 * AI CONTEXT TEST: Should detect user input in shell command
 */
router.get('/ping', (req, res) => {
    const host = req.query.host;
    
    // CRITICAL: Command injection
    // Attacker can send: host=google.com; cat /etc/passwd
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

/**
 * VULNERABILITY: Insecure Direct Object Reference (CWE-639, OWASP A01)
 * AI CONTEXT TEST: Should detect missing authorization check
 */
router.get('/users/:userId/profile', async (req, res) => {
    const { userId } = req.params;
    
    // CRITICAL: No authorization check!
    // Any authenticated user can access any other user's profile
    const user = await User.findById(userId);
    
    // Exposing sensitive data
    res.json({
        id: user._id,
        email: user.email,
        ssn: user.ssn,           // CRITICAL: Exposing SSN!
        creditCard: user.creditCard  // CRITICAL: Exposing credit card!
    });
});

/**
 * VULNERABILITY: Sensitive data in error response (CWE-209)
 */
router.get('/data', async (req, res) => {
    try {
        // Some operation
    } catch (error) {
        // CRITICAL: Exposing stack trace and internal details
        res.status(500).json({
            error: error.message,
            stack: error.stack,
            dbConnection: `mongodb://admin:${DB_PASSWORD}@prod-mongo:27017`
        });
    }
});

/**
 * VULNERABILITY: Missing rate limiting
 * AI CONTEXT TEST: Should note absence of rate limiting on auth endpoint
 */
router.post('/forgot-password', async (req, res) => {
    // No rate limiting - brute force possible!
    const { email } = req.body;
    // Send reset email...
    res.json({ message: 'Reset email sent' });
});

module.exports = router;
