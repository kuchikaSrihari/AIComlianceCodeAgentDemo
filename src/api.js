// API Service Module
// This file contains intentional security issues for demo purposes

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');

// ============================================
// CRITICAL ISSUES - Will BLOCK the PR
// ============================================

// CRITICAL: Hardcoded API credentials
const API_SECRET = "super-secret-api-key-12345";
const DB_PASSWORD = "mysql_password_123";
const JWT_SECRET = "jwt-signing-secret-do-not-share";

// Database connection with hardcoded credentials
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'RootPassword123!',  // CRITICAL: Hardcoded password
  database: 'production'
});

// CRITICAL: SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // Vulnerable: Direct string concatenation
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// CRITICAL: Command injection via eval
app.post('/calculate', (req, res) => {
  const expression = req.body.expression;
  // CRITICAL: eval() with user input
  const result = eval(expression);
  res.json({ result });
});


// ============================================
// HIGH ISSUES - Will BLOCK the PR
// ============================================

// HIGH: Weak cryptographic hash for passwords
function hashPassword(password) {
  // HIGH: MD5 is cryptographically broken
  return crypto.createHash('md5').update(password).digest('hex');
}

// HIGH: SHA1 is deprecated
function generateToken(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}


// ============================================
// MEDIUM ISSUES - Will show as SUGGESTIONS
// ============================================

// MEDIUM: Debug mode enabled
const DEBUG = true;
const VERBOSE_ERRORS = true;

// MEDIUM: HTTP endpoint without TLS
const API_ENDPOINT = "http://api.internal.company.com/v1";
const WEBHOOK_URL = "http://hooks.example.com/notify";

// MEDIUM: Insecure cookie settings
app.use(session({
  secret: 'keyboard cat',
  cookie: { 
    secure: false,  // MEDIUM: Should be true in production
    httpOnly: false // MEDIUM: Should be true
  }
}));


// ============================================
// LOW ISSUES - Informational only
// ============================================

// TODO: Add rate limiting to prevent abuse
// FIXME: Need to add input validation
// TODO: Implement proper error handling

function processRequest(data) {
  // Placeholder implementation
  return data;
}

module.exports = { hashPassword, generateToken, processRequest };
