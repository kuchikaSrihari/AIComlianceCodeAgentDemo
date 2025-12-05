# E-Commerce Application - Flow-Based Security Test

A realistic e-commerce application with **intentional vulnerabilities** organized by user journey flows.

## User Journey Flows

```
USER FLOW          PRODUCT FLOW        CART FLOW           PAYMENT FLOW
    |                   |                  |                    |
    v                   v                  v                    v
Register -----> Search Products ---> Add to Cart -----> Enter Card
    |                   |                  |                    |
    v                   v                  v                    v
Verify Email    View Details        Apply Coupon        Process Payment
    |                   |                  |                    |
    v                   v                  v                    v
Login --------> Add Review -------> Update Qty -------> Refund
    |                   |                  |                    |
    v                   v                  v                    v
Update Profile  Upload Image        Checkout            ORDER FLOW
                                                            |
                                                            v
                                                    Track -> Invoice -> Cancel
```

## Files & Vulnerability Summary

### UserController.java (User Flow)
| Step | Vulnerability | CWE/CVE |
|------|--------------|---------|
| Register | Log4Shell JNDI Injection | CVE-2021-44228 |
| Verify | Insecure Direct Object Reference | CWE-639 |
| Login | SQL Injection + Insecure Cookies | CWE-89, CWE-614 |
| Forgot Password | Weak Token Generation | CWE-330 |
| Update Profile | Mass Assignment | CWE-915 |

### ProductController.java (Product Flow)
| Step | Vulnerability | CWE/CVE |
|------|--------------|---------|
| Search | SQL Injection | CWE-89 |
| View | Reflected XSS | CWE-79 |
| Review | Stored XSS | CWE-79 |
| Import | XXE Attack | CVE-2014-3529 |
| Upload | Path Traversal | CWE-22 |
| Report | Command Injection | CWE-78 |

### CartController.java (Cart Flow)
| Step | Vulnerability | CWE |
|------|--------------|-----|
| Add Item | IDOR | CWE-639 |
| Update Qty | Negative Value Logic Flaw | CWE-840 |
| Coupon | Race Condition | CWE-362 |
| Checkout | Client-Side Price Trust | CWE-602 |
| Import | Unsafe Deserialization | CWE-502 |
| Analytics | SSRF | CWE-918 |

### PaymentController.java (Payment Flow - PCI-DSS Critical)
| Step | Vulnerability | Compliance |
|------|--------------|------------|
| Process | Log card data | PCI-DSS 3.2 |
| Process | Log4Shell | CVE-2021-44228 |
| Encrypt | ECB Mode (weak) | PCI-DSS 3.4 |
| Hash | MD5 (broken) | CWE-328 |
| Store | CVV Storage | PCI-DSS 3.2.2 |
| Refund | Missing Authorization | CWE-862 |
| Webhook | No Signature Verification | CWE-347 |
| Receipt | HTTP instead of HTTPS | CWE-319 |

### OrderController.java (Order Flow)
| Step | Vulnerability | CWE |
|------|--------------|-----|
| Create | Race Condition (inventory) | CWE-362 |
| Get | Broken Access Control | CWE-639 |
| Track | SSRF | CWE-918 |
| Invoice | Path Traversal | CWE-22 |
| Update | Mass Assignment | CWE-915 |
| Cancel | Business Logic Flaw | CWE-840 |
| Export | Command Injection | CWE-78 |
| Import | XXE | CWE-611 |

## AI Capability Demonstrations

### 1. Attack Chain Detection
AI should identify cross-flow attack chains:
- Register (Log4Shell) -> Login (SQLi) -> Payment (PCI violation)
- IDOR in Cart -> Price Manipulation -> Free Products

### 2. Business Logic Understanding
AI understands context:
- Negative quantity = financial loss
- Cancel after shipped = fraud opportunity
- Race condition = overselling inventory

### 3. Compliance Mapping
AI maps to frameworks:
- **PCI-DSS**: Payment violations
- **OWASP Top 10**: Injection, XSS, IDOR
- **SCF Controls**: CRY-03, TDA-02, IAC-01

## Testing

```bash
# Test complete e-commerce app
git add test-samples/ecommerce-app/
git commit -m "Add e-commerce application"
# Create PR to trigger AI scan
```

## Warning

**DO NOT deploy to production!** Intentionally vulnerable for testing.
