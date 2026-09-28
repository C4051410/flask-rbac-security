# Role-Based Access Control (RBAC) & Hardened Web Service

A modular web application built with Python, Flask, and SQLAlchemy demonstrating multi-tier Role-Based Access Control (RBAC), cryptographic credential hashing, defense-in-depth HTTP security headers, and parameterized query execution to eliminate common web vulnerabilities.

---

## Architectural & Security Overview

```text
[ Incoming Client Request ]
            │
            ▼
[ Application Blueprint Router ]
            │
  ┌─────────┴─────────┐
  ▼                   ▼
[/login, /register]  [Protected Endpoints: /admin-panel, /moderator, /user-dashboard]
  │                   │
  │                   ├─► [Session Check: Authenticated?] ──► No  ──► [HTTP 403 Forbidden]
  │                   └─► [Role Evaluation: Role Match?]   ──► No  ──► [HTTP 403 Forbidden]
  │                                                            │
  │                                                           Yes
  │                                                            │
  ▼                                                            ▼
[SQLAlchemy 2.0 ORM Engine] ◄─────────────────────── [Controller Execution]
  (Parameterized SQL Execution)                                │
            │                                                  ▼
            └─────────────────────────────────────► [HTTP Response Object]
                                                               │
                                                               ▼
                                                  [@app.after_request Middleware]
                                                   - Content-Security-Policy (CSP)
                                                   - X-Frame-Options: DENY
                                                   - X-Content-Type-Options: nosniff
                                                   - Referrer-Policy
                                                               │
                                                               ▼
                                                    [Client Browser Render]