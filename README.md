# Zero-Trust Authentication Microservice

A production-grade, security-focused authentication service built with Node.js, Express, PostgreSQL, and Redis. Engineered with a zero-trust architecture, robust input sanitization, Argon2id key derivation, and defense-in-depth rate limiting.

## Features

- **Argon2id Hashing:** Password hashing configured with high memory and time cost factors to mitigate GPU-accelerated brute-force attacks.
- **Zero-Trust Token Management:** Short-lived JWTs issued via `HttpOnly`, `SameSite=Strict`, and `Secure` cookies to prevent XSS and CSRF token theft.
- **Adaptive Rate Limiting:** Redis-backed IP/account throttling to neutralize credential stuffing and automated password spraying.
- **Parameterized SQL Layer:** PostgreSQL persistence utilizing strict parameterized queries (`pg`) to eliminate SQL injection vulnerabilities.
- **Structured JSON Logging:** Redacted audit logs formatted for SIEM ingestion (e.g., Datadog, Splunk) without exposing PII/secrets.
- **Containerized Architecture:** Fully dockerized environment with multi-stage builds for secure deployment across cloud environments.

## Tech Stack

- **Runtime:** Node.js / Express
- **Cryptography & Security:** Argon2id, JSON Web Tokens (JWT), Helmet.js
- **Database:** PostgreSQL (Parameterized Queries via `pg`)
- **Cache & Rate-Limiting:** Redis / `express-rate-limit`
- **Containerization:** Docker & Docker Compose

## Quick Start

### 1. Environment Configuration
Create a `.env` file in the root directory:

```env
PORT=3000
NODE_ENV=development
JWT_SECRET=your_super_secret_jwt_key_here
CLIENT_URL=http://localhost:3000
DATABASE_URL=postgresql://postgres:password@localhost:5432/auth_db
