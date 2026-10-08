# 🔒 Zero-Trust Authentication Microservice

![Node.js](https://img.shields.io/badge/Node.js-v18%2B-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)
![NeonDB](https://img.shields.io/badge/Neon.tech-00E599?style=for-the-badge&logo=postgresql&logoColor=black)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![Jest](https://img.shields.io/badge/Jest-C21325?style=for-the-badge&logo=jest&logoColor=white)

---

> A production-grade, security-focused authentication service engineered with zero-trust principles, short-lived JWTs, automated token rotation, Argon2id key derivation, and defense-in-depth rate limiting.

---

## 🚀 Key Features

- 🔐 **Argon2id Hashing:** Password hashing configured with high memory ($64\text{ MB}$) and iteration costs to neutralize GPU-accelerated brute-force attacks.
- 🛡️ **Dual-Token Session Strategy:** Short-lived access JWTs ($15\text{ mins}$) combined with opaque, persistent refresh tokens ($7\text{ days}$) stored as SHA-256 hashes.
- 🔄 **Automatic Token Rotation:** Instantly revokes consumed refresh tokens upon use to stop session hijacking and token reuse vectors.
- 🍪 **Hardened Cookie Delivery:** Session tokens delivered strictly via `HttpOnly`, `SameSite=Strict`, and `Secure` cookies to block XSS and CSRF exposure.
- ⚡ **Rate Limiting & Throttling:** IP and route throttling (`express-rate-limit`) to prevent credential stuffing attacks.
- 🗄️ **Parameterized Database Layer:** Pure PostgreSQL connection pool utilizing parameterized SQL queries to eliminate SQL injection risks.
- 🧪 **Automated Test Suite:** Full integration testing powered by **Jest** and **Supertest**.

---

## 🛠️ Tech Stack

```text
┌─────────────────┬─────────────────────────────────────────────────┐
│ Layer           │ Technology                                      │
├─────────────────┼─────────────────────────────────────────────────┤
│ Runtime / Framework │ Node.js / Express.js                         │
│ Cryptography    │ Argon2id (`argon2`), Crypto (SHA-256), JWT      │
│ Database        │ PostgreSQL (Hosted on Neon.tech Serverless)    │
│ Security        │ Helmet.js, Cookie-Parser, Express-Rate-Limit    │
│ Testing         │ Jest, Supertest                                 │
└─────────────────┴─────────────────────────────────────────────────┘
