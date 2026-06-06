# 🔒 Security — Security Multicloud Scanner

## Overview

This document describes all security measures implemented in the **Security Multicloud Scanner** production environment.

---

## 🏗️ Security Architecture

```
Internet
    │
    ▼
[ALB / HTTPS 443]  ←── SSL/TLS Certificate
    │
    ▼
[AWS Security Group]  ←── Network Firewall
    │
    ▼
[EC2 - Ubuntu]  ←── Fail2Ban + Rate Limiting
    │
    ▼
[API - FastAPI + MFA]  ←── Mandatory Authentication
```

---

## ☁️ AWS — Security Group (Firewall)

### Inbound Rules

| Protocol | Port | Source | Purpose |
|---|---|---|---|
| TCP | 22 (SSH) | `179.228.23.2/32` | Administrative access |
| TCP | 443 (HTTPS) | `0.0.0.0/0` | Public application access |
| TCP | 80 (HTTP) | `0.0.0.0/0` | HTTP → HTTPS redirect |
| TCP | 8000 | `security-scanner-alb-sg` | Internal ALB traffic |

---

## 🔐 Authentication — Mandatory MFA

The application uses mandatory two-factor authentication (MFA) for all users.

### Authentication Flow

```
User accesses /login
    │
    ▼
Enters email + password
    │
    ▼
Enters TOTP code (Google Authenticator / Authy)
    │
    ▼
Session cookie generated (scanner_session)
    │
    ▼
Dashboard access granted
```

### Technologies Used

- `pyotp` — TOTP token generation and validation
- `qrcode` — QR Code for authenticator setup
- `email-validator` + `pydantic[email]` — Email validation
- Session cookies with `HttpOnly` and `Secure` flags

---

## 🛡️ Fail2Ban — Attack Protection

**Fail2Ban** monitors logs and automatically bans malicious IPs.

### Configuration

| Jail | Port | Max Attempts | Ban Duration |
|---|---|---|---|
| `sshd` | 22 | 3 attempts | 24 hours |
| `http-scan` | 80, 443, 8000 | 20 attempts | 2 hours |

### Detected and Banned Patterns

- PHPUnit exploit attempts (`/vendor/phpunit/...`)
- Laravel exploit attempts (`/laravel/vendor/...`)
- Access to `.env`, `wp-admin`, `shell`, `cmd`
- Path traversal (`../../../`)
- XML-RPC attacks

### Monitoring Commands

```bash
# Check overall status
sudo fail2ban-client status

# See banned IPs in SSH jail
sudo fail2ban-client status sshd

# See banned IPs in HTTP jail
sudo fail2ban-client status http-scan

# Manually unban an IP
sudo fail2ban-client set http-scan unbanip <IP>
```

---

## 🚀 Deploy — GitHub Actions

Production deployment is 100% automated via **GitHub Actions**.

### Flow

```
git push origin main
    │
    ▼
GitHub Actions triggers
    │
    ▼
Connects to server via SSH (port 22)
using encrypted secrets
    │
    ▼
git pull + pip install + application restart
    │
    ▼
✅ Production updated in ~16 seconds
```

### Configured Secrets

| Secret | Description |
|---|---|
| `AWS_HOST` | EC2 server public IP |
| `AWS_SSH_KEY` | SSH private key (.pem) |

> Secrets are stored encrypted in GitHub and never exposed in logs.

---

## 🔄 HTTPS — SSL/TLS Certificate

- HTTP traffic (port 80) is automatically redirected to HTTPS (301)
- Valid SSL certificate at `scanner.oisolucoes.app.br`
- Client ↔ server communication fully encrypted

---

## 📋 Security Checklist

- [x] MFA mandatory for all users
- [x] SSH restricted to specific IPs (GitHub Actions + admin)
- [x] HTTPS with valid SSL certificate
- [x] HTTP redirects to HTTPS
- [x] Fail2Ban active (sshd + http-scan)
- [x] Automated deploy without credential exposure
- [x] Encrypted secrets in GitHub Actions
- [x] Port 8000 accessible only via internal Security Group
- [ ] API rate limiting *(in progress)*
- [ ] WAF (Web Application Firewall) *(planned)*

---

## 🚨 Vulnerability Reporting

If you find a security vulnerability, **do not open a public issue**.

Contact the repository administrator directly via email.

---

## 📅 Security Update History

| Date | Description |
|---|---|
| 2026-03-01 | Mandatory MFA implementation |
| 2026-03-01 | Fail2Ban configuration (sshd + http-scan) |
| 2026-03-01 | SSH port restriction to GitHub Actions IPs |
| 2026-03-01 | Automated deploy via GitHub Actions |
| 2026-03-01 | Authentication fix for scan calls |
