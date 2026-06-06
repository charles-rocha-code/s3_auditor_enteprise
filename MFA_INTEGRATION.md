# 🔐 MFA Integration Guide — Security Multicloud Scanner

## 📋 Overview

This guide shows how to integrate the MFA (Multi-Factor Authentication) system with the Security Multicloud Storage Scanner.

---

## 📦 Files Created

| File | Description |
|------|-------------|
| **auth_mfa.py** | Complete MFA authentication module |
| **login.html** | Login/registration page matching dashboard style |
| **api_integrado.py** | API with MFA integrated (replaces api.py) |
| **requirements_mfa.txt** | Updated dependencies with MFA |

---

## 🚀 Installation (3 Steps)

### Step 1: Install MFA Dependencies

```bash
pip install pyotp==2.9.0 qrcode[pil]==7.4.2 Pillow==10.1.0 python-dotenv==1.0.0
```

Or install everything at once:
```bash
pip install -r requirements_mfa.txt
```

### Step 2: Organize Files

```
your-project/
│
├── api_integrado.py         ← New API with MFA
├── auth_mfa.py              ← Authentication module
├── login.html               ← Login page
│
├── templates/
│   └── dashboard.html       ← Existing dashboard
│
├── auditor.py               ← Your existing auditors
├── auditor_gcs.py
├── auditor_azure.py
├── engine_risk.py
│
└── requirements_mfa.txt     ← Updated dependencies
```

### Step 3: Run

```bash
python api_integrado.py
```

**Expected output:**
```
======================================================================
🚀 Security Multicloud Storage Scanner + MFA — STARTED
======================================================================
📡 API: http://localhost:8000
📄 Docs: http://localhost:8000/docs
🔐 Login: http://localhost:8000/login
🛡️  Dashboard: http://localhost:8000/dashboard
======================================================================
🔑 MFA: ✅ ACTIVE
📊 Providers: AWS S3, GCS, Azure Blob
======================================================================
```

---

## 🎯 How to Use

### 1️⃣ First Time: Create Account

Go to: http://localhost:8000/login

1. Click **"Create account"**
2. Fill in:
   - Name: John Doe
   - Email: john@company.com
   - Password: password123
3. Click **"Create Account"**

### 2️⃣ Initial Login (Without MFA)

1. Enter email and password
2. Click **"Sign In"**
3. You'll be taken to the **Security Panel**

### 3️⃣ Set Up MFA (First Time)

1. In the Panel, click **"Set Up MFA"**
2. Enter your password to confirm
3. Click **"Generate QR Code"**

4. **Scan QR Code:**
   - Open **Google Authenticator** on your phone
   - Tap **"+"** → **"Scan QR code"**
   - Point at the QR Code on screen

5. **Save Backup Codes:**
   - Write down the 10 codes in a safe place
   - You can use them if you lose your phone

6. **Activate MFA:**
   - Enter the 6-digit code from the app
   - Click **"Activate MFA"**

✅ **MFA is now active!**

### 4️⃣ Login with MFA (After activation)

1. Enter email and password
2. **"MFA Code"** field will appear
3. Open Google Authenticator
4. Enter the 6-digit code
5. Click **"Sign In"**

---

## 📡 API Endpoints

### Authentication

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/auth/register` | POST | Register user | ❌ No |
| `/auth/login` | POST | Login (with/without MFA) | ❌ No |
| `/auth/mfa/setup` | POST | Configure MFA | ❌ No* |
| `/auth/mfa/verify` | POST | Activate MFA | ❌ No* |
| `/auth/mfa/status` | GET | MFA status | ❌ No* |
| `/auth/logout` | POST | Logout | ✅ Yes |

*Requires email and password, but not JWT token

### Scanning

| Endpoint | Method | Description | Auth | MFA |
|----------|--------|-------------|------|-----|
| `/scan/{bucket}` | GET | Public scan | ✅ Token | ❌ No |
| `/scan/authenticated` | POST | Authenticated scan | ✅ Token | ✅ **Yes** |

### Reports

| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/generate-report` | POST | Generate report | ✅ Yes |
| `/download-report/{filename}` | GET | Download | ✅ Yes |

---

## 🔐 Security Implemented

### ✅ What's implemented:

1. **TOTP (Time-based One-Time Password)**
   - 6-digit codes
   - Expire every 30 seconds
   - Tolerance window: ±30 seconds

2. **Backup Codes**
   - 10 unique codes
   - Single-use (invalidated after use)

3. **Session Tokens**
   - Unique tokens per session
   - Stored in memory

4. **Password Validation**
   - SHA-256 hash (basic)

5. **Authentication Middleware**
   - `get_current_user()` — Requires authentication
   - `require_mfa()` — Requires MFA enabled

### ⚠️ For Production (IMPORTANT!):

#### 1. Use a Real Database

Replace `USERS_DB = {}` in `auth_mfa.py`:

```python
from sqlalchemy import create_engine, Column, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql://user:password@localhost/scanner_db"
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    email = Column(String, primary_key=True)
    password = Column(String)
    mfa_secret = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
```

#### 2. Use Bcrypt for Passwords

```bash
pip install passlib bcrypt
```

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
```

#### 3. Implement Real JWT

```bash
pip install python-jose[cryptography]
```

```python
from jose import JWTError, jwt
from datetime import datetime, timedelta

SECRET_KEY = "your-very-strong-secret-key-here"
ALGORITHM = "HS256"

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
```

#### 4. Configure HTTPS

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
uvicorn api_integrado:app --ssl-keyfile=key.pem --ssl-certfile=cert.pem --port 443
```

#### 5. Add Rate Limiting

```bash
pip install slowapi
```

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, ...):
    ...
```

#### 6. Environment Variables

Create `.env`:
```bash
DATABASE_URL=postgresql://user:pass@localhost/scanner_db
SECRET_KEY=your-super-secret-key-here
MFA_ISSUER=Security Scanner
ENVIRONMENT=production
```

```python
from dotenv import load_dotenv
import os

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
```

---

## 🧪 Testing

### Manual Test

```bash
# Register
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"pass123","full_name":"Test User"}'

# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"pass123"}'

# Scan (with token)
curl -X GET http://localhost:8000/scan/my-bucket.s3.amazonaws.com \
  -H "Authorization: Bearer {your-token-here}"
```

---

## 🔄 Migrating from Old API

### Option 1: Gradual Replacement (Recommended)

```bash
# Old API (port 8000)
python api.py

# New API with MFA (port 8001)
python api_integrado.py --port 8001
```

Configure reverse proxy (Nginx):
```nginx
location /auth/ { proxy_pass http://localhost:8001; }
location / { proxy_pass http://localhost:8000; }
```

### Option 2: Direct Replacement

```bash
cp api.py api_backup.py
mv api_integrado.py api.py
python api.py
```

---

## 📊 Authentication Flow

```
1. REGISTRATION
   └─ POST /auth/register → account created (MFA disabled)

2. FIRST LOGIN (NO MFA)
   └─ POST /auth/login {email, password} → receives token

3. SET UP MFA
   ├─ POST /auth/mfa/setup {email, password}
   │   └─ receives QR Code + Secret + 10 Backup Codes
   ├─ Scan QR Code in Google Authenticator
   └─ POST /auth/mfa/verify {email, code} → MFA ACTIVE ✅

4. LOGIN WITH MFA
   ├─ POST /auth/login {email, password}
   │   └─ response: {"mfa_required": true}
   ├─ Frontend shows MFA code field
   └─ POST /auth/login {email, password, mfa_code} → token + dashboard access

5. USE DASHBOARD
   ├─ GET /scan/{bucket} → requires token
   └─ POST /scan/authenticated → requires token + MFA enabled
```

---

## ❓ FAQ

**Q: Can I use without MFA?**
A: Yes! Public scans work with basic authentication only. MFA is required only for authenticated scans (with cloud credentials).

**Q: What if I lose my phone?**
A: Use one of the 10 backup codes you saved. Each code works only once.

**Q: Can I disable MFA later?**
A: Yes! In the Security Panel → "Disable MFA" (requires current MFA code).

**Q: Is data secure?**
A: In the current code, data is stored in memory (lost on restart). For production, use a real database (PostgreSQL, MongoDB).

---

## ✅ Deploy Checklist

- [ ] Database configured (PostgreSQL/MongoDB)
- [ ] Bcrypt for passwords implemented
- [ ] JWT with strong SECRET_KEY configured
- [ ] HTTPS configured (SSL/TLS)
- [ ] Rate limiting enabled
- [ ] Environment variables (.env) configured
- [ ] CORS configured for specific domains
- [ ] Backup codes explained to users
- [ ] Audit logs implemented
- [ ] Monitoring configured (Prometheus/Datadog)
- [ ] Automated tests passing

---

**Developed for Security Multicloud Scanner**
