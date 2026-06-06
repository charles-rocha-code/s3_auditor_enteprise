# 🛡️ Security Multicloud Scanner — Enterprise Edition

Advanced security auditing platform for **AWS S3**, **Google Cloud Storage**, **Azure Blob Storage** and **Kubernetes** with MFA enterprise authentication, interactive web dashboard and executive report generation.

---

## 🚀 Features

- ☁️ **Multicloud:** AWS S3, GCS, Azure Blob Storage
- ☸️ **Kubernetes:** Authenticated cluster scanning (EKS, GKE, AKS, on-prem)
- 🔐 **Dual Mode:** Public scan (no credentials) + authenticated (with credentials)
- 🔑 **MFA Authentication:** Login with OTP via TOTP (Google Authenticator)
- 📊 **Risk Scoring:** 0–100 with CRITICAL / HIGH / MEDIUM / LOW levels
- ⚖️ **Compliance:** CIS, PCI-DSS, HIPAA, NIST, ISO 27001
- 📄 **Executive Reports:** Automatic PDF and DOCX generation
- 🎨 **Web Dashboard:** Modern interface with scan history and Chart.js graphs
- 🛡️ **Rate Limiting:** Brute-force protection via slowapi
- 📧 **Password Recovery:** Email reset with 30-minute token via SMTP/SES

---

## 🏗️ Architecture

### Application

![Application Architecture — Security Multicloud Scanner](docs/app-architecture.png)

### AWS Infrastructure

![AWS Infrastructure — Security Multicloud Scanner (HA)](docs/aws-architecture.png)

> High availability in `us-east-2` · WAF v2 · ALB · Auto Scaling Group (2–4 EC2) · TLS 1.3 via ACM · Terraform IaC

### Current vs Future

![Current vs Future Architecture](docs/architecture-current-vs-future.png)

> **Current:** EC2 ASG + WAF v2 + ALB + NAT Gateways · **Future:** ECS Fargate + CloudFront + DynamoDB + S3 + Secrets Manager

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/charles-rocha-code/s3_auditor_enteprise.git
cd s3_auditor_enteprise

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## 🔧 Starting the Server

The main server is `api_with_mfa.py`, which includes MFA authentication.

```bash
# Activate virtual environment
source venv/bin/activate

# Start server with MFA
uvicorn api_with_mfa:app --host 0.0.0.0 --port 8000 --reload

# Access dashboard
# http://localhost:8000/dashboard
```

> ⚠️ `api.py` is the base server without MFA — use it only for local development. Always use `api_with_mfa.py` in production.

---

## 👤 User Management

### Reset user database

```bash
./reset_users.sh
```

Stops the API, backs up the current database, resets users and restarts the server.

### First access

1. Go to `http://localhost:8000/dashboard`
2. Click **Register** and enter your name, email and password
3. Set up MFA via QR Code (Google Authenticator or similar)
4. On next login, enter email, password and the 6-digit OTP code

---

## 📊 API Endpoints

### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check — `{"status": "ok"}` |

### Authentication

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/auth/register` | Register new user | Public |
| `POST` | `/auth/login` | Login + MFA code | Public |
| `POST` | `/auth/logout` | Logout (invalidates session) | Token |
| `POST` | `/auth/mfa/setup` | Generate new MFA QR Code | Token |
| `POST` | `/auth/mfa/verify` | Activate MFA with TOTP code | Token |
| `GET` | `/auth/mfa/status` | Check user MFA status | Token |
| `POST` | `/forgot-password` | Request password reset by email | Public |
| `POST` | `/reset-password` | Reset password with token | Public |

### Scanning

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/scan/{target}` | Public scan by name or URL (up to 200 objects) | MFA |
| `POST` | `/scan/authenticated` | Authenticated scan S3/GCS/Azure/K8s (up to 1000 objects) | MFA |
| `POST` | `/scan/k8s` | Kubernetes scan with kubeconfig | MFA |

### Reports

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/generate-report` | Generate PDF + DOCX with charts | MFA |
| `GET` | `/download-report/{filename}` | Download generated report | MFA |

### Dashboard

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/dashboard` | Web dashboard with history | MFA |
| `GET` | `/api/dashboard` | Current user data (JSON) | MFA |

---

## 🔐 Authenticated Scan — Examples

### AWS S3

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{
    "provider": "AWS_S3",
    "bucket": "my-bucket",
    "aws_access_key_id": "AKIA...",
    "aws_secret_access_key": "xxxxx",
    "region": "us-east-1",
    "max_objects": 1000
  }'
```

### Google Cloud Storage

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{
    "provider": "GCS",
    "bucket": "my-gcs-bucket",
    "service_account_key": {
      "type": "service_account",
      "project_id": "my-project",
      "private_key": "-----BEGIN PRIVATE KEY-----\n...",
      "client_email": "sa@project.iam.gserviceaccount.com"
    },
    "max_objects": 1000
  }'
```

> The `service_account_key` JSON is generated at **GCP Console → IAM & Admin → Service Accounts → Create Key → JSON**.

### Azure Blob Storage

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{
    "provider": "AZURE_BLOB",
    "bucket": "myaccount.blob.core.windows.net",
    "azure_connection_string": "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net",
    "max_objects": 1000
  }'
```

### Kubernetes

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{
    "provider": "KUBERNETES",
    "bucket": "my-cluster",
    "kubeconfig_path": "/home/user/.kube/config",
    "context": "my-context",
    "namespace": "production",
    "max_objects": 1000
  }'
```

> For EKS/GKE/AKS clusters, use the kubeconfig generated by the provider:
> - `aws eks update-kubeconfig --name cluster --region us-east-1`
> - `gcloud container clusters get-credentials CLUSTER --zone ZONE`
>
> To run **inside the cluster**, omit `kubeconfig_path` and set `"in_cluster": true`.

---

## 🌐 Public Scan (no credentials)

Provider is auto-detected from the URL.

```bash
# AWS S3
curl http://localhost:8000/scan/my-bucket

# GCS (full URL)
curl http://localhost:8000/scan/my-bucket.storage.googleapis.com

# Azure
curl http://localhost:8000/scan/myaccount.blob.core.windows.net
```

---

## ☸️ Kubernetes — Security Checks

The auditor `auditor_k8s_authenticated.py` connects to the cluster via kubeconfig and runs 5 check categories:

### 1. Workload Security (Pods and Containers)

| Severity | Check |
|---|---|
| `CRITICAL` | Container with `privileged: true` |
| `HIGH` | `hostNetwork: true` — shares node network |
| `HIGH` | `hostPID: true` — accesses node processes |
| `HIGH` | `hostIPC: true` |
| `HIGH` | Container running as root (`runAsUser: 0` or missing `runAsNonRoot`) |
| `MEDIUM` | Container missing `resources.limits` (CPU/memory) |

### 2. RBAC

| Severity | Check |
|---|---|
| `CRITICAL` | `ClusterRole` with `verbs: ["*"]` and `resources: ["*"]` (full permission) |

### 3. Secrets and ConfigMaps

| Severity | Check |
|---|---|
| `CRITICAL` | `ConfigMap` with sensitive plaintext keys (`password`, `secret`, `token`, `apikey`, `private_key`) |
| `MEDIUM` | `Secret` mounted as environment variable (can leak in logs) |

### 4. Network Exposure

| Severity | Check |
|---|---|
| `MEDIUM` | `LoadBalancer` or `NodePort` service exposed externally |
| `HIGH` | Namespace without `NetworkPolicy` (unrestricted pod-to-pod traffic) |

### 5. Anonymous API Server Authentication

| Severity | Check |
|---|---|
| `CRITICAL` | `ClusterRoleBinding` to `system:anonymous` or `system:unauthenticated` |

### Kubernetes Risk Score Formula

```
risk_score = min(100, CRITICAL×25 + HIGH×10 + MEDIUM×3 + LOW×1)
```

### Response Payload

```json
{
  "provider": "KUBERNETES",
  "cluster": "1.29",
  "platform": "linux/amd64",
  "namespace_filter": "production",
  "summary": { "namespaces_scanned": 5, "findings_total": 12 },
  "files": [
    {
      "key": "default/Container/nginx/app",
      "severity": "CRITICAL",
      "category": "Workload Security",
      "reason": "Container running as privileged",
      "recommendation": "Remove privileged=true; use specific capabilities if needed."
    }
  ],
  "severity_distribution": { "CRITICAL": 2, "HIGH": 4, "MEDIUM": 6, "LOW": 0 },
  "risk_score": 72,
  "recommendations": ["Remove privileged=true...", "Apply NetworkPolicy..."],
  "errors": []
}
```

---

## 🎯 Application Architecture — Modules

```
FastAPI Server (api_with_mfa.py)
│
├── MFA Authentication
│   ├── auth_mfa.py                  — TOTP + JWT
│   ├── templates/login.html         — Login page
│   ├── templates/forgot_password.html
│   └── templates/reset_password.html
│
├── Public Scan (up to 200 objects)
│   ├── auditor.py                   — AWS S3
│   ├── auditor_gcs.py               — GCS
│   └── auditor_azure.py             — Azure Blob
│
├── Authenticated Scan (up to 1000 objects)
│   ├── auditor_s3_authenticated.py
│   ├── auditor_gcs_authenticated.py
│   ├── auditor_azure_authenticated.py
│   └── auditor_k8s_authenticated.py — ☸️ Kubernetes
│
├── Universal Router
│   └── auditor_universal.py         — Auto-detects provider from URL
│
├── Risk Engine
│   └── engine_risk.py               — Scoring + Compliance
│
├── Reports
│   └── generate_report.py           — PDF + DOCX with charts
│
└── Dashboard
    └── templates/dashboard.html
```

---

## 🗂️ File Structure

```
s3_auditor_enteprise/
├── api_with_mfa.py                 # Main server (with MFA) ← use this
├── api.py                          # Base server (without MFA)
├── auth_mfa.py                     # MFA authentication module
├── auditor_universal.py            # Provider router by URL
├── auditor.py                      # AWS S3 public auditor
├── auditor_gcs.py                  # GCS public auditor
├── auditor_azure.py                # Azure public auditor
├── auditor_s3_authenticated.py     # AWS S3 authenticated auditor
├── auditor_gcs_authenticated.py    # GCS authenticated auditor
├── auditor_azure_authenticated.py  # Azure authenticated auditor
├── auditor_k8s_authenticated.py    # ☸️ Kubernetes authenticated auditor
├── engine_risk.py                  # Risk and compliance engine
├── generate_report.py              # PDF/DOCX report generator
├── requirements.txt                # Python dependencies
├── deploy_mfa.sh                   # Deploy with MFA
├── reset_users.sh                  # Reset users
├── install.sh                      # Installation script
└── templates/
    ├── dashboard.html              # Main dashboard
    ├── login.html                  # MFA login page
    ├── mfa_setup.html              # MFA setup
    ├── forgot_password.html        # Password recovery
    └── reset_password.html         # Password reset
```

---

## ⚙️ Configuration

The system uses local JSON files for persistence:

| File | Description |
|------|-------------|
| `users_db.json` | User database (do not commit to git) |
| `sessions_db.json` | Active sessions (do not commit to git) |
| `reports_executive/` | Generated reports (do not commit to git) |

### Environment Variables (.env)

| Variable | Description | Example |
|----------|-------------|---------|
| `SMTP_HOST` | SMTP server for emails | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USER` | Sender email | `your@email.com` |
| `SMTP_PASS` | App password | `xxxx xxxx xxxx xxxx` |
| `APP_BASE_URL` | Application base URL | `https://scanner.yourdomain.com` |

---

## 🔒 Security

- Credentials are **never stored** — used only during the scan in memory
- JWT tokens with 24-hour expiration
- MFA required for all authenticated scans
- Rate limiting: 1 login/min, 3 forgot-password/hour
- `.gitignore` configured to exclude sensitive data

---

## 📝 License

MIT License

---

## 👤 Author

Developed by **Charles Rocha** for multicloud enterprise security auditing.
