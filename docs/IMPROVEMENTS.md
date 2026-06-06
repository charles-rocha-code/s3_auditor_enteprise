# 🔐 S3 Security Auditor v3.0 — Enterprise Edition

## 📋 Overview

Advanced security auditing system for AWS S3 buckets with intelligent vulnerability detection, CVSS risk classification and interactive dashboard.

---

## ✨ Key Improvements Implemented

### 🔍 1. Intelligent Classification System

#### Before (v2.0):
- 7 basic categories
- Limited critical file detection
- Generic severity

#### Now (v3.0):
- ✅ **15+ detailed categories** with visual emojis
- ✅ **Expanded sensitive pattern detection** (20+ regex)
- ✅ **Custom CVSS score** (0.0 to 10.0) per file
- ✅ **Specific recommendations** by file type
- ✅ **Categorization tags** (CRITICAL_EXPOSURE, GIT_EXPOSED, etc.)

**New Categories:**
- 🔴 Keys/Credentials (AWS keys, private keys, tokens, .env)
- 🔴 Repository (.git exposed)
- ⚠️ Configurations (configs, YAML, JSON with possible credentials)
- ⚠️ Backups (SQL dumps, database backups)
- ⚠️ Source Code (Python, Java, JS, etc.)
- ⚠️ Source Maps (.map files that expose original code)
- 📦 Compressed (ZIP, RAR, TAR)
- 📄 Documents (PDF, DOCX, XLSX with possible PII)
- 🎬 Media (videos and audio)
- 🖼️ Images
- 🔤 Fonts
- 📱 Statics (CSS, JS, HTML)
- ❓ Others/Unknown

### 🛡️ 2. Advanced Credential Detection

**Detected Patterns:**
```python
✅ AWS Access Keys (AKIA...)
✅ AWS Secret Keys
✅ Private Keys (RSA, OpenSSH, ECDSA)
✅ Generic API Keys
✅ Bearer Tokens
✅ Hardcoded passwords
✅ Database passwords
✅ JWT Tokens
✅ Connection Strings (MongoDB, MySQL, PostgreSQL)
✅ GitHub Tokens (ghp_, gho_, ghs_)
✅ Slack Tokens (xox...)
✅ Stripe Keys (sk_live_)
✅ Google API Keys (AIza...)
```

### 📊 3. Completely Redesigned HTML Dashboard

#### Visual Improvements:
- ✨ Modern design with gradients and animations
- 📱 100% responsive (mobile-first)
- 🎨 Interactive cards with hover effects
- 📈 Enhanced charts (Chart.js 4.x)
- 🔔 Highlighted critical alerts
- 💾 JSON and CSV export
- 🎯 Detail modal with recommendations

#### New Features:
- **Rich Header**: region, scan duration, auditor version
- **Animated Critical Alert**: visual highlight for critical findings
- **Dynamic Risk Score**: visual classification (Critical/High/Medium/Low)
- **3 Interactive Charts**:
  - Severity Distribution (Doughnut)
  - Category Distribution (Bar)
  - Historical Trend (Line)
- **Statistics Grid**: detailed metrics
- **Advanced Table**: DataTables with filters and sorting
- **Personalized Recommendations**: based on specific findings

### 🚀 4. Enhanced Python Script

#### New Features:

**Robust Validation:**
- ✅ Complete bucket name validation (AWS rules)
- ✅ Automatic region detection with fallback
- ✅ Enhanced HTTP error handling
- ✅ XML pagination support with/without namespace

**Expanded Metadata:**
- ⏱️ Scan execution time
- 📊 Average CVSS per category
- 📈 Top 10 largest files
- 🎯 Top 20 most critical files
- 💾 Total size per category

**Enhanced History:**
- 📅 Keeps up to 100 runs (was 50)
- ⏱️ Includes duration of each scan
- 📊 Detailed metrics per run

**Improved Logging System:**
- 🎯 Logs with emojis and levels (INFO, WARNING, ERROR, CRITICAL, SUCCESS)
- 📊 Progress every 1000 files
- ⚡ Detailed executive summary

**Personalized Recommendations:**
```python
# Generates specific recommendations based on:
- Number of critical files
- Types of vulnerabilities found
- Public access enabled
- Total bucket size
- Specific categories detected
```

---

## 🚀 How to Use

### 1. Installation

```bash
pip install requests --break-system-packages
mkdir -p templates reports/history
```

### 2. Prepare Templates

```bash
cp dashboard_improved.html templates/dashboard.html
```

### 3. Run Audit

```bash
python s3_auditor_improved.py
```

### 4. View Report

```bash
# Linux/Mac
open reports/my-bucket_20241208_103000.html

# Windows
start reports/my-bucket_20241208_103000.html
```

---

## 📊 Understanding Metrics

### CVSS Score (0.0 - 10.0)

| Score | Severity | Description |
|-------|----------|-------------|
| 9.0 - 10.0 | 🚨 Critical | Credential exposure, private keys, .env |
| 7.0 - 8.9 | ⚠️ High | Configs, backups, source code, .git |
| 4.0 - 6.9 | ℹ️ Medium | Documents, source maps, large compressed files |
| 0.0 - 3.9 | ✅ Low | Images, fonts, statics (CSS/JS) |

### Overall Risk Score

Weighted average of CVSS scores of all files:
- **8.0 - 10.0**: 🔴 Critical — Immediate action required
- **6.0 - 7.9**: 🟠 High — Review urgently
- **4.0 - 5.9**: 🟡 Medium — Review soon
- **0.0 - 3.9**: 🟢 Low — Monitor

---

## 🛡️ Remediation Checklist

### ⚡ Urgent (First 24h)

- [ ] Remove **ALL** critical files (.env, keys, credentials)
- [ ] Rotate **ALL** potentially exposed credentials
- [ ] Audit CloudTrail logs for unauthorized access
- [ ] Enable **Block Public Access** (4 settings)
- [ ] Remove .git repositories if exposed

### 📅 Short Term (First Week)

- [ ] Enable **Server Access Logging** and **CloudTrail**
- [ ] Implement **least-privilege IAM policies**
- [ ] Configure **AWS Secrets Manager** for credentials
- [ ] Enable bucket **versioning**
- [ ] Configure **SSE-KMS encryption**
- [ ] Review and remove unnecessary backups
- [ ] Remove exposed source code

### 🔄 Medium Term (First Month)

- [ ] Configure **Amazon Macie** for sensitive data discovery
- [ ] Implement **lifecycle policies** for automatic expiry
- [ ] Configure **AWS Config Rules** for continuous compliance
- [ ] Enable **AWS GuardDuty** for threat detection
- [ ] Implement **Object Lock** for critical data
- [ ] Configure **restrictive CORS**
- [ ] Establish **VPC Endpoints** for private access

### 🎯 Ongoing

- [ ] Quarterly access audits
- [ ] S3 security team training
- [ ] CloudWatch alert monitoring
- [ ] IAM policy review
- [ ] Authorized penetration testing
- [ ] Deploy **git-secrets** and **truffleHog** in CI/CD

---

## 📈 Dashboard Features

### 1. Interactive Cards
- Click metric cards to see details
- Hover for click hint
- Smooth and responsive animations

### 2. File Modal
- Detailed listing by severity
- Complete file metadata
- Inline specific recommendations

### 3. Dynamic Charts
- **Doughnut**: Severity distribution
- **Bar**: File categories
- **Line**: Historical score evolution

### 4. Advanced Table
- Sort by any column
- Global search filter
- Customizable pagination
- CSV export

### 5. Export
- **JSON**: Complete structured report
- **CSV**: Spreadsheet for analysis

---

## ⚠️ Important Notes

### Limitations:
1. ✋ **Public Scan Only**: This tool scans via public HTTP. For private buckets, use AWS CLI with credentials.
2. 🔒 **No File Download**: Does not download content (only metadata).
3. 📊 **Heuristic-Based**: Classification is based on patterns and names, not actual content analysis.
4. ⚡ **Rate Limits**: Respect AWS rate limits when doing multiple scans.

### Responsible Use:
- ⚠️ Do not use to test third-party buckets without authorization
- 🔐 Do not share reports containing sensitive information
- 📋 Use only for legitimate security auditing purposes

---

## 📚 AWS S3 Security References

### Official Documentation:
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)
- [Amazon Macie](https://docs.aws.amazon.com/macie/)

### Compliance:
- LGPD (Lei Geral de Proteção de Dados — Brazil)
- GDPR (General Data Protection Regulation)
- PCI DSS (Payment Card Industry Data Security Standard)
- HIPAA (Health Insurance Portability and Accountability Act)

---

## 🎯 Improvements Summary

| Aspect | v2.0 | v3.0 |
|--------|------|------|
| **Categories** | 7 basic | 15+ detailed |
| **Credential Patterns** | 5 | 20+ |
| **CVSS Score** | Generic | Custom 0-10 |
| **Recommendations** | Fixed | Dynamic per finding |
| **Dashboard** | Basic | Enterprise (responsive) |
| **Charts** | 2 simple | 3 interactive |
| **Export** | JSON/HTML | JSON/HTML/CSV |
| **History** | 50 runs | 100 runs |
| **Metadata** | Basic | Expanded (ETag, duration) |
| **Alerts** | Console | Console + Visual (HTML) |

---

**✨ Total Improvements: 50+ features and enhancements!**

**🔐 S3 Security Auditor v3.0 — Enterprise Edition**
*Developed for professional security audits on AWS infrastructure*
