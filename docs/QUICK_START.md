# 🚀 QUICK START — S3 Security Auditor v3.0

## ⚡ Getting Started (5 minutes)

### 1️⃣ Setup

```bash
# Install dependency
pip install requests --break-system-packages

# Create structure
mkdir -p templates reports/history

# Copy dashboard
cp dashboard_improved.html templates/dashboard.html
```

### 2️⃣ Run

```bash
python s3_auditor_improved.py
```

**Input:**
```
🪣 Enter buckets: my-public-bucket
🔢 File limit: [Enter for no limit]
```

### 3️⃣ View

```bash
# Open HTML in browser
open reports/my-public-bucket_*.html

# Or on Windows:
start reports\my-public-bucket_*.html
```

---

## 📊 What to Expect

### Console Output:
```
🔐 S3 SECURITY AUDIT v3.0
==================================
✅ Region: us-east-1
🚨 3 critical files found!
📊 1,500 files processed
⏱️ Duration: 45.2s
```

### HTML Dashboard:
- 📊 **6 metric cards** (total, critical, high, medium, low, score)
- 📈 **3 interactive charts** (severity, category, history)
- 📋 **Full table** with sorting and filters
- 🎯 **Personalized recommendations** based on findings
- 💾 **Export** JSON and CSV

---

## 🚨 Key Findings

### Critical (Immediate Action)
- 🔴 `.env` → Exposed environment variables
- 🔴 `id_rsa` → Private SSH key
- 🔴 `.git/` → Exposed repository
- 🔴 `credentials.json` → AWS/GCP credentials

### High (Prioritize Review)
- ⚠️ `config.yaml` → Sensitive configurations
- ⚠️ `backup.sql` → Database dump
- ⚠️ `app.py` → Exposed source code
- ⚠️ `bundle.js.map` → Exposed source map

---

## 🛡️ Top 5 Immediate Actions

### 1. Remove Critical Files
```bash
# List critical files
grep "CRITICAL" reports/*.json

# Remove from bucket (AWS CLI)
aws s3 rm s3://my-bucket/.env
aws s3 rm s3://my-bucket/id_rsa
```

### 2. Rotate Credentials
```bash
# AWS
aws iam create-access-key --user-name my-user
aws iam delete-access-key --access-key-id AKIA...

# Update your applications!
```

### 3. Block Public Access
```bash
aws s3api put-public-access-block \
  --bucket my-bucket \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 4. Enable Logging
```bash
aws s3api put-bucket-logging \
  --bucket my-bucket \
  --bucket-logging-status file://logging.json
```

### 5. Enable Versioning
```bash
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled
```

---

## 📋 Post-Audit Checklist

### ⚡ Urgent (24h)
- [ ] Remove critical files
- [ ] Rotate exposed credentials
- [ ] Audit CloudTrail logs
- [ ] Enable Block Public Access

### 📅 This Week
- [ ] Enable logging (S3 + CloudTrail)
- [ ] Configure SSE-KMS encryption
- [ ] Implement least-privilege IAM policies
- [ ] Enable versioning

### 🔄 Ongoing
- [ ] Monthly audit
- [ ] CloudWatch monitoring
- [ ] Team training
- [ ] Access review

---

## 🆘 Troubleshooting

### ❌ Error: "Invalid bucket name"
```
Bucket must:
- Have 3-63 characters
- Use only lowercase, numbers, hyphen, dot
- Not start/end with hyphen
- Not contain .. or .- or -.
```

### ❌ Error: "Connection timeout"
```
Causes:
- Bucket does not exist
- Wrong region
- Network issues
- AWS rate limiting

Solution:
- Check bucket name
- Try with --region
- Wait a few minutes
```

### ❌ Error: "Could not verify public access"
```
Cause: Bucket is private or does not exist

OK! This means:
✅ Bucket is protected, OR
❌ Name is incorrect
```

### ❌ Dashboard not loading
```
Check:
1. Does the JSON file exist in the same directory?
2. Is the JSON name correct in the HTML?
3. Opened via http:// (not file://)?

Solution:
# Serve via simple HTTP
python -m http.server 8000
# Open: http://localhost:8000/reports/bucket.html
```

---

## 💡 Pro Tips

### 🎯 Multiple Buckets
```python
buckets = ["bucket1", "bucket2", "bucket3"]
# Enter comma-separated
```

### 📊 Large Buckets
```python
# Limit to 10,000 files for quick test
max_files = 10000
```

### 🔍 Focus on Critical
```python
# In dashboard, click the red "Critical" card
# Shows only critical files with recommendations
```

### 💾 Export for Analysis
```python
# Dashboard → "CSV" button
# Opens in Excel/Google Sheets
# Filter by CVSS > 7.0
```

---

## 🎓 Understanding Scores

### CVSS (0-10)
```
10.0 = .env with AWS_SECRET_KEY
9.5  = id_rsa (SSH key)
9.0  = .git/ exposed
8.0  = config.yaml with DB_PASSWORD
7.0  = sensitive source code
5.0  = documents (may have PII)
2.0  = images/CSS/JS
```

### Overall Risk Score
```
Weighted average of all files

9-10 = 🔴 CRITICAL - Immediate action
7-8  = 🟠 HIGH - Prioritize
5-6  = 🟡 MEDIUM - Review
0-4  = 🟢 LOW - Monitor
```

---

## 📞 Support

### Technical Issues
1. Check Python version (3.7+)
2. Reinstall requests: `pip install requests --force-reinstall`
3. Test with known public bucket
4. Check connectivity: `ping s3.amazonaws.com`

### False Positives
- Adjust `classify_file()` in the code
- Modify CVSS scores by type
- Add exceptions by filename

---

## ⚖️ Responsible Use

### ✅ Allowed
- Audit your own buckets
- Audit company buckets (with authorization)
- Educational purposes in controlled environment
- Authorized security testing

### ❌ Prohibited
- Audit third-party buckets without authorization
- Malicious purposes
- Share reports with sensitive data
- Ignore privacy laws (LGPD/GDPR)

---

## 🎯 Security Goals

### Short Term (1 month)
- Score < 5.0
- Zero critical files
- Block Public Access active
- Logging enabled

### Medium Term (3 months)
- Score < 3.0
- Encryption on 100% of buckets
- Audited IAM policies
- Macie configured

### Long Term (6+ months)
- Score < 2.0
- Automatic compliance (AWS Config)
- Zero policy violations
- Security culture established

---

## 📚 Additional Resources

### AWS Docs
- [S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)

### Complementary Tools
- **AWS CLI** - Bucket management
- **AWS CloudTrail** - API call auditing
- **Amazon Macie** - Sensitive data discovery
- **AWS Config** - Continuous compliance
- **git-secrets** - Prevent secret commits

---

**🔐 S3 Security Auditor v3.0 - Protecting your AWS infrastructure**

*Developed for professional security audits*
