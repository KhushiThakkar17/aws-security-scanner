# 🛡️ AWS Security Misconfiguration Scanner

![Python](https://img.shields.io/badge/Python-3.13-blue)
![AWS](https://img.shields.io/badge/AWS-Boto3-orange)
![Checks](https://img.shields.io/badge/Checks-5%20Services-green)
![Report](https://img.shields.io/badge/Report-HTML%20Dashboard-purple)

A Python-based AWS security auditing tool that automatically scans
cloud infrastructure for misconfigurations across 5 AWS services and
generates a color-coded HTML security report with risk-scored findings.

---

## 🎯 What It Scans

| Service | Checks |
|---------|--------|
| **S3** | Public access, encryption, versioning |
| **IAM Users** | MFA, admin policies, access key age |
| **IAM Policy** | Password length, symbols, rotation |
| **Security Groups** | Dangerous open ports, world-open rules |
| **CloudTrail** | Logging status, log validation |

---

## 📊 Sample Report

Color-coded HTML dashboard with:
- 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low / ✅ Passed findings
- Security score percentage
- Detailed recommendations for each finding

---

## ⚙️ Installation
```bash
git clone https://github.com/KhushiThakkar17/aws-security-scanner.git
cd aws-security-scanner
python3 -m venv venv
source venv/bin/activate
pip install boto3
aws configure
```

## 🚀 Usage
```bash
# Run the scanner
python3 scanner.py

# Generate HTML report
python3 report_generator.py

# Open report in browser
xdg-open aws_security_report.html
```

---

## 🛠️ Tech Stack
- **Language:** Python 3.13
- **AWS SDK:** Boto3
- **Report:** HTML/CSS Dashboard
- **Platform:** Kali Linux

---

## 👩‍💻 Author
**Khushi Thakkar**
M.Eng Cybersecurity — University of Maryland
[LinkedIn](https://linkedin.com/in/khushithakkar17)
