import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
REPORT_FILE    = "aws_security_report.json"
HIGH_RISK_PORTS = [22, 3389, 3306, 5432, 27017, 6379]
# 22=SSH, 3389=RDP, 3306=MySQL, 5432=Postgres
# 27017=MongoDB, 6379=Redis

# Findings storage
findings = {
    "critical": [],
    "high":     [],
    "medium":   [],
    "low":      [],
    "passed":   []
}

# ──────────────────────────────────────────
# HELPER — Add a finding
# ──────────────────────────────────────────
def add_finding(severity, service, issue, resource, recommendation):
    emoji = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🔵",
        "passed":   "✅"
    }
    findings[severity].append({
        "service":        service,
        "issue":          issue,
        "resource":       resource,
        "recommendation": recommendation
    })
    print(f"  {emoji[severity]} [{severity.upper()}] {issue} — {resource}")

# ──────────────────────────────────────────
# CHECK 1 — S3 Bucket Security
# ──────────────────────────────────────────
def check_s3():
    print("\n[*] Scanning S3 Buckets...")
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
        if not buckets:
            print("  ℹ️  No S3 buckets found")
            return

        for bucket in buckets:
            name = bucket["Name"]

            # Check public access block
            try:
                pub    = s3.get_public_access_block(Bucket=name)
                config = pub["PublicAccessBlockConfiguration"]
                all_blocked = all([
                    config.get("BlockPublicAcls",        False),
                    config.get("IgnorePublicAcls",       False),
                    config.get("BlockPublicPolicy",      False),
                    config.get("RestrictPublicBuckets",  False)
                ])
                if all_blocked:
                    add_finding("passed", "S3",
                        "Public access fully blocked",
                        name, "No action needed")
                else:
                    add_finding("critical", "S3",
                        "Public access NOT fully blocked",
                        name,
                        "Enable all 4 public access block settings")
            except ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    add_finding("critical", "S3",
                        "No public access block configured",
                        name,
                        "Enable S3 Block Public Access for this bucket")

            # Check encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
                add_finding("passed", "S3",
                    "Bucket encryption enabled",
                    name, "No action needed")
            except ClientError:
                add_finding("medium", "S3",
                    "Bucket encryption NOT enabled",
                    name,
                    "Enable AES-256 or AWS KMS encryption")

            # Check versioning
            versioning = s3.get_bucket_versioning(Bucket=name)
            status     = versioning.get("Status", "Disabled")
            if status == "Enabled":
                add_finding("passed", "S3",
                    "Versioning enabled", name, "No action needed")
            else:
                add_finding("low", "S3",
                    "Versioning not enabled",
                    name,
                    "Enable versioning to protect against accidental deletion")

    except ClientError as e:
        print(f"  ⚠️  S3 error: {e}")

# ──────────────────────────────────────────
# CHECK 2 — IAM Users
# ──────────────────────────────────────────
def check_iam():
    print("\n[*] Scanning IAM Users...")
    iam = boto3.client("iam")

    try:
        users = iam.list_users()["Users"]
        if not users:
            print("  ℹ️  No IAM users found")
            return

        for user in users:
            uname = user["UserName"]

            # Check MFA
            mfa = iam.list_mfa_devices(UserName=uname)["MFADevices"]
            if mfa:
                add_finding("passed", "IAM",
                    "MFA enabled", uname, "No action needed")
            else:
                add_finding("high", "IAM",
                    "MFA NOT enabled",
                    uname,
                    "Enable MFA for all IAM users immediately")

            # Check admin policies
            attached = iam.list_attached_user_policies(
                UserName=uname)["AttachedPolicies"]
            for policy in attached:
                pname = policy["PolicyName"]
                if "Admin" in pname or "FullAccess" in pname:
                    add_finding("high", "IAM",
                        f"Admin/FullAccess policy attached: {pname}",
                        uname,
                        "Apply least privilege — remove unnecessary admin access")

            # Check access key age
            keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
            for key in keys:
                created  = key["CreateDate"].replace(tzinfo=None)
                now      = datetime.now(timezone.utc).replace(tzinfo=None)
                age_days = (now - created).days

                if age_days > 90:
                    add_finding("medium", "IAM",
                        f"Access key older than 90 days ({age_days} days old)",
                        f"{uname} / {key['AccessKeyId']}",
                        "Rotate access keys every 90 days")
                else:
                    add_finding("passed", "IAM",
                        f"Access key age OK ({age_days} days)",
                        f"{uname} / {key['AccessKeyId']}",
                        "No action needed")

    except ClientError as e:
        print(f"  ⚠️  IAM error: {e}")

# ──────────────────────────────────────────
# CHECK 3 — IAM Password Policy
# ──────────────────────────────────────────
def check_password_policy():
    print("\n[*] Scanning IAM Password Policy...")
    iam = boto3.client("iam")

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        # Min length
        if policy.get("MinimumPasswordLength", 0) >= 14:
            add_finding("passed", "IAM",
                "Password length >= 14 chars",
                "Account", "No action needed")
        else:
            add_finding("medium", "IAM",
                f"Password too short (min={policy.get('MinimumPasswordLength')})",
                "Account",
                "Set minimum password length to 14+")

        # Symbols required
        if policy.get("RequireSymbols"):
            add_finding("passed", "IAM",
                "Password requires symbols",
                "Account", "No action needed")
        else:
            add_finding("medium", "IAM",
                "Password does not require symbols",
                "Account",
                "Enforce symbol requirement in password policy")

        # Rotation
        if policy.get("MaxPasswordAge", 999) <= 90:
            add_finding("passed", "IAM",
                "Password rotation enforced",
                "Account", "No action needed")
        else:
            add_finding("medium", "IAM",
                "Password rotation not enforced",
                "Account",
                "Set max password age to 90 days")

    except ClientError:
        add_finding("high", "IAM",
            "No account password policy set",
            "Account",
            "Create a strong IAM password policy immediately")

# ──────────────────────────────────────────
# CHECK 4 — Security Groups
# ──────────────────────────────────────────
def check_security_groups():
    print("\n[*] Scanning Security Groups...")
    ec2 = boto3.client("ec2")

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]

        for sg in sgs:
            sg_id   = sg["GroupId"]
            sg_name = sg["GroupName"]

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort",   65535)
                protocol  = rule.get("IpProtocol", "all")

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")

                    if cidr == "0.0.0.0/0":
                        # Dangerous ports open to world
                        for port in HIGH_RISK_PORTS:
                            if from_port <= port <= to_port:
                                add_finding("critical", "EC2",
                                    f"Port {port} open to entire internet",
                                    f"{sg_name} ({sg_id})",
                                    f"Restrict port {port} to specific IPs only")

                        # All traffic open
                        if protocol == "-1":
                            add_finding("critical", "EC2",
                                "ALL traffic allowed from internet",
                                f"{sg_name} ({sg_id})",
                                "Never allow all inbound traffic from 0.0.0.0/0")

        add_finding("passed", "EC2",
            f"Scanned {len(sgs)} security groups",
            "EC2", "Review findings above")

    except ClientError as e:
        print(f"  ⚠️  EC2 error: {e}")

# ──────────────────────────────────────────
# CHECK 5 — CloudTrail Logging
# ──────────────────────────────────────────
def check_cloudtrail():
    print("\n[*] Scanning CloudTrail...")
    ct = boto3.client("cloudtrail")

    try:
        trails = ct.describe_trails()["trailList"]

        if not trails:
            add_finding("high", "CloudTrail",
                "No CloudTrail trails configured",
                "Account",
                "Enable CloudTrail to log all API activity")
            return

        for trail in trails:
            name   = trail["Name"]
            status = ct.get_trail_status(Name=trail["TrailARN"])

            if status.get("IsLogging"):
                add_finding("passed", "CloudTrail",
                    "Trail actively logging",
                    name, "No action needed")
            else:
                add_finding("high", "CloudTrail",
                    "Trail exists but logging is DISABLED",
                    name,
                    "Enable logging on this CloudTrail trail")

            if trail.get("LogFileValidationEnabled"):
                add_finding("passed", "CloudTrail",
                    "Log file validation enabled",
                    name, "No action needed")
            else:
                add_finding("medium", "CloudTrail",
                    "Log file validation disabled",
                    name,
                    "Enable log file validation to detect tampering")

    except ClientError as e:
        print(f"  ⚠️  CloudTrail error: {e}")

# ──────────────────────────────────────────
# REPORT GENERATOR
# ──────────────────────────────────────────
def generate_report():
    total  = sum(len(v) for v in findings.values())
    issues = total - len(findings["passed"])
    now    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*55}")
    print(f"   📊 AWS SECURITY SCAN REPORT")
    print(f"{'='*55}")
    print(f"   Scan Time    : {now} UTC")
    print(f"   Total Checks : {total}")
    print(f"   Issues Found : {issues}")
    print(f"{'='*55}")
    print(f"   🔴 Critical  : {len(findings['critical'])}")
    print(f"   🟠 High      : {len(findings['high'])}")
    print(f"   🟡 Medium    : {len(findings['medium'])}")
    print(f"   🔵 Low       : {len(findings['low'])}")
    print(f"   ✅ Passed    : {len(findings['passed'])}")
    print(f"{'='*55}\n")

    # Save JSON report
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_checks": total,
            "issues_found": issues,
            "critical":     len(findings["critical"]),
            "high":         len(findings["high"]),
            "medium":       len(findings["medium"]),
            "low":          len(findings["low"]),
            "passed":       len(findings["passed"])
        },
        "findings": findings
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"[+] Full report saved to: {REPORT_FILE}")

# ──────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────
def main():
    print("=" * 55)
    print("   AWS Security Misconfiguration Scanner")
    print("   Checks: S3, IAM, Security Groups, CloudTrail")
    print("=" * 55)

    check_s3()
    check_iam()
    check_password_policy()
    check_security_groups()
    check_cloudtrail()
    generate_report()

if __name__ == "__main__":
    main()
