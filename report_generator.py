import json
from datetime import datetime, timezone

# ──────────────────────────────────────────
# Load JSON report
# ──────────────────────────────────────────
with open("aws_security_report.json", "r") as f:
    data = json.load(f)

summary  = data["summary"]
findings = data["findings"]
scantime = data["scan_time"]

# ──────────────────────────────────────────
# Helper — Build findings rows
# ──────────────────────────────────────────
def build_rows(items, badge_class):
    rows = ""
    for item in items:
        rows += f"""
        <tr>
            <td><span class="badge {badge_class}">{badge_class.upper()}</span></td>
            <td>{item['service']}</td>
            <td>{item['issue']}</td>
            <td>{item['resource']}</td>
            <td>{item['recommendation']}</td>
        </tr>"""
    return rows

# ──────────────────────────────────────────
# Build all findings table rows
# ──────────────────────────────────────────
all_rows = ""
all_rows += build_rows(findings["critical"], "critical")
all_rows += build_rows(findings["high"],     "high")
all_rows += build_rows(findings["medium"],   "medium")
all_rows += build_rows(findings["low"],      "low")
all_rows += build_rows(findings["passed"],   "passed")

# ──────────────────────────────────────────
# Calculate security score
# ──────────────────────────────────────────
total   = summary["total_checks"]
passed  = summary["passed"]
score   = int((passed / total) * 100) if total > 0 else 0

if score >= 80:
    score_color = "#2ecc71"
    score_label = "Good"
elif score >= 60:
    score_color = "#f39c12"
    score_label = "Fair"
else:
    score_color = "#e74c3c"
    score_label = "Poor"

# ──────────────────────────────────────────
# Generate HTML
# ──────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #0f1117;
            color: #e0e0e0;
            padding: 30px;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1f2e, #252d3d);
            border: 1px solid #2d3748;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            font-size: 26px;
            color: #fff;
            margin-bottom: 6px;
        }}
        .header p {{
            color: #8892a4;
            font-size: 13px;
        }}
        .score-circle {{
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 6px solid {score_color};
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: #1a1f2e;
        }}
        .score-circle .score-num {{
            font-size: 28px;
            font-weight: bold;
            color: {score_color};
        }}
        .score-circle .score-lbl {{
            font-size: 11px;
            color: #8892a4;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }}
        .summary-card {{
            background: #1a1f2e;
            border: 1px solid #2d3748;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .summary-card .count {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .summary-card .label {{
            font-size: 12px;
            color: #8892a4;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .critical-count {{ color: #e74c3c; }}
        .high-count     {{ color: #e67e22; }}
        .medium-count   {{ color: #f1c40f; }}
        .low-count      {{ color: #3498db; }}
        .passed-count   {{ color: #2ecc71; }}
        .table-container {{
            background: #1a1f2e;
            border: 1px solid #2d3748;
            border-radius: 12px;
            overflow: hidden;
        }}
        .table-header {{
            padding: 20px 25px;
            border-bottom: 1px solid #2d3748;
        }}
        .table-header h2 {{
            font-size: 16px;
            color: #fff;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #252d3d;
            padding: 12px 16px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #8892a4;
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid #1e2535;
            font-size: 13px;
            vertical-align: top;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #1e2535; }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge.critical {{ background: #3d1515; color: #e74c3c; border: 1px solid #e74c3c; }}
        .badge.high     {{ background: #3d2a0f; color: #e67e22; border: 1px solid #e67e22; }}
        .badge.medium   {{ background: #3d350f; color: #f1c40f; border: 1px solid #f1c40f; }}
        .badge.low      {{ background: #0f253d; color: #3498db; border: 1px solid #3498db; }}
        .badge.passed   {{ background: #0f3d1f; color: #2ecc71; border: 1px solid #2ecc71; }}
        .footer {{
            text-align: center;
            margin-top: 25px;
            color: #4a5568;
            font-size: 12px;
        }}
    </style>
</head>
<body>

    <!-- HEADER -->
    <div class="header">
        <div>
            <h1>🛡️ AWS Security Scan Report</h1>
            <p>Scan completed: {scantime}</p>
            <p>Checks performed: S3 • IAM • Security Groups • CloudTrail</p>
        </div>
        <div class="score-circle">
            <span class="score-num">{score}%</span>
            <span class="score-lbl">{score_label}</span>
        </div>
    </div>

    <!-- SUMMARY CARDS -->
    <div class="summary-grid">
        <div class="summary-card">
            <div class="count critical-count">{summary['critical']}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card">
            <div class="count high-count">{summary['high']}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card">
            <div class="count medium-count">{summary['medium']}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card">
            <div class="count low-count">{summary['low']}</div>
            <div class="label">Low</div>
        </div>
        <div class="summary-card">
            <div class="count passed-count">{summary['passed']}</div>
            <div class="label">Passed</div>
        </div>
    </div>

    <!-- FINDINGS TABLE -->
    <div class="table-container">
        <div class="table-header">
            <h2>🔍 Detailed Findings ({summary['total_checks']} total checks)</h2>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Service</th>
                    <th>Issue</th>
                    <th>Resource</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {all_rows}
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p>Generated by AWS Security Misconfiguration Scanner</p>
        <p>Built by Khushi Thakkar | github.com/KhushiThakkar17</p>
    </div>

</body>
</html>"""

# ──────────────────────────────────────────
# Save HTML report
# ──────────────────────────────────────────
with open("aws_security_report.html", "w") as f:
    f.write(html)

print("[+] HTML report generated: aws_security_report.html")
print(f"[+] Security Score: {score}% ({score_label})")
print("[+] Open the file in your browser to view it!")
