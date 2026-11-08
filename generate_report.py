from html import escape
from urllib.parse import urlsplit
import json
from pathlib import Path
from datetime import datetime

def generate_html(json_file="data/autopilot/latest_fast_scan.json", out_file="data/autopilot/dashboard.html"):
    file_path = Path(json_file)
    if not file_path.exists():
        print("[-] No scan results found to generate dashboard.")
        return

    data = json.loads(file_path.read_text())
    
    # Calculate stats
    high_count = sum(1 for item in data if item.get("severity") in ["HIGH", "CRITICAL"])
    medium_count = sum(1 for item in data if item.get("severity") == "MEDIUM")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Recon Dashboard</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }}
        h1 {{ color: #ffffff; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .stats {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #1e1e1e; padding: 20px; border-radius: 8px; flex: 1; text-align: center; border: 1px solid #333; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .stat-card h3 {{ margin: 0 0 10px 0; color: #888; }}
        .stat-card .value {{ font-size: 2em; font-weight: bold; }}
        .val-high {{ color: #ff4757; }}
        .val-medium {{ color: #ffa502; }}
        .val-total {{ color: #1e90ff; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background-color: #2f3542; color: #ffffff; }}
        tr:hover {{ background-color: #2d2d2d; }}
        .badge {{ padding: 5px 10px; border-radius: 4px; font-weight: bold; font-size: 0.9em; }}
        .badge-CRITICAL {{ background: #ff0000; color: white; }}
        .badge-HIGH {{ background: #ff4757; color: white; }}
        .badge-MEDIUM {{ background: #ffa502; color: black; }}
        .badge-LOW {{ background: #2ed573; color: black; }}
    </style>
</head>
<body>
    <h1>🎯 Bug Bounty Recon Dashboard</h1>
    <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <div class="stats">
        <div class="stat-card">
            <h3>Total Findings</h3>
            <div class="value val-total">{len(data)}</div>
        </div>
        <div class="stat-card">
            <h3>High/Critical</h3>
            <div class="value val-high">{high_count}</div>
        </div>
        <div class="stat-card">
            <h3>Medium</h3>
            <div class="value val-medium">{medium_count}</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Vulnerability Type</th>
                <th>Target URL</th>
                <th>Program</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
"""
    # Sort data: CRITICAL > HIGH > MEDIUM > LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    data.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 99))

    for item in data:
        raw_sev = item.get("severity", "UNKNOWN")
        sev = raw_sev if raw_sev in severity_order else "UNKNOWN"
        item = {k: escape(str(v), quote=True) for k, v in item.items()}
        raw_url = str(item.get("url", ""))
        try:
            parsed = urlsplit(raw_url)
            safe_url = raw_url if parsed.scheme in ("http", "https") and parsed.hostname else "#"
        except ValueError:
            safe_url = "#"
        html += f"""
            <tr>
                <td><span class="badge badge-{sev}">{sev}</span></td>
                <td>{item.get("type", "Unknown")}</td>
                <td><a href="{safe_url}" style="color: #1e90ff; text-decoration: none;" target="_blank" rel="noopener noreferrer">{item.get("url", "-")}</a></td>
                <td>{item.get("program", "-")}</td>
                <td>{item.get("detail", "-")}</td>
            </tr>
"""
    
    html += """
        </tbody>
    </table>
</body>
</html>
"""
    Path(out_file).write_text(html, encoding="utf-8")
    print(f"[+] Dashboard generated successfully at {out_file}")

if __name__ == "__main__":
    generate_html()
