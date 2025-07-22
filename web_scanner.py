from flask import Flask, request, render_template_string, redirect, url_for
import subprocess
import threading
import time
from collections import defaultdict
import os

app = Flask(__name__)

tool_outputs = defaultdict(str)
lock = threading.Lock()

def run_tool(command, tool_name):
    with lock:
        tool_outputs[tool_name] += f"Running {tool_name}...\n"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=90)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = f"{tool_name} timed out.\n"

    with lock:
        tool_outputs[tool_name] += output
        tool_outputs[tool_name] += f"\n{tool_name} completed.\n\n"

def generate_html(filename):
    with open(filename, "w") as html:
        html.write("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Scan Report</title>
<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    .tool { margin-bottom: 30px; }
    pre { background: #f4f4f4; padding: 10px; border-radius: 5px; white-space: pre-wrap; }
    table { border-collapse: collapse; width: 100%; margin-top: 30px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    tr:nth-child(even) { background-color: #f9f9f9; }
</style>
</head>
<body>
<h1>Vulnerability Scan Report</h1>
""")

        for tool, output in tool_outputs.items():
            html.write(f"<div class='tool'><h2>{tool}</h2><pre>{output}</pre></div>\n")

        findings = []

        if "ASP.NET" in tool_outputs["WhatWeb"]:
            findings.append(("🧬 Technology Disclosure", "ASP.NET version visible", "Medium", "Remove version headers"))
        if "PHP" in tool_outputs["WhatWeb"]:
            findings.append(("🧬 Technology Disclosure", "PHP Detected", "Medium", "Suppress headers or hide tech stack"))

        if "filtered" in tool_outputs["Nmap (Fast)"]:
            findings.append(("🛡️ Blocking", "ICMP/ports filtered", "Low", "May indicate basic hardening"))

        if "+" in tool_outputs["Nikto"]:
            findings.append(("🕵️ Web Server Issues", "Nikto reported potential problems", "High", "Review insecure HTTP methods, headers, etc."))

        if tool_outputs["Nuclei"].strip():
            findings.append(("📄 Vulnerability Matches", "Nuclei reported possible vulnerabilities", "High", "Review findings and patch if needed"))

        html.write("<h2>🧯 Summary of Findings:</h2>\n<table>\n<tr><th>Risk Area</th><th>Issue</th><th>Threat Level</th><th>Suggestion</th></tr>\n")
        if not findings:
            html.write("<tr><td colspan='4'>✅ No major issues found based on scan outputs.</td></tr>\n")
        else:
            for area, issue, level, suggestion in findings:
                html.write(f"<tr><td>{area}</td><td>{issue}</td><td>{level}</td><td>{suggestion}</td></tr>\n")

        html.write("</table>\n</body></html>")

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        url = request.form['url']
        scan_thread = threading.Thread(target=start_scanning, args=(url,))
        scan_thread.start()
        return redirect(url_for('result'))

    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>🌐 Web Vulnerability Scanner</title>
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      padding: 0;
      font-family: "Segoe UI", sans-serif;
      background: linear-gradient(120deg, #89f7fe, #66a6ff);
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      animation: fadeIn 1s ease-in-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .scanner-container {
      background: #ffffff;
      border-radius: 16px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
      padding: 40px;
      width: 90%;
      max-width: 600px;
      text-align: center;
      transition: transform 0.3s ease;
    }
    .scanner-container:hover {
      transform: translateY(-4px);
    }
    h1 {
      color: #333;
      margin-bottom: 20px;
    }
    input[type="text"] {
      padding: 12px;
      width: 80%;
      max-width: 400px;
      border: 2px solid #66a6ff;
      border-radius: 8px;
      font-size: 16px;
      outline: none;
      margin-bottom: 20px;
      transition: box-shadow 0.2s ease;
    }
    input[type="text"]:focus {
      box-shadow: 0 0 10px rgba(102, 166, 255, 0.6);
    }
    button {
      padding: 12px 20px;
      font-size: 16px;
      background-color: #66a6ff;
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: background-color 0.3s ease, transform 0.2s ease;
    }
    button:hover {
      background-color: #558ed8;
      transform: scale(1.05);
    }
    .report {
      margin-top: 30px;
      text-align: left;
      background: #f4f4f4;
      padding: 20px;
      border-radius: 10px;
      max-height: 500px;
      overflow-y: auto;
      white-space: pre-wrap;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      margin-top: 20px;
      border-radius: 8px;
      overflow: hidden;
    }
    th, td {
      padding: 12px;
      border: 1px solid #ccc;
      text-align: left;
    }
    th {
      background-color: #66a6ff;
      color: white;
    }
    tr:nth-child(even) {
      background-color: #f9f9f9;
    }
  </style>
</head>
<body>
  <div class="scanner-container">
    <h1>🌐 Web Vulnerability Scanner</h1>
    <form method="POST">
      <input type="text" name="url" placeholder="http://example.com" required />
      <br>
      <button type="submit">🚀 Start Scan</button>
    </form>
    {% if report %}
      <div class="report">
        <h2>📝 Scan Report</h2>
        {{ report|safe }}
      </div>
    {% endif %}
  </div>
</body>
</html>

    ''')

@app.route('/result')
def result():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Started</title>
    </head>
    <body>
        <h2>✅ Scan started!</h2>
        <p>The vulnerability scan is running in the background. This may take 1-2 minutes.</p>
        <p>Once finished, view your report here:</p>
        <a href="/report" target="_blank">View Report</a>
    </body>
    </html>
    ''')

@app.route('/report')
def report():
    report_path = "vulnerability_report.html"
    if not os.path.exists(report_path):
        return "<h2>Report not ready. Please wait a moment and refresh.</h2>"
    with open(report_path) as f:
        return f.read()

def start_scanning(url):
    tool_outputs.clear()
    target = url.replace("http://", "").replace("https://", "").split("/")[0]

    threads = [
        threading.Thread(target=run_tool, args=(f"timeout 30s whatweb {url}", "WhatWeb")),
        threading.Thread(target=run_tool, args=(f"timeout 60s nikto -host {url} -nointeractive", "Nikto")),
        threading.Thread(target=run_tool, args=(f"timeout 60s nmap -T4 -F {target}", "Nmap (Fast)")),
        threading.Thread(target=run_tool, args=(f"timeout 60s nuclei -u {url} -silent", "Nuclei"))
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    generate_html("vulnerability_report.html")

if __name__ == "__main__":
    app.run(debug=True)

