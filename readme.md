🌟 XSecure: Advanced Vulnerability Scanner 🔒
Welcome to XSecure, a state-of-the-art, AI-powered vulnerability scanner designed to fortify web applications and infrastructure! 🚀 Crafted by Sripadkarthik, this Python-based tool leverages the power of agentic AI to deliver in-depth security assessments, prioritized vulnerabilities, actionable remediation plans, and adaptive scan strategies. Secure your digital assets with confidence! 💻

🎯 Key Features

🔍 Comprehensive Scanning: Analyzes DNS, WHOIS, ports, SSL/TLS, HTTP headers, CMS detection, subdomains, directories, web vulnerabilities (XSS, SQLi, CSRF, SSRF, XXE), and API endpoints.
🧠 Agentic AI Integration: Harnesses the Gemini API for intelligent vulnerability prioritization, remediation planning, and adaptive scan suggestions.
📊 Multi-Format Reports: Produces vibrant JSON, HTML, and PDF reports for seamless analysis and sharing.
⚡ Adaptive Scanning: Dynamically suggests and executes follow-up scans based on findings.
🛡️ Robust Security Checks: Validates security headers, SSL configurations, DNSSEC, and more.
⚙️ Customizable: Tailor scans with a config.yaml file for precise control.


🛠️ Installation
Prerequisites
Ensure the following are installed:

Python 3.8+
External Tools:
🌐 nmap for port scanning: Install nmap
🔒 testssl.sh for SSL/TLS analysis: Install testssl.sh
📜 latexmk for PDF reports: Install via TeX Live or MiKTeX


Python Libraries:Install dependencies with:pip install -r requirements.txt



Sample requirements.txt
aiohttp
beautifulsoup4
pyOpenSSL
dnspython
python-whois
nmap
requests
httpx
pyyaml
jinja2
google-generativeai
certifi
cryptography

Gemini API Key
Replace the placeholder in config.yaml with your Gemini API key to enable AI-driven features.

🚀 Usage
Configuration
Customize scans with a config.yaml file. Here's a sample:
timeout: 10
max_redirects: 5
user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36"
max_depth: 3
rate_limit_delay: 0.2
scan_profile: deep
output_formats:
  - json
  - html
  - pdf
wordlist_path: wordlists/common.txt
testssl_path: testssl.sh
gemini_api_key: "YOUR_GEMINI_API_KEY"
payloads:
  xss:
    - "<script>alert('xss')</script>"
    - '""><img src=x onerror=alert(1)>'
    - 'javascript:alert(1)'
  sql_injection:
    - "' OR '1'='1"
    - "' UNION SELECT NULL--"
    - "1' OR SLEEP(5)--"
  traversal:
    - "../../etc/passwd"
    - "../../windows/win.ini"
    - "../config.yaml"
risky_ports:
  21: "FTP - Consider disabling or securing with FTPS"
  22: "SSH - Ensure strong authentication"
  23: "Telnet - Insecure, disable"
  80: "HTTP - Should redirect to HTTPS"
  445: "SMB - Vulnerable if not secured"

Running the Scanner

Save the script as xsecure_main.py.
Install all dependencies.
Run the scanner:python xsecure_main.py


Enter the target URL (e.g., https://example.com).

Example
$ python xsecure_main.py
Enter URL to scan (e.g., https://example.com): https://example.com
Starting security scan for https://example.com (Scan ID: f7b8a2d1-9c4e-4a7b-b1e4-5e2f3d9c8e7a)
...
🎉 Scan completed in 0:00:45.123456
⏱️ Duration: 45.12 seconds
📂 Results saved to: scan_results/f7b8a2d1-9c4e-4a7b-b1e4-5e2f3d9c8e7a.*
🛠️ Remediation plan: scan_results/remediation_plan.txt


📊 Results
Results are stored in the scan_results directory:

JSON Report (<scan_id>.json): Comprehensive scan data in JSON format.
HTML Report (<scan_id>.html): A visually appealing report with color-coded tables for vulnerabilities, remediation plans, and adaptive suggestions.
PDF Report (<scan_id>.pdf): Professional PDF report (requires latexmk).
Remediation Plan (remediation_plan.txt): Actionable steps for critical/high-severity issues.
Feedback Log (agent_feedback.json): Tracks AI agent performance.

Sample Output
=== Scan Summary ===
🎯 Target: https://example.com
🌐 IP Address: 93.184.216.34
⚠️ Vulnerabilities Found: 5
🔴 Critical/High Severity Vulnerabilities:
- XSS: Reflected XSS at https://example.com/login (Severity: high, CVSS: 7.5)
- SQLi: Potential SQLi at https://example.com/search (Severity: critical, CVSS: 9.8)
🌍 Total Subdomains Found: 3
🔌 Open Ports Detected: 2
🛡️ Recommendations: 6

📜 Full report: scan_results/f7b8a2d1-9c4e-4a7b-b1e4-5e2f3d9c8e7a.json
🌐 HTML report: scan_results/f7b8a2d1-9c4e-4a7b-b1e4-5e2f3d9c8e7a.html
📄 PDF report: scan_results/f7b8a2d1-9c4e-4a7b-b1e4-5e2f3d9c8e7a.pdf
🛠️ Remediation plan: scan_results/remediation_plan.txt

Vulnerability Types

🔍 DNS Misconfigurations: Missing SPF/DMARC records.
🔒 SSL/TLS Issues: Expired certificates, weak ciphers/protocols.
🌐 Web Vulnerabilities: XSS, SQL Injection, CSRF, SSRF, XXE.
📂 Sensitive Files: Exposed .env, .git, or configuration files.
🔌 Risky Ports: Open FTP, Telnet, or SMB ports.
🛡️ Security Headers: Missing or misconfigured CSP, HSTS, etc.
🍪 Insecure Cookies & CORS Misconfigurations.


⚡ Adaptive Scanning
The AdaptiveScanAgent dynamically suggests and executes follow-up scans:

🌍 Subdomain Enumeration: Uses larger wordlists for deeper discovery.
🔌 Port Scanning: Detailed version detection on risky ports.
🌐 Web Tests: Additional payloads for XSS and SQL Injection.

Results are included in reports under "Adaptive Scan Results."

🛡️ Security Notes

Ethical Use: Only scan targets with explicit permission. Unauthorized scanning is illegal. ⚠️
Rate Limiting: Configurable rate_limit_delay prevents server overload.
Safe Payloads: Non-destructive payloads ensure safe testing.


📝 Contributing
Want to improve XSecure? Here's how:

Fork the repository.
Create a feature branch: git checkout -b feature/YourFeature.
Commit changes: git commit -m 'Add YourFeature'.
Push: git push origin feature/YourFeature.
Open a Pull Request.


📞 Contact
Developed by: Sripadkarthik📧 Email: sripadkarthik@gmail.com📱 Phone: +91 9398755799🌐 GitHub: Submit issues here

⚠️ Troubleshooting

Missing Dependencies: Verify nmap, testssl.sh, and latexmk. Check scan.log for details.
API Key Issues: Ensure a valid Gemini API key in config.yaml.
PDF Failures: Install latexmk and TeX Live/MiKTeX.
Scan Errors: Confirm network connectivity and target accessibility.


📜 License
Licensed under the MIT License. See the LICENSE file for details.

🔐 Secure the Future with XSecure!Built with 💖 by Sripadkarthik. Let's protect the digital world together! 🌍
