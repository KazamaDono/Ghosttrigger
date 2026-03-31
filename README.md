# GhostTrigger

**Automated Detection and Exploitation of Modern Authentication Bypass Vulnerabilities**

GhostTrigger is a security tool that scans web applications for authentication bypass vectors and automatically attempts exploitation. It combines browser-based crawling with a modular detection engine and a clean PyQt6 graphical interface, making it suitable for penetration testers and security engineers.

<img width="2163" height="1326" alt="image" src="https://github.com/user-attachments/assets/7caf05ec-b9d7-4bcc-8819-4ba3639df9a8" />

---

## Features

- **Modern vulnerability coverage**  
  - JWT misconfigurations (`alg:none`, weak signatures, claim injection)  
  - Insecure Direct Object References (IDOR)  
  - Role header injection (X‑Role, X‑Admin, etc.)  
  - GraphQL introspection and data extraction  
  - NoSQL injection in login forms  
  - Server‑Side Request Forgery (SSRF)  
  - Path traversal  
  - Legacy ASP.NET `__doPostBack` analysis  

- **Two interfaces**  
  - **CLI** – quick scans for automation  
  - **GUI** – interactive sessions with live log, results table, and exploit detail view  

- **Automated exploitation** – attempts to weaponize findings (JWT manipulation, IDOR iteration, header injection, etc.)  

- **Professional reporting** – generates detailed markdown reports with remediation advice  

- **Extensible architecture** – add new detection modules or exploit handlers easily  

---

## Installation

### Prerequisites

- Python 3.8 or higher  
- Chrome browser (for Selenium)  
- Pip package manager  

### Clone the repository

```bash
git clone https://github.com/KazamaDono/ghosttrigger.git
cd ghosttrigger
```
### Install dependencies
```bash
pip install -r requirements.txt
```

# Usage
### 1. Configure config.py
Set the url to the target application.

### 2. Run the scanner either as cli or gui

CLI mode:
```bash
python main.py
```
Configure the target and credentials inside config.py or use the GUI to save settings.


GUI mode:
```bash
python gui.py
```
- Enter target URL, optional login credentials, and LLM settings
- Click Start Scan
- View real‑time logs, results table, and detailed exploit info
- Export reports as Markdown

<img width="2384" height="1296" alt="guidemo" src="https://github.com/user-attachments/assets/68612cd4-23ca-41fe-9471-54a9199118c8" />
<img width="1202" height="832" alt="guidemo2" src="https://github.com/user-attachments/assets/c05ece59-99ac-4aca-9543-886499f48b2d" />



# Project Structure
```text
ghosttrigger/ 
├── main.py              # CLI entry point
├── gui.py               # GUI application
├── config.py            # Configuration settings
├── crawler.py           # Selenium‑based page crawler
├── analyzer.py          # Candidate detection logic
├── exploiter.py         # Exploitation engine
├── reporter.py          # Markdown report generator
├── requirements.txt     # Python dependencies
├── README.md            # This file
└── vulnerable_app
    └── app.py           # vulnerable test app set at http://127.0.0.1:5000
```


# Future upgrades
- AI/ML‑powered filtering – use local LLMs (via Ollama) to reduce false positives and prioritize high‑value candidates.
- Automatic exploit chaining – combine low‑severity findings to achieve privilege escalation.
- Additional modules – test for CSRF, open redirects, and business logic flaws.
- Agent‑based scanning – orchestrate multiple scans concurrently for large applications.
- Export to Burp Suite / ZAP – integrate findings into existing penetration testing workflows.

# Important Notes
- Use only on systems you own or have explicit written permission to test. Unauthorized access is illegal.
- The tool performs active exploitation – ensure you have proper authorization before running it against production environments.
- False positives may occur; manual verification of all findings is recommended.














