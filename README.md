# ExtensionSentry

ExtensionSentry is a cybersecurity-focused web application designed to analyze browser extension packages and detect potential security risks using static analysis techniques.

## Project Overview
Browser extensions often request permissions and execute scripts that are not fully understood by users. ExtensionSentry provides a platform to inspect extension files and evaluate their behavior by analyzing their structure and code.

It helps identify:
- Risky permissions  
- Suspicious scripts  
- Indicators of malicious behavior  

## Problem Statement
- Users install browser extensions without verifying safety  
- Extensions can:
  - Access sensitive data  
  - Track user activity  
  - Inject malicious scripts  
There is no simple and accessible tool to analyze extension files before installation.

## Solution
ExtensionSentry allows users to:
- Upload browser extension files (ZIP/CRX)  
- Extract and analyze internal components  
- Detect:
  - Over-permissioned extensions  
  - Suspicious JavaScript patterns  
- View results through a dashboard  

## Implementation / Architecture
### Workflow:
1. User uploads extension file  
2. System extracts contents  
3. Reads `manifest.json`  
4. Performs:
   - Permission analysis  
   - Script inspection  
5. Applies heuristic rules:
   - Risky APIs (e.g., `eval`)  
   - Excessive permissions  
   - Obfuscated code patterns  
6. Displays results in a dashboard  

## Tech Stack

Backend:
- Python (Django)

Frontend:
- HTML, CSS, JavaScript

Analysis Engine:
- Python-based static analysis  
- Heuristic rule-based detection
  
## Features

- Dashboard UI for analysis results  
- Extension upload and parsing  
- Permission inspection  
- Static JavaScript analysis  
- Risk indication system  

---

## Setup Instructions

```bash
git clone <your-repo-link>
cd ExtensionSentry
pip install -r requirements.txt
python manage.py runserver
