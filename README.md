# ExtensionSentry Forensic Grid

Futuristic Django cybersecurity product for static Chrome extension ZIP forensics. Upload an extension archive, watch the processing animation, review deterministic findings, and download a PDF intelligence report.

## Run

```powershell
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

Open `http://127.0.0.1:8000/`.

Demo operator login:

- Email: `analyst@example.com`
- Password: `SecurePass123!`

## Scanner Pipeline

- `scanner/file_handler.py` - safe ZIP extraction, archive limits, manifest discovery
- `scanner/manifest_analyzer.py` - Chrome manifest permissions, CSP, host access, messaging checks
- `scanner/js_analyzer.py` - JavaScript static malware heuristics
- `scanner/communication_analyzer.py` - URLs, domains, IPs, WebSocket and exfil indicators
- `scanner/scoring_engine.py` - deterministic severity scoring
- `scanner/report_generator.py` - PDF intelligence report generation
- `scanner/utils.py` - shared hashing, decoding, entropy, IOC extraction helpers
