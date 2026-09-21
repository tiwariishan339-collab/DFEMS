# DFEMS – Digital Forensic Evidence Management System

Secure Flask web app to store, track, and verify digital evidence integrity
using SHA-256 hashing, with case management, chain of custody, audit logs,
search, and PDF report generation.

## Setup

**1. Install MongoDB** (if not already installed) and make sure it's running:
```bash
# Windows: install MongoDB Community Server, then it usually runs as a service.
# Mac: brew tap mongodb/brew && brew install mongodb-community && brew services start mongodb-community
# Linux: sudo systemctl start mongod
```
Default connection used by the app: `mongodb://localhost:27017/` (database name: `dfems`).
If your MongoDB runs elsewhere, set an environment variable before running:
```bash
set MONGO_URI=mongodb://localhost:27017/      # Windows
export MONGO_URI="mongodb://localhost:27017/" # Mac/Linux
```

**2. Install Python dependencies and run:**
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** in your browser. Collections (`users`, `cases`,
`evidence`, `custody_log`, `audit_log`) are created automatically in MongoDB
on first use — nothing to set up manually.

## Demo flow (for viva)

1. **Sign up** two accounts — one `admin`, one `investigator`.
2. Login as investigator → **Cases** → create a new case (e.g. "Case #101 – Laptop Seizure").
3. **Upload Evidence** → attach any file to that case. Note the SHA-256 hashpip  shown.
4. Open the evidence page → click **Verify Integrity** → shows ✅ Evidence Intact.
5. Now manually edit the uploaded file inside `evidence_files/` (change even
   one byte) and click **Verify Integrity** again → shows ❌ Evidence Modified.
   This is the core "tamper detection" demo.
6. Check the **Chain of Custody** table on the evidence page — every action
   (upload, view, verify, download) is logged with user + timestamp.
7. Login as admin → **Audit Logs** page shows every system-wide action.
8. Go to a case → **Download PDF Report** → generates a report with case
   info, evidence hashes, and custody logs.
9. Use **Search** to find evidence by filename/uploader/case.

## Project structure

```
dfems/
├── app.py              # All routes, auth, MongoDB logic
├── utils.py            # SHA-256 hashing + PDF report generation
├── requirements.txt
├── evidence_files/     # uploaded evidence stored here
├── reports/            # generated PDF reports (auto-created)
├── templates/          # Jinja2 HTML templates (Bootstrap 5 styled)
└── static/
    └── style.css
```

## Notes

- Uses **MongoDB** (via `pymongo`) exactly as per the synopsis — documents
  are stored as collections, IDs are Mongo `ObjectId`s (shown as hex strings
  in URLs like `/case/<id>`).
- Passwords are hashed with Werkzeug's `generate_password_hash` — never
  stored in plain text.
- SHA-256 hashing is in `utils.py` → `generate_file_hash()` — reads file in
  8KB chunks so it works for large files too.
- If MongoDB isn't running when you start the app, requests will fail with a
  connection error — start `mongod` first.
