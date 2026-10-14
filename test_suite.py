import os
import sys

# Insert dfems path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "dfems"))

from app import app, db, cases_col, evidence_col, custody_col, audit_col, users_col
from utils import generate_file_hash

print(">>> Starting DFEMS Comprehensive Test Suite...")

client = app.test_client()

# Test 1: Public access to Login and Signup
print("\n[Test 1] Testing unauthenticated routes...")
resp = client.get("/login")
assert resp.status_code == 200, f"Login failed with status {resp.status_code}"
assert b"Forensic Console Login" in resp.data
assert b"Created by Ishan" in resp.data
print("  [PASSED] Login page rendered successfully with 'Created by Ishan'.")

resp = client.get("/signup")
assert resp.status_code == 200, f"Signup failed with status {resp.status_code}"
assert b"Create Forensic Account" in resp.data
print("  [PASSED] Signup page rendered successfully.")

# Test 2: Protected route redirects when not logged in
print("\n[Test 2] Testing authentication protection...")
resp = client.get("/", follow_redirects=False)
assert resp.status_code == 302 and "/login" in resp.headers["Location"]
print("  [PASSED] Unauthenticated dashboard request properly redirects to /login.")

# Test 3: Login as investigator 'ishan'
print("\n[Test 3] Testing authentication as investigator...")
login_resp = client.post("/login", data={"username": "ishan", "password": "123"}, follow_redirects=True)
# If password is known, let's see if 123 works, or let's test creating a dedicated test user
with app.app_context():
    from werkzeug.security import generate_password_hash
    # Ensure test user exists
    users_col.update_one(
        {"username": "test_investigator"},
        {"$set": {"password_hash": generate_password_hash("testpass123"), "role": "investigator"}},
        upsert=True
    )
    users_col.update_one(
        {"username": "test_admin"},
        {"$set": {"password_hash": generate_password_hash("adminpass123"), "role": "admin"}},
        upsert=True
    )

# Login with test_investigator
login_resp = client.post("/login", data={"username": "test_investigator", "password": "testpass123"}, follow_redirects=True)
assert login_resp.status_code == 200
assert b"Investigation Command Center" in login_resp.data
assert b"Created by Ishan" in login_resp.data
print("  [PASSED] Investigator logged in and dashboard rendered with real statistics.")

# Test 4: RBAC - Investigator cannot access /audit
print("\n[Test 4] Testing RBAC restriction (Investigator -> /audit)...")
audit_resp = client.get("/audit")
assert audit_resp.status_code == 403
assert b"Administrator privileges required" in audit_resp.data
print("  [PASSED] Investigator access to /audit was correctly denied with 403 Forbidden.")

# Test 5: Case Docket Creation
print("\n[Test 5] Testing Case Docket Creation...")
case_resp = client.post("/cases", data={
    "title": "Automated Unit Test Docket #909",
    "description": "Test docket created by automated test suite."
}, follow_redirects=True)
assert case_resp.status_code == 200
assert b"Automated Unit Test Docket #909" in case_resp.data
print("  [PASSED] Case docket created and listed.")

# Fetch created case ID
test_case = cases_col.find_one({"title": "Automated Unit Test Docket #909"})
assert test_case is not None
case_id = str(test_case["_id"])

# Test 6: Evidence Registration & SHA-256 Upload
print("\n[Test 6] Testing Evidence Upload & SHA-256 Cryptographic Computation...")
import io
dummy_content = b"CRITICAL FORENSIC EVIDENCE DUMP 2026 - CONFIDENTIAL"
expected_hash = generate_file_hash.__globals__["hashlib"].sha256(dummy_content).hexdigest()

upload_resp = client.post("/upload", data={
    "case_id": case_id,
    "evidence": (io.BytesIO(dummy_content), "network_payload_dump.log")
}, content_type="multipart/form-data", follow_redirects=True)

assert upload_resp.status_code == 200
assert expected_hash.encode() in upload_resp.data
print(f"  [PASSED] Evidence uploaded with verified SHA-256: {expected_hash}")

# Fetch uploaded evidence document
test_ev = evidence_col.find_one({"case_id": test_case["_id"], "original_filename": "network_payload_dump.log"})
assert test_ev is not None
ev_id = str(test_ev["_id"])
stored_path = os.path.join(app.config["UPLOAD_FOLDER"], test_ev["stored_filename"])
assert os.path.exists(stored_path)

# Test 7: Integrity Verification - Untampered File
print("\n[Test 7] Testing True Integrity Verification (Untampered State)...")
verify_resp = client.get(f"/evidence/{ev_id}/verify")
assert verify_resp.status_code == 200
assert b"EVIDENCE INTEGRITY CONFIRMED" in verify_resp.data
assert expected_hash.encode() in verify_resp.data
print("  [PASSED] Integrity check confirmed file is INTACT.")

# Test 8: Tamper Detection (Modify file content on disk)
print("\n[Test 8] Testing Cryptographic Tamper Detection...")
with open(stored_path, "wb") as f:
    f.write(b"TAMPERED EVIDENCE BITSTREAM - ALTERED BY ADVERSARY")

tampered_hash = generate_file_hash(stored_path)
verify_tampered_resp = client.get(f"/evidence/{ev_id}/verify")
assert verify_tampered_resp.status_code == 200
assert b"CRITICAL TAMPER ALERT" in verify_tampered_resp.data
assert tampered_hash.encode() in verify_tampered_resp.data
print(f"  [PASSED] Tamper detected! Live altered hash ({tampered_hash[:12]}...) identified.")

# Test 9: Restore file integrity and re-verify
print("\n[Test 9] Testing Integrity Restoration...")
with open(stored_path, "wb") as f:
    f.write(dummy_content)

verify_restored_resp = client.get(f"/evidence/{ev_id}/verify")
assert verify_restored_resp.status_code == 200
assert b"EVIDENCE INTEGRITY CONFIRMED" in verify_restored_resp.data
print("  [PASSED] Restored file correctly validated as INTACT.")

# Test 10: Search and filter
print("\n[Test 10] Testing Forensic Search...")
search_resp = client.get(f"/search?q=network_payload")
assert search_resp.status_code == 200
assert b"network_payload_dump.log" in search_resp.data
print("  [PASSED] Search by filename returned matching record.")

search_hash_resp = client.get(f"/search?q={expected_hash[:16]}")
assert search_hash_resp.status_code == 200
assert b"network_payload_dump.log" in search_hash_resp.data
print("  [PASSED] Search by SHA-256 hash prefix returned matching record.")

# Test 11: PDF Report Generation
print("\n[Test 11] Testing PDF Report Generation...")
report_resp = client.get(f"/case/{case_id}/report")
assert report_resp.status_code == 200
assert report_resp.content_type == "application/pdf"
assert len(report_resp.data) > 500
print(f"  [PASSED] PDF report generated successfully ({len(report_resp.data)} bytes).")

# Test 12: Admin Audit Trail Access
print("\n[Test 12] Testing Admin Access to Audit Trail...")
client.get("/logout")
admin_login = client.post("/login", data={"username": "test_admin", "password": "adminpass123"}, follow_redirects=True)
assert admin_login.status_code == 200
audit_resp = client.get("/audit")
assert audit_resp.status_code == 200
assert b"System Security Audit Trail" in audit_resp.data
print("  [PASSED] Administrator accessed full security audit logs.")

# Clean up test records
print("\n[Cleanup] Removing automated test records from MongoDB...")
evidence_col.delete_many({"case_id": test_case["_id"]})
cases_col.delete_one({"_id": test_case["_id"]})
custody_col.delete_many({"evidence_id": test_ev["_id"]})
users_col.delete_many({"username": {"$in": ["test_investigator", "test_admin"]}})
if os.path.exists(stored_path):
    os.remove(stored_path)
print("  [PASSED] Test artifacts cleaned up successfully.")

print("\n>>> ALL 12 FORENSIC INTEGRITY & SECURITY TESTS PASSED PERFECTLY! <<<")
