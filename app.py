"""
DFEMS - Digital Forensic Evidence Management System
Main Flask application: routes, auth, upload, hashing, verification.
Database: MongoDB (via pymongo).
"""

import os
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson.objectid import ObjectId
from bson.errors import InvalidId

from utils import generate_file_hash, generate_report_pdf, format_file_size

from db_adapter import get_database

# ---------- Config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "evidence_files")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "dfems")

app = Flask(__name__)
app.config["SECRET_KEY"] = "dfems-college-project-secret-key"  # change for real deployment
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.jinja_env.filters["format_file_size"] = format_file_size

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------- Database initialization (MongoDB with automatic SQLite fallback) ----------
db, is_fallback_db = get_database(BASE_DIR, MONGO_URI, MONGO_DB_NAME)

users_col = db.users
cases_col = db.cases
evidence_col = db.evidence
custody_col = db.custody_log
audit_col = db.audit_log


def init_db():
    """Create indexes (safe to call every startup)."""
    try:
        users_col.create_index("username", unique=True)
    except Exception as e:
        print(f"[DFEMS] MongoDB initialization note: {e}")


# Initialize indexes on app load
init_db()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def oid_or_404(id_str):
    try:
        return ObjectId(id_str)
    except (InvalidId, TypeError):
        abort(404)


def serialize(doc):
    """Add a plain 'id' string field so templates can use doc.id easily."""
    if doc is None:
        return None
    doc["id"] = str(doc["_id"])
    return doc


def serialize_many(cursor):
    return [serialize(d) for d in cursor]


def log_audit(username, action):
    audit_col.insert_one({"username": username, "action": action, "timestamp": now_str()})


def log_custody(evidence_id, username, action):
    custody_col.insert_one({
        "evidence_id": ObjectId(evidence_id) if not isinstance(evidence_id, ObjectId) else evidence_id,
        "username": username,
        "action": action,
        "timestamp": now_str(),
    })


# ---------- User model for Flask-Login ----------
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    try:
        row = users_col.find_one({"_id": ObjectId(user_id)})
    except (InvalidId, TypeError):
        return None
    if row:
        return User(str(row["_id"]), row["username"], row["role"])
    return None


def admin_required(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)

    return wrapper


# ---------- Auth routes ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form.get("role", "investigator")

        if users_col.find_one({"username": username}):
            flash("Username already taken.", "danger")
            return redirect(url_for("signup"))

        users_col.insert_one({
            "username": username,
            "password_hash": generate_password_hash(password),
            "role": role,
        })
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        row = users_col.find_one({"username": username})

        if row and check_password_hash(row["password_hash"], password):
            user = User(str(row["_id"]), row["username"], row["role"])
            login_user(user)
            log_audit(username, "Logged in")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_audit(current_user.username, "Logged out")
    logout_user()
    return redirect(url_for("login"))


# ---------- Dashboard ----------
@app.route("/")
@login_required
def dashboard():
    total_cases = cases_col.count_documents({})
    total_evidence = evidence_col.count_documents({})
    total_custody = custody_col.count_documents({})
    total_audits = audit_col.count_documents({})
    recent_activity = list(audit_col.find().sort("_id", -1).limit(8))

    recent_cases = serialize_many(cases_col.find().sort("_id", -1).limit(4))
    for c in recent_cases:
        c["evidence_count"] = evidence_col.count_documents({"case_id": c["_id"]})

    recent_evidence = serialize_many(evidence_col.find().sort("_id", -1).limit(5))
    for ev in recent_evidence:
        c = cases_col.find_one({"_id": ev.get("case_id")})
        ev["case_title"] = c["title"] if c else "-"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], ev.get("stored_filename", ""))
        ev["file_exists"] = os.path.exists(filepath)
        ev["file_size_bytes"] = os.path.getsize(filepath) if ev["file_exists"] else 0

    return render_template(
        "dashboard.html",
        total_cases=total_cases,
        total_evidence=total_evidence,
        total_custody=total_custody,
        total_audits=total_audits,
        recent_activity=recent_activity,
        recent_cases=recent_cases,
        recent_evidence=recent_evidence,
    )


# ---------- Case management ----------
@app.route("/cases", methods=["GET", "POST"])
@login_required
def cases():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        if not title:
            flash("Case title cannot be empty.", "danger")
            return redirect(url_for("cases"))

        cases_col.insert_one({
            "title": title,
            "description": description,
            "created_by": current_user.username,
            "created_at": now_str(),
        })
        log_audit(current_user.username, f"Created case '{title}'")
        flash(f"Case '{title}' created successfully.", "success")
        return redirect(url_for("cases"))

    all_cases = serialize_many(cases_col.find().sort("_id", -1))
    for c in all_cases:
        c["evidence_count"] = evidence_col.count_documents({"case_id": c["_id"]})
    return render_template("cases.html", cases=all_cases)


@app.route("/case/<case_id>")
@login_required
def case_detail(case_id):
    oid = oid_or_404(case_id)
    case = serialize(cases_col.find_one({"_id": oid}))
    if not case:
        abort(404)
    evidence_list = serialize_many(evidence_col.find({"case_id": oid}).sort("_id", -1))
    for ev in evidence_list:
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], ev.get("stored_filename", ""))
        ev["file_exists"] = os.path.exists(filepath)
        ev["file_size_bytes"] = os.path.getsize(filepath) if ev["file_exists"] else 0
    return render_template("case_detail.html", case=case, evidence_list=evidence_list)


# ---------- Evidence upload ----------
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    all_cases = serialize_many(cases_col.find().sort("_id", -1))
    selected_case_id = request.args.get("case_id", "")

    if request.method == "POST":
        case_id = request.form.get("case_id")
        file = request.files.get("evidence")

        if not case_id:
            flash("Please select a target case.", "danger")
            return redirect(url_for("upload"))

        if not file or file.filename == "":
            flash("Please choose a valid evidence file.", "danger")
            return redirect(url_for("upload", case_id=case_id))

        original_name = secure_filename(file.filename)
        if not original_name:
            original_name = "evidence_file"

        stored_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{original_name}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
        file.save(filepath)

        file_size = os.path.getsize(filepath)
        file_hash = generate_file_hash(filepath)
        case_oid = oid_or_404(case_id)

        result = evidence_col.insert_one({
            "case_id": case_oid,
            "stored_filename": stored_name,
            "original_filename": original_name,
            "file_size": file_size,
            "file_hash": file_hash,
            "uploader": current_user.username,
            "uploaded_at": now_str(),
        })
        evidence_id = result.inserted_id

        log_custody(evidence_id, current_user.username, "Evidence registered & uploaded")
        log_audit(current_user.username, f"Uploaded evidence '{original_name}' (SHA-256: {file_hash[:12]}...)")

        flash(f"Evidence '{original_name}' registered. SHA-256: {file_hash}", "success")
        return redirect(url_for("evidence_detail", evidence_id=str(evidence_id)))

    return render_template("upload.html", cases=all_cases, selected_case_id=selected_case_id)


# ---------- Evidence detail + verify ----------
@app.route("/evidence/<evidence_id>")
@login_required
def evidence_detail(evidence_id):
    oid = oid_or_404(evidence_id)
    ev = serialize(evidence_col.find_one({"_id": oid}))
    if not ev:
        abort(404)
    case = serialize(cases_col.find_one({"_id": ev.get("case_id")}))
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], ev.get("stored_filename", ""))
    ev["file_exists"] = os.path.exists(filepath)
    ev["file_size_bytes"] = os.path.getsize(filepath) if ev["file_exists"] else 0
    custody = serialize_many(custody_col.find({"evidence_id": oid}).sort("_id", 1))
    log_custody(oid, current_user.username, "Evidence record viewed")
    return render_template("evidence_detail.html", ev=ev, case=case, custody=custody)


@app.route("/evidence/<evidence_id>/verify")
@login_required
def verify_evidence(evidence_id):
    oid = oid_or_404(evidence_id)
    ev = evidence_col.find_one({"_id": oid})
    if not ev:
        abort(404)

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], ev["stored_filename"])
    current_hash = None
    if not os.path.exists(filepath):
        result = "missing"
    else:
        current_hash = generate_file_hash(filepath)
        result = "intact" if current_hash == ev["file_hash"] else "tampered"

    log_custody(oid, current_user.username, f"Verification run -> {result}")
    log_audit(current_user.username, f"Verified evidence '{ev['original_filename']}' -> {result}")

    ev_serial = serialize(evidence_col.find_one({"_id": oid}))
    case = serialize(cases_col.find_one({"_id": ev_serial.get("case_id")}))
    ev_serial["file_exists"] = os.path.exists(filepath)
    ev_serial["file_size_bytes"] = os.path.getsize(filepath) if ev_serial["file_exists"] else 0
    custody = serialize_many(custody_col.find({"evidence_id": oid}).sort("_id", 1))

    return render_template(
        "evidence_detail.html",
        ev=ev_serial,
        case=case,
        custody=custody,
        verify_result=result,
        current_hash=current_hash
    )


@app.route("/evidence/<evidence_id>/download")
@login_required
def download_evidence(evidence_id):
    oid = oid_or_404(evidence_id)
    ev = evidence_col.find_one({"_id": oid})
    if not ev:
        abort(404)
    log_custody(oid, current_user.username, "Evidence downloaded")
    log_audit(current_user.username, f"Downloaded evidence '{ev['original_filename']}'")
    return send_from_directory(
        app.config["UPLOAD_FOLDER"], ev["stored_filename"], as_attachment=True,
        download_name=ev["original_filename"]
    )


# ---------- Viva Demonstration: Tamper Simulation & Restoration ----------
@app.route("/evidence/<evidence_id>/tamper")
@login_required
def tamper_evidence(evidence_id):
    oid = oid_or_404(evidence_id)
    ev = evidence_col.find_one({"_id": oid})
    if not ev:
        abort(404)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], ev["stored_filename"])
    backup_path = filepath + ".original"
    if os.path.exists(filepath):
        import shutil
        if not os.path.exists(backup_path):
            shutil.copy2(filepath, backup_path)
        with open(filepath, "ab") as f:
            f.write(b"\n# [ADVERSARY TAMPER INJECTION - DEMO]")
        log_custody(oid, current_user.username, "Adversary Tampering Simulated (File bitstream modified)")
        log_audit(current_user.username, f"Simulated tamper on evidence '{ev['original_filename']}'")
        flash("Demonstration: File was altered on the storage medium! Click 'Run Integrity Verification' to test tamper detection.", "warning")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))


@app.route("/evidence/<evidence_id>/restore")
@login_required
def restore_evidence(evidence_id):
    oid = oid_or_404(evidence_id)
    ev = evidence_col.find_one({"_id": oid})
    if not ev:
        abort(404)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], ev["stored_filename"])
    backup_path = filepath + ".original"
    if os.path.exists(backup_path):
        import shutil
        shutil.copy2(backup_path, filepath)
        log_custody(oid, current_user.username, "File restored to original cryptographic state")
        log_audit(current_user.username, f"Restored evidence '{ev['original_filename']}' to baseline")
        flash("File successfully restored to original baseline! Click 'Run Integrity Verification' to confirm integrity.", "success")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))


# ---------- Search ----------
@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "").strip()
    case_id_filter = request.args.get("case_id", "").strip()
    all_cases = serialize_many(cases_col.find().sort("title", 1))

    results = []
    if query or case_id_filter:
        filter_conditions = []

        if query:
            matching_case_ids = [c["_id"] for c in cases_col.find(
                {"title": {"$regex": query, "$options": "i"}}
            )]
            query_or = [
                {"original_filename": {"$regex": query, "$options": "i"}},
                {"uploader": {"$regex": query, "$options": "i"}},
                {"file_hash": {"$regex": query, "$options": "i"}},
                {"case_id": {"$in": matching_case_ids}},
            ]
            filter_conditions.append({"$or": query_or})

        if case_id_filter:
            try:
                filter_conditions.append({"case_id": ObjectId(case_id_filter)})
            except (InvalidId, TypeError):
                pass

        if filter_conditions:
            mongo_query = {"$and": filter_conditions} if len(filter_conditions) > 1 else filter_conditions[0]
            cursor = evidence_col.find(mongo_query).sort("_id", -1)

            for ev in cursor:
                ev = serialize(ev)
                case = cases_col.find_one({"_id": ev["case_id"]})
                ev["case_title"] = case["title"] if case else "-"
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], ev.get("stored_filename", ""))
                ev["file_exists"] = os.path.exists(filepath)
                ev["file_size_bytes"] = os.path.getsize(filepath) if ev["file_exists"] else 0
                results.append(ev)

    return render_template(
        "search.html",
        query=query,
        case_id_filter=case_id_filter,
        cases=all_cases,
        results=results
    )


# ---------- Audit logs (admin only) ----------
@app.route("/audit")
@login_required
@admin_required
def audit_logs():
    logs = serialize_many(audit_col.find().sort("_id", -1))
    return render_template("audit_logs.html", logs=logs)


# ---------- Report generation ----------
@app.route("/case/<case_id>/report")
@login_required
def case_report(case_id):
    oid = oid_or_404(case_id)
    case = cases_col.find_one({"_id": oid})
    if not case:
        abort(404)
    evidence_list = list(evidence_col.find({"case_id": oid}).sort("_id", 1))

    evidence_with_logs = []
    for ev in evidence_list:
        custody = list(custody_col.find({"evidence_id": ev["_id"]}).sort("_id", 1))
        evidence_with_logs.append((ev, custody))

    pdf_path = generate_report_pdf(case, evidence_with_logs, BASE_DIR)
    log_audit(current_user.username, f"Generated report for case '{case['title']}'")
    return send_from_directory(
        os.path.dirname(pdf_path), os.path.basename(pdf_path), as_attachment=True
    )


# ---------- Error handlers ----------
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access denied. Administrator privileges required."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="The requested forensic record or page was not found."), 404


@app.errorhandler(PyMongoError)
def database_error(e):
    return render_template(
        "error.html",
        code=500,
        message="Database connection error. Please ensure your cloud MongoDB (MongoDB Atlas) connection string is set in Render environment variables (MONGO_URI)."
    ), 500


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="An internal system exception occurred in the evidence engine."), 500


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
