import os
from pathlib import Path
from datetime import timedelta
from functools import wraps

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from backend.auth_service import AuthService
from backend.enterprise_integrations import EnterpriseExporter, EnterprisePushClient
from backend.file_ingestion import LogFileReader
from backend.forensic_correlation import ForensicCorrelationEngine
from backend.investigation_service import InvestigationService
from backend.log_parser import LogParser
from backend.logmind_assistant import LogMindAssistant
from backend.reporting import ReportExporter
from backend.repository import LogRepository
from backend.scoring import CompositeRiskScorer, EventClassifier, EventScoringService, HeuristicRiskScorer, LstmRiskScorer
from backend.security import AuditLogger, apply_security_headers, csrf_token, is_valid_csrf
from backend.summary import InvestigationSummary
from backend.user_repository import UserRepository


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "forensics.db"
AUDIT_LOG_PATH = BASE_DIR / "data" / "audit.log"

repository = LogRepository(DB_PATH)
user_repository = UserRepository(DB_PATH)
auth_service = AuthService(user_repository)
audit_logger = AuditLogger(AUDIT_LOG_PATH)
summary_builder = InvestigationSummary()
report_exporter = ReportExporter()
enterprise_exporter = EnterpriseExporter()
enterprise_push_client = EnterprisePushClient(enterprise_exporter)
file_reader = LogFileReader()
correlation_engine = ForensicCorrelationEngine()
logmind_assistant = LogMindAssistant(correlation_engine)
investigation_service = InvestigationService(
    parser=LogParser(),
    scoring_service=EventScoringService(
        risk_scorer=CompositeRiskScorer(LstmRiskScorer(), HeuristicRiskScorer()),
        classifier=EventClassifier(),
    ),
    repository=repository,
    summary_builder=summary_builder,
)

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "frontend" / "templates"),
    static_folder=str(BASE_DIR / "frontend" / "static"),
)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    app.secret_key = "dev-only-secret"
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("SECRET_KEY must be set in production.")
app.config.update(
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_BYTES", 5 * 1024 * 1024)),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30"))),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
)


@app.after_request
def add_security_headers(response):
    return apply_security_headers(response)


@app.before_request
def protect_mutating_requests():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    if not is_valid_csrf():
        return jsonify({"error": "Invalid or missing CSRF token"}), 400
    return None


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(error):
    max_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    return jsonify({"error": f"Uploaded data is too large. Maximum allowed size is {max_mb} MB."}), 413


def init_db():
    repository.initialize()
    user_repository.initialize()
    user_repository.ensure_default_users()


def request_filters():
    return {
        "search": request.args.get("search", ""),
        "verdict": request.args.get("verdict", ""),
        "severity": request.args.get("severity", ""),
        "source_ip": request.args.get("source_ip", ""),
        "event_type": request.args.get("event_type", ""),
    }


def case_events_for_correlation(case_id: int):
    return repository.query_events(case_id, {}, limit=10000)


def case_events_for_export(case_id: int):
    return repository.query_events(case_id, request_filters(), limit=10000)


def requested_log_type(default="generic"):
    value = (request.form.get("log_type") if request.form else None) or default
    return value if value in LogParser.PARSER_REGISTRY else "generic"


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            if request.path.startswith(("/cases", "/upload", "/get", "/export", "/clear")):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))
        return view_function(*args, **kwargs)

    return wrapped_view


def require_case(case_id: int):
    if not repository.case_exists(case_id):
        return jsonify({"error": "Case not found"}), 404
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = auth_service.authenticate(username, password)

        if user:
            auth_service.create_session(user)
            audit_logger.record("login", details={"username": username})
            return redirect(url_for("dashboard"))

        audit_logger.record("login", status="failure", details={"username": username})
        error = "Invalid username or password"

    return render_template("login.html", error=error, csrf_token=csrf_token())


@app.get("/logout")
def logout():
    audit_logger.record("logout")
    auth_service.clear_session()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template(
        "index.html",
        username=session["username"],
        role=session["role"],
        csrf_token=csrf_token(),
    )


@app.get("/cases")
@login_required
def list_cases():
    return jsonify({"cases": repository.list_cases()})


@app.post("/cases")
@login_required
def create_case():
    payload = request.get_json(force=True)
    title = (payload.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Case title is required"}), 400

    case = repository.create_case(
        title=title,
        description=(payload.get("description") or "").strip(),
    )
    audit_logger.record("case_create", details={"case_id": case["id"], "title": case["title"]})
    return jsonify({"case": case}), 201


@app.post("/cases/<int:case_id>/upload_logs")
@login_required
def upload_logs(case_id):
    denied = require_case(case_id)
    if denied:
        return denied

    payload = request.get_json(force=True)
    logs = payload.get("logs", "")
    log_type = payload.get("log_type", "generic")
    if log_type not in LogParser.PARSER_REGISTRY:
        log_type = "generic"
    result = investigation_service.ingest(logs, case_id, log_type=log_type)
    audit_logger.record(
        "upload_logs",
        details={"case_id": case_id, "log_type": log_type, "event_count": len(result["events"])},
    )
    return jsonify({"status": "processed", "summary": result["summary"], "events": result["events"][:50]})


@app.post("/cases/<int:case_id>/upload_file")
@login_required
def upload_file(case_id):
    denied = require_case(case_id)
    if denied:
        return denied

    uploaded_file = request.files.get("file")
    if not uploaded_file:
        return jsonify({"error": "No log file was uploaded."}), 400

    original_filename = uploaded_file.filename or "uploaded.log"
    safe_filename = secure_filename(original_filename) or "uploaded.log"
    log_type = requested_log_type()
    try:
        logs = file_reader.read(safe_filename, uploaded_file.read())
    except ValueError as exc:
        audit_logger.record(
            "upload_file",
            status="failure",
            details={"case_id": case_id, "filename": safe_filename, "log_type": log_type, "reason": str(exc)},
        )
        return jsonify({"error": str(exc)}), 400

    result = investigation_service.ingest(logs, case_id, log_type=log_type)
    audit_logger.record(
        "upload_file",
        details={
            "case_id": case_id,
            "filename": safe_filename,
            "log_type": log_type,
            "event_count": len(result["events"]),
        },
    )
    return jsonify({"status": "processed", "summary": result["summary"], "events": result["events"][:50]})


@app.get("/cases/<int:case_id>/results")
@login_required
def get_results(case_id):
    denied = require_case(case_id)
    if denied:
        return denied

    limit = min(max(int(request.args.get("limit", 250)), 1), 1000)
    return jsonify(investigation_service.search(case_id, request_filters(), limit=limit))


@app.get("/cases/<int:case_id>/timeline")
@login_required
def forensic_timeline(case_id):
    denied = require_case(case_id)
    if denied:
        return denied

    timeline = correlation_engine.build_timeline(case_events_for_correlation(case_id))
    return jsonify(timeline)


@app.post("/cases/<int:case_id>/ask")
@login_required
def ask_case(case_id):
    denied = require_case(case_id)
    if denied:
        return denied

    payload = request.get_json(force=True)
    query = (payload.get("query") or "").strip()
    if not query:
        return jsonify({"error": "Question is required"}), 400

    answer = logmind_assistant.answer(case_events_for_correlation(case_id), query)
    audit_logger.record("natural_language_query", details={"case_id": case_id, "query": query[:160]})
    return jsonify(answer)


@app.get("/cases/<int:case_id>/export/<file_type>")
@login_required
def export_report(case_id, file_type):
    denied = require_case(case_id)
    if denied:
        return denied

    result = investigation_service.search(case_id, request_filters(), limit=10000)
    summary = result["summary"]
    events = result["events"]
    audit_logger.record(
        "export_report",
        details={"case_id": case_id, "file_type": file_type, "event_count": len(events)},
    )

    if file_type == "json":
        return Response(
            report_exporter.json_report(summary, events),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=forensic_report.json"},
        )

    if file_type == "csv":
        return Response(
            report_exporter.csv_report(events),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=forensic_report.csv"},
        )

    if file_type == "pdf":
        return Response(
            report_exporter.pdf_report(summary, events),
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=forensic_report.pdf"},
        )

    return Response("Unsupported export type", status=400)


@app.get("/cases/<int:case_id>/integrations")
@login_required
def integration_status(case_id):
    denied = require_case(case_id)
    if denied:
        return denied

    return jsonify(
        {
            "formats": EnterpriseExporter.SUPPORTED_FORMATS,
            "push_targets": enterprise_push_client.status(),
        }
    )


@app.get("/cases/<int:case_id>/integrations/export/<target>")
@login_required
def export_integration_payload(case_id, target):
    denied = require_case(case_id)
    if denied:
        return denied

    case = repository.get_case(case_id)
    events = case_events_for_export(case_id)
    try:
        payload = enterprise_exporter.export(target, case, events)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    content_types = {
        "elastic": "application/x-ndjson",
        "splunk": "application/x-ndjson",
        "cef": "text/plain",
        "leef": "text/plain",
        "ndjson": "application/x-ndjson",
    }
    extensions = {
        "elastic": "elastic.ndjson",
        "splunk": "splunk-hec.ndjson",
        "cef": "cef.log",
        "leef": "leef.log",
        "ndjson": "events.ndjson",
    }
    audit_logger.record(
        "integration_export",
        details={"case_id": case_id, "target": target, "event_count": len(events)},
    )
    return Response(
        payload,
        mimetype=content_types.get(target, "text/plain"),
        headers={"Content-Disposition": f"attachment; filename=case_{case_id}_{extensions.get(target, 'integration.txt')}"},
    )


@app.post("/cases/<int:case_id>/integrations/push/<target>")
@login_required
def push_integration_payload(case_id, target):
    denied = require_case(case_id)
    if denied:
        return denied

    case = repository.get_case(case_id)
    events = case_events_for_export(case_id)
    try:
        result = enterprise_push_client.push(target, case, events)
    except ValueError as exc:
        audit_logger.record("integration_push", status="failure", details={"case_id": case_id, "target": target, "reason": str(exc)})
        return jsonify({"error": str(exc), "status": enterprise_push_client.status()}), 400

    audit_logger.record(
        "integration_push",
        status="success" if result.get("ok") else "failure",
        details={"case_id": case_id, "target": target, "event_count": len(events), "status_code": result.get("status_code")},
    )
    http_status = 200 if result.get("ok") else 502
    return jsonify(result), http_status


@app.get("/cases/<int:case_id>/verify_chain")
@login_required
def verify_chain(case_id):
    denied = require_case(case_id)
    if denied:
        return denied

    result = repository.verify_case_chain(case_id)
    audit_logger.record(
        "verify_chain",
        details={"case_id": case_id, "valid": result["valid"], "checked_logs": result["checked_logs"]},
    )
    return jsonify(result)


@app.delete("/cases/<int:case_id>/logs")
@login_required
def clear_logs(case_id):
    denied = require_case(case_id)
    if denied:
        return denied

    repository.clear_case_logs(case_id)
    audit_logger.record("clear_case_logs", details={"case_id": case_id})
    return jsonify({"status": "cleared"})


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
