"""
app.py — Flask Admin Dashboard v2.0
NEW: /api/live_stream (SSE from LIVE_EVENT_QUEUE),
     /api/session/<id>/detail,
     /api/attacker_types, /api/attack_phases
"""

import os, json, time, hashlib, logging
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, send_file,
    Response, stream_with_context,
)

import database as db
from report_generator import generate_daily_report
from config import (
    FLASK_HOST, FLASK_PORT, FLASK_SECRET_KEY,
    ADMIN_USERNAME, ADMIN_PASSWORD,
)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = FLASK_SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot.dashboard")
db.init_db()

ADMIN_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()


# ── Auth ──────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def api_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("dashboard") if session.get("admin_logged_in") else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if u == ADMIN_USERNAME and hashlib.sha256(p.encode()).hexdigest() == ADMIN_HASH:
            session["admin_logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": datetime.utcnow().isoformat()})


# ── Data API ──────────────────────────────────────────────────────────────────
@app.route("/api/stats")
@api_auth
def api_stats():
    return jsonify(db.get_dashboard_stats())

@app.route("/api/sessions")
@api_auth
def api_sessions():
    limit = min(int(request.args.get("limit",50)), 200)
    return jsonify(db.get_recent_sessions(limit))

@app.route("/api/session/<int:session_id>/detail")
@api_auth
def api_session_detail(session_id):
    data = db.get_session_detail(session_id)
    return jsonify(data)

@app.route("/api/attack_types")
@api_auth
def api_attack_types():
    return jsonify(db.get_attack_type_distribution())

@app.route("/api/attacker_types")
@api_auth
def api_attacker_types():
    return jsonify(db.get_attacker_type_distribution())

@app.route("/api/attack_phases")
@api_auth
def api_attack_phases():
    return jsonify(db.get_attack_phase_distribution())

@app.route("/api/countries")
@api_auth
def api_countries():
    return jsonify(db.get_country_distribution())

@app.route("/api/timeline")
@api_auth
def api_timeline():
    return jsonify(db.get_attacks_last_7_days())

@app.route("/api/map_markers")
@api_auth
def api_map_markers():
    return jsonify(db.get_map_markers())

@app.route("/api/top_attackers")
@api_auth
def api_top_attackers():
    limit = int(request.args.get("limit",10))
    return jsonify(db.get_top_attackers(limit))

@app.route("/api/alerts")
@api_auth
def api_alerts():
    return jsonify(db.get_recent_alerts(int(request.args.get("limit",20))))

@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
@api_auth
def api_ack_alert(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok"})

@app.route("/api/commands")
@api_auth
def api_commands():
    page     = int(request.args.get("page",1))
    per_page = int(request.args.get("per_page",100))
    return jsonify(db.get_all_commands_paginated(page, per_page))


# ── Standard SSE (stats refresh every 5s) ────────────────────────────────────
@app.route("/api/stream")
@api_auth
def api_stream():
    def gen():
        while True:
            try:
                stats   = db.get_dashboard_stats()
                alerts  = db.get_recent_alerts(3)
                payload = json.dumps({
                    "stats":   stats,
                    "alerts":  alerts,
                    "ts":      datetime.utcnow().isoformat(),
                })
                yield f"data: {payload}\n\n"
            except Exception as exc:
                logger.error("SSE error: %s", exc)
            time.sleep(5)
    return Response(stream_with_context(gen()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


# ── Live events SSE (real-time commands / alerts from LIVE_EVENT_QUEUE) ───────
@app.route("/api/live_stream")
@api_auth
def api_live_stream():
    """
    Streams real-time events from the honeypot:
      - new_connection
      - command (with live risk score)
      - live_alert (mid-session escalation)
      - session_end
    """
    def gen():
        # Import here to avoid circular import
        from honeypot_server import LIVE_EVENT_QUEUE
        import queue as _queue
        while True:
            try:
                event = LIVE_EVENT_QUEUE.get(timeout=15)
                yield f"data: {json.dumps(event)}\n\n"
            except _queue.Empty:
                # Send keepalive comment
                yield ": keepalive\n\n"
            except Exception as exc:
                logger.error("Live SSE error: %s", exc)
                time.sleep(1)
    return Response(stream_with_context(gen()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


# ── PDF Reports ───────────────────────────────────────────────────────────────
@app.route("/api/report/generate", methods=["POST"])
@api_auth
def api_generate_report():
    try:
        date_str = request.json.get("date") if request.is_json else None
        filepath = generate_daily_report(date_str)
        fname    = os.path.basename(filepath)
        return jsonify({"status":"ok","filename":fname,
                        "url":f"/api/report/download/{fname}"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

@app.route("/api/report/download/<filename>")
@api_auth
def api_download_report(filename):
    from config import REPORT_DIR
    fp = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(fp):
        return jsonify({"error":"Not found"}), 404
    return send_file(fp, as_attachment=True,
                     download_name=filename, mimetype="application/pdf")

@app.route("/api/report/list")
@api_auth
def api_list_reports():
    from config import REPORT_DIR
    files = sorted([f for f in os.listdir(REPORT_DIR) if f.endswith(".pdf")], reverse=True)
    return jsonify(files)


if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT,
            debug=False, threaded=True, use_reloader=False)
