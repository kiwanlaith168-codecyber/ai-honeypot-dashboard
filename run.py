"""
run.py — Master Launcher v2.0
Starts the SSH honeypot and Flask dashboard in parallel threads.
"""

import sys, os, time, threading, logging, schedule
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("honeypot.launcher")


def start_honeypot():
    from honeypot_server import start_honeypot as _start
    _start()


def start_dashboard():
    from app import app
    from config import FLASK_HOST, FLASK_PORT
    app.run(host=FLASK_HOST, port=FLASK_PORT,
            debug=False, threaded=True, use_reloader=False)


def start_scheduler():
    """Nightly PDF report + DB cleanup."""
    from config import REPORT_SCHEDULE_HOUR
    from report_generator import generate_daily_report
    import database as db

    def nightly():
        try:
            path = generate_daily_report()
            logger.info("Nightly report saved: %s", path)
        except Exception as e:
            logger.error("Report failed: %s", e)
        db.cleanup_old_live_events()

    schedule.every().day.at(f"{REPORT_SCHEDULE_HOUR:02d}:00").do(nightly)
    while True:
        schedule.run_pending()
        time.sleep(60)


def banner():
    from config import HONEYPOT_PORT, FLASK_PORT
    print(f"""
╔══════════════════════════════════════════════════════╗
║      🍯  AI-Powered Honeypot System  v2.0            ║
║      Zarqa University — Cybersecurity Lab            ║
╠══════════════════════════════════════════════════════╣
║  SSH Honeypot  →  port {HONEYPOT_PORT:<5}                        ║
║  Dashboard     →  http://localhost:{FLASK_PORT}              ║
║  Login         →  see ADMIN_USERNAME / ADMIN_PASSWORD║
║  SSH test      →  ssh zarqa@localhost -p {HONEYPOT_PORT}      ║
║  SSH password  →  2026                               ║
╠══════════════════════════════════════════════════════╣
║  LLM: set GROQ_API_KEY env var for AI narratives     ║
║  Seed data: python seed_demo_data.py  (run once)     ║
╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    banner()
    from config import ADMIN_PASSWORD_GENERATED, ADMIN_USERNAME, ADMIN_PASSWORD
    if ADMIN_PASSWORD_GENERATED:
        print(f"[!] ADMIN_PASSWORD not set. Temporary login this run: {ADMIN_USERNAME} / {ADMIN_PASSWORD}\n")

    threads = [
        threading.Thread(target=start_honeypot,  name="honeypot",   daemon=True),
        threading.Thread(target=start_dashboard, name="dashboard",  daemon=True),
        threading.Thread(target=start_scheduler, name="scheduler",  daemon=True),
    ]

    for t in threads:
        t.start()
        logger.info("Started thread: %s", t.name)
        time.sleep(0.4)

    logger.info("All services running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down…")
        sys.exit(0)
