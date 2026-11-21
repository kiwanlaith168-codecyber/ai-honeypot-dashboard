# AI-Based Intelligent Honeypot Threat Detection and Analysis System

An SSH honeypot with a real-time SOC dashboard. It records every login attempt and command an attacker types, classifies the behavior, scores the risk, and turns raw SSH telemetry into readable threat intelligence.

Graduation project, Department of Cybersecurity, Zarqa University (2025/2026).

## Features

- **SSH honeypot** (Paramiko): fake Ubuntu shell that logs credentials, commands, and timing. Commands are never executed on the host.
- **Hybrid classifier** (no trained ML model):
  - Rule-based engine with 50+ regex attack signatures (recon, brute force, privilege escalation, malware download, lateral movement, exfiltration, persistence)
  - Behavioral scoring that profiles the attacker as bot / script kiddie / experienced human and detects the attack phase (reconnaissance / exploitation / post-compromise)
  - Risk score mapped to Low / Medium / High
- **Optional LLM analysis** (Groq API): a short written analysis per session, with a deterministic fallback when no key is set or the call fails
- **SOC dashboard** (Flask, Chart.js, Leaflet.js): KPIs, attack-type charts, attacker map, live feed via Server-Sent Events, alert acknowledgement
- **Alerts**: mid-session live alerts when risk escalates; optional email
- **PDF reports**: daily reports with attack summaries and recommendations
- **Geolocation** via ip-api.com with caching

## Quick start

```bash
git clone <this-repo>
cd <this-repo>
pip install -r requirements.txt
cp .env.example .env        # then edit .env (optional: add your own GROQ_API_KEY)
python seed_demo_data.py    # optional: fill the dashboard with demo data
python run.py
```

- Dashboard: http://localhost:5000 (log in with `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env`; if the password is empty, a temporary one is printed in the terminal)
- SSH honeypot: `ssh zarqa@localhost -p 2222` (honeypot password is defined in `config.py`)

Keep `dashboard.html` and `login.html` inside a `templates/` folder (Flask loads them from there).

## Project structure

| File | Purpose |
|---|---|
| `honeypot_server.py` | SSH server and fake shell |
| `ai_analyzer.py` | Rule-based attack classification and recommendations |
| `behavior_analyzer.py` | Attacker profiling and attack-phase detection |
| `llm_client.py` | Groq / Google AI client with fallback |
| `app.py` | Flask dashboard and API |
| `database.py` | SQLite layer |
| `alert_system.py`, `traffic_monitor.py` | Alerts and rate-based flags |
| `report_generator.py` | PDF reports |
| `geo.py` | IP geolocation |
| `run.py` | Launcher |

## Security notes

- Secrets are read from environment variables or `.env`. Never commit them.
- The dashboard binds to `127.0.0.1` by default. Run the honeypot on an isolated machine or VM, not on a production host.
- Testing so far used controlled simulations (brute force, recon, malware-download and privilege-escalation commands, concurrent sessions), not live internet traffic.

## Limitations

- SSH only, session level (no packet inspection)
- Fixed behavioral thresholds instead of a trained model
- Geolocation depends on a third-party service and VPN/Tor hides the real origin

## License

MIT
