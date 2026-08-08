import re
from collections import defaultdict

# Simulated web server log entries
LOG_DATA = [
    '192.168.1.10 - - [10/May/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024',
    '192.168.1.15 - - [10/May/2026:10:00:05 +0000] "POST /login HTTP/1.1" 401 512',
    '192.168.1.15 - - [10/May/2026:10:00:06 +0000] "POST /login HTTP/1.1" 401 512',
    '192.168.1.15 - - [10/May/2026:10:00:07 +0000] "POST /login HTTP/1.1" 401 512',
    '192.168.1.15 - - [10/May/2026:10:00:08 +0000] "POST /login HTTP/1.1" 401 512',
    '192.168.1.15 - - [10/May/2026:10:00:09 +0000] "POST /login HTTP/1.1" 401 512',
    '10.0.0.45 - - [10/May/2026:10:01:22 +0000] "GET /products.php?id=1%27%20OR%201=1-- HTTP/1.1" 200 4096',
    '10.0.0.88 - - [10/May/2026:10:02:10 +0000] "GET /../../etc/passwd HTTP/1.1" 403 256'
]

# Attack Patterns (Signatures)
PATTERNS = {
    "SQL Injection": r"(\%27|\'|UNION|SELECT|OR\%201\%3D1)",
    "Path Traversal": r"(\.\.\/|\.\.\\)"
}

FAILED_LOGIN_THRESHOLD = 5

def analyze_logs():
    failed_logins = defaultdict(int)
    alerts = []

    print("=== Starting Security Log Analysis ===\n")

    for line in LOG_DATA:
        ip = line.split()[0]
        
        # 1. Detect Potential Brute Force Attacks
        if "POST /login" in line and "401" in line:
            failed_logins[ip] += 1
            if failed_logins[ip] == FAILED_LOGIN_THRESHOLD:
                alerts.append(f"[HIGH ALERT] Potential Brute Force attack detected from IP: {ip}")

        # 2. Signature Detection (SQLi, Path Traversal)
        for attack_type, pattern in PATTERNS.items():
            if re.search(pattern, line, re.IGNORECASE):
                alerts.append(f"[CRITICAL] {attack_type} pattern detected from IP: {ip}")

    # Output Results
    if alerts:
        print("Threats Found:")
        for alert in alerts:
            print(f"- {alert}")
    else:
        print("No threats detected.")

if __name__ == "__main__":
    analyze_logs()
