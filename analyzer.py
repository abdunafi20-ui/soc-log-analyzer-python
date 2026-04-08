import re
from collections import defaultdict

log_file = "log.txt"

failed_attempts = defaultdict(int)
suspicious_ips = []

with open(log_file, "r") as file:
    for line in file:
        # Detect failed login attempts
        if "Failed password" in line:
            ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip:
                ip = ip.group(1)
                failed_attempts[ip] += 1

        # Detect successful login at odd hours (before 6 AM)
        if "Accepted password" in line:
            time_match = re.search(r'\d{2}:(\d{2}):(\d{2})', line)
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)

            if time_match and ip_match:
                hour = int(line.split()[2].split(":")[0])
                ip = ip_match.group(1)

                if hour < 6:
                    suspicious_ips.append(ip)

# Alert Generation
print("\n--- Suspicious Activity Report ---\n")

for ip, count in failed_attempts.items():
    if count > 3:
        print(f"[ALERT] Possible brute-force attack from IP: {ip} ({count} attempts)")

for ip in suspicious_ips:
    print(f"[ALERT] Suspicious login time detected from IP: {ip}")