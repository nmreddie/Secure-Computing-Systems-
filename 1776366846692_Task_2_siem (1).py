import re
import sys
import json
from collections import defaultdict
from datetime import datetime

# Verify correct number of command-line arguments
if len(sys.argv) != 3:
    print("Usage: python3 siem.py <log_file> <threshold>")
    sys.exit(1)

input_log_file = sys.argv[1]

# Parse threshold value from arguments
try:
    alert_threshold = int(sys.argv[2])
except ValueError:
    print("Error: Threshold value must be an integer")
    sys.exit(1)

# Data structure to track suspicious activity per IP
attack_records = defaultdict(lambda: {
    "failed_logins": 0,
    "unknown_users": 0,
    "targeted_accounts": set()
})

try:
    # Read and process each line in the log file
    with open(input_log_file, "r") as log:
        for entry in log:

            # Match failed password attempts using regex
            failed_pattern = re.search(
                r"Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)", entry
            )

            # Match invalid/unknown user attempts using regex
            invalid_pattern = re.search(
                r"Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)", entry
            )

            # Record failed login attempt
            if failed_pattern:
                account = failed_pattern.group(1)
                source_ip = failed_pattern.group(2)

                attack_records[source_ip]["failed_logins"] += 1
                attack_records[source_ip]["targeted_accounts"].add(account)

            # Record invalid user attempt
            if invalid_pattern:
                account = invalid_pattern.group(1)
                source_ip = invalid_pattern.group(2)

                attack_records[source_ip]["unknown_users"] += 1
                attack_records[source_ip]["targeted_accounts"].add(account)

    flagged_ips = []

    # Evaluate each IP against the alert threshold
    for source_ip, record in attack_records.items():
        combined_attempts = record["failed_logins"] + record["unknown_users"]

        # Only flag IPs that exceed or meet the threshold
        if combined_attempts >= alert_threshold:

            # Assign severity based on attempt volume
            if combined_attempts >= alert_threshold * 2:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            flagged_ips.append({
                "ip_address": source_ip,
                "failed_logins": record["failed_logins"],
                "unknown_users": record["unknown_users"],
                "total_attempts": combined_attempts,
                "targeted_accounts": list(record["targeted_accounts"]),
                "severity_level": severity
            })

    # Build the final report structure
    final_report = {
        "analysed_file": input_log_file,
        "threshold_applied": alert_threshold,
        "flagged_ip_count": len(flagged_ips),
        "alerts": flagged_ips
    }

    # Generate unique filename using current timestamp
    report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"siem_alert_{report_time}.json"

    # Write the report to a JSON file
    with open(report_filename, "w") as report_file:
        json.dump(final_report, report_file, indent=4)

    print("Log analysis completed successfully")
    print("Alert report saved as:", report_filename)

except FileNotFoundError:
    print("Error: The specified log file could not be found")