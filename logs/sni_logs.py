import csv
import os

LOG_FILE = "/home/quor/Desktop/firewall/DEFENDER/venv/logs/sni_spoof_log.csv"


def load_logs():

    logs = []

    if not os.path.exists(LOG_FILE):
        print("SNI log not found:", LOG_FILE)
        return logs

    try:

        with open(LOG_FILE, "r") as f:

            reader = csv.reader(f)
            next(reader, None)

            for row in reader:

                if len(row) < 5:
                    continue

                logs.append((
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4]
                ))

    except Exception as e:
        print("Error reading SNI logs:", e)

    return logs


def clear_logs():

    try:

        with open(LOG_FILE, "w", newline="") as f:

            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "client_ip",
                "sni",
                "server_name",
                "result"
            ])

        return True

    except Exception as e:
        print("Error clearing logs:", e)
        return False