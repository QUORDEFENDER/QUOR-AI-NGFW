import csv

LOG_PATH="/home/quor/Desktop/SNI_LOG/sni_spoof_log.csv"


def load_logs():

    rows=[]

    try:

        with open(LOG_PATH) as f:

            reader=csv.DictReader(f)

            for r in reader:

                rows.append((
                    r["timestamp"],
                    r["client_ip"],
                    r["sni"],
                    r["server_name"],
                    r["result"]
                ))

    except:

        rows.append(("No logs","","","",""))

    return rows