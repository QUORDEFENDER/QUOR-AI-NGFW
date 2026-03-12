from mitmproxy import tls, ctx
from datetime import datetime
import csv
import os

LOG_FILE = "sni_spoof_log.csv"

# ---------------- CSV INIT ----------------
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "time",
            "client_ip",
            "sni",
            "connect_host",
            "result"
        ])

# ---------------- TLS CLIENTHELLO ----------------
def tls_clienthello(data: tls.ClientHelloData):
    try:
        sni = data.client_hello.sni
        if not sni:
            return

        client_ip = data.context.client.peername[0]

        # CONNECT destination (what client thinks it connects to)
        connect_host = data.context.server.address[0]

        spoofed = sni != connect_host
        result = "SNI_SPOOF_DETECTED" if spoofed else "SNI_OK"

        log_msg = (
            f"[{result}] {client_ip} | "
            f"SNI={sni} CONNECT={connect_host}"
        )

        if spoofed:
            ctx.log.warn(log_msg)
        else:
            ctx.log.info(log_msg)

        with open(LOG_FILE, 'a', newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                client_ip,
                sni,
                connect_host,
                result
            ])

    except Exception as e:
        ctx.log.error(f"[SNI ERROR] {e}")