from scapy.all import IP, TCP, sniff
import re
import base64
import hashlib
import math
from collections import Counter
from urllib.parse import unquote
from queue import Queue
from xai.xai_engine import generate_explanation

# Queue used by GUI
dpi_queue = Queue()

# ---------------------------------------------------
# Signature database
# ---------------------------------------------------

SIGNATURES = [
    b"cmd.exe",
    b"powershell -enc",
    b"/bin/bash",
    b"wget http",
    b"curl http",
    b"nc -e",
]

# ---------------------------------------------------
# SQL Injection detection
# ---------------------------------------------------

SQLI_PATTERN = re.compile(
    rb"(union\s+select|select\s+.*\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|"
    rb"or\s+1=1|or\s+'1'='1'|and\s+\d+=\d+|and\s+'.+'='.+'|order\s+by\s+\d+|"
    rb"sleep\s*\(|benchmark\s*\(|information_schema|load_file\s*\(|outfile|--|#)",
    re.I
)

# ---------------------------------------------------
# XSS detection
# ---------------------------------------------------

XSS_PATTERN = re.compile(
    rb"(<script[^>]*>|</script>|javascript:|vbscript:|data:text/html|"
    rb"onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|"
    rb"alert\s*\(|prompt\s*\(|confirm\s*\(|document\.cookie|"
    rb"%3cscript|%3e|%3cimg|%3csvg)",
    re.I
)

# ---------------------------------------------------
# Path traversal detection
# ---------------------------------------------------

PATH_TRAVERSAL = re.compile(
    rb"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\|%252e%252e%252f|"
    rb"/etc/passwd|/etc/shadow|/proc/self/environ|"
    rb"boot\.ini|win\.ini|system32|/var/log)",
    re.I
)

# ---------------------------------------------------
# Command injection detection
# ---------------------------------------------------

CMD_INJECTION = re.compile(
    rb"(;|\||&&|\$\(|`)\s*(whoami|id|uname|ls|cat|bash|sh|"
    rb"nc|netcat|curl|wget|python|perl|php|powershell)",
    re.I
)

# ---------------------------------------------------
# Base64 detection
# ---------------------------------------------------

BASE64_PATTERN = re.compile(rb"(?:[A-Za-z0-9+/]{12,}={0,2})")

# ---------------------------------------------------
# Entropy calculation
# ---------------------------------------------------

def calculate_entropy(data):

    if not data:
        return 0

    counter = Counter(data)
    length = len(data)

    entropy = 0

    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


# ---------------------------------------------------
# Base64 malware detection
# ---------------------------------------------------

def detect_base64(payload):

    matches = BASE64_PATTERN.findall(payload)

    for m in matches:

        try:

            decoded = base64.b64decode(m)

            if any(x in decoded for x in [
                b"powershell",
                b"cmd.exe",
                b"/bin/bash",
                b"/bin/sh"
            ]):
                return True

        except:
            pass

    return False


# ---------------------------------------------------
# File hash extraction
# ---------------------------------------------------

def extract_file_hash(payload):

    if len(payload) < 200:
        return None

    sha256 = hashlib.sha256(payload).hexdigest()
    return sha256


# ---------------------------------------------------
# Send detection result to GUI
# ---------------------------------------------------

def send_to_gui(result):

    dpi_queue.put((
        result["src"],
        result["dst"],
        result["proto"],
        result["len"],
        result["result"],
        result["confidence"]
    ))


# ---------------------------------------------------
# DPI packet inspection
# ---------------------------------------------------

def inspect_packet(pkt):

    if TCP not in pkt or IP not in pkt:
        return

    # Ignore encrypted traffic
    if pkt[TCP].dport in [443, 8443] or pkt[TCP].sport in [443, 8443]:
        return

    payload = bytes(pkt[TCP].payload)

    if not payload:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    try:
        decoded_payload = unquote(payload.decode(errors="ignore")).encode()
    except:
        decoded_payload = payload

    entropy = calculate_entropy(payload)

    features = {
        "entropy": entropy,
        "packet_size": len(payload)
    }

    # ---------------------------------------------------
    # Signature detection
    # ---------------------------------------------------

    for sig in SIGNATURES:

        if sig in decoded_payload:

            result = {
                "src": src,
                "dst": dst,
                "proto": "PAYLOAD",
                "len": len(payload),
                "result": "SIGNATURE_MATCH",
                "confidence": 1.0
            }

            send_to_gui(result)

            generate_explanation(src, dst, "SIGNATURE_MATCH", features)

            return result

    # ---------------------------------------------------
    # SQL Injection detection
    # ---------------------------------------------------

    if SQLI_PATTERN.search(decoded_payload):

        features["keyword"] = "SQL"

        result = {
            "src": src,
            "dst": dst,
            "proto": "HTTP",
            "len": len(payload),
            "result": "SQL_INJECTION",
            "confidence": 0.95
        }

        send_to_gui(result)

        generate_explanation(src, dst, "SQL_INJECTION", features)

        return result


    # ---------------------------------------------------
    # XSS detection
    # ---------------------------------------------------

    if XSS_PATTERN.search(decoded_payload):

        features["keyword"] = "XSS"

        result = {
            "src": src,
            "dst": dst,
            "proto": "HTTP",
            "len": len(payload),
            "result": "XSS_ATTACK",
            "confidence": 0.9
        }

        send_to_gui(result)

        generate_explanation(src, dst, "XSS_ATTACK", features)

        return result


    # ---------------------------------------------------
    # Path traversal detection
    # ---------------------------------------------------

    if PATH_TRAVERSAL.search(decoded_payload):

        result = {
            "src": src,
            "dst": dst,
            "proto": "HTTP",
            "len": len(payload),
            "result": "PATH_TRAVERSAL",
            "confidence": 0.9
        }

        send_to_gui(result)

        generate_explanation(src, dst, "PATH_TRAVERSAL", features)

        return result


    # ---------------------------------------------------
    # Command injection detection
    # ---------------------------------------------------

    if CMD_INJECTION.search(decoded_payload):

        features["keyword"] = "COMMAND"

        result = {
            "src": src,
            "dst": dst,
            "proto": "HTTP",
            "len": len(payload),
            "result": "COMMAND_INJECTION",
            "confidence": 0.95
        }

        send_to_gui(result)

        generate_explanation(src, dst, "COMMAND_INJECTION", features)

        return result


    # ---------------------------------------------------
    # Base64 malware detection
    # ---------------------------------------------------

    if detect_base64(decoded_payload):

        result = {
            "src": src,
            "dst": dst,
            "proto": "PAYLOAD",
            "len": len(payload),
            "result": "BASE64_MALWARE",
            "confidence": 0.92
        }

        send_to_gui(result)

        generate_explanation(src, dst, "BASE64_MALWARE", features)

        return result


    # ---------------------------------------------------
    # High entropy detection
    # ---------------------------------------------------

    if len(payload) > 1200 and entropy > 7.9:

        result = {
            "src": src,
            "dst": dst,
            "proto": "PAYLOAD",
            "len": len(payload),
            "result": "HIGH_ENTROPY_PAYLOAD",
            "confidence": round(entropy / 8, 2)
        }

        send_to_gui(result)

        generate_explanation(src, dst, "HIGH_ENTROPY_PAYLOAD", features)

        return result


    # ---------------------------------------------------
    # File transfer detection
    # ---------------------------------------------------

    file_hash = extract_file_hash(payload)

    if file_hash:

        result = {
            "src": src,
            "dst": dst,
            "proto": "HTTP",
            "len": len(payload),
            "result": f"FILE_TRANSFER {file_hash[:12]}",
            "confidence": 0.7
        }

        send_to_gui(result)

        generate_explanation(src, dst, "FILE_TRANSFER", features)

        return result
# ---------------------------------------------------
# Start DPI engine
# ---------------------------------------------------

def start_dpi():

    sniff(
        prn=inspect_packet,
        store=False
    )