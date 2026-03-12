from scapy.all import IP, TCP, sniff
import re
import base64
import hashlib
import math
from collections import Counter
from urllib.parse import unquote
from queue import Queue
from xai.xai_engine import generate_explanation
import requests
import os

# ---------------- GUI Queue ----------------

dpi_queue = Queue()

# ---------------- VirusTotal API ----------------

VT_API_KEY = os.getenv("VT_API_KEY")

def check_hash(hash_value):

    if not VT_API_KEY:
        return False

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    headers = {"x-apikey": VT_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=5)

        if r.status_code == 200:
            data = r.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

            if malicious > 0:
                return True
    except:
        pass

    return False


# ---------------- Signature database ----------------

SIGNATURES = [
    b"cmd.exe",
    b"powershell -enc",
    b"/bin/bash",
    b"wget http",
    b"curl http",
    b"nc -e",
]


# ---------------- Attack patterns ----------------

SQLI_PATTERN = re.compile(
rb"(union\s+select|or\s+1=1|or\s+'1'='1'|and\s+1=1|sleep\s*\(|benchmark\s*\(|information_schema|drop\s+table)",
re.I
)

XSS_PATTERN = re.compile(
rb"(<script>|</script>|javascript:|onerror=|onload=|alert\s*\(|document\.cookie)",
re.I
)

PATH_TRAVERSAL = re.compile(
rb"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|system32)",
re.I
)

CMD_INJECTION = re.compile(
rb"(;|\||&&|\$\(|`)\s*(whoami|id|uname|ls|cat|bash|sh|nc|curl|wget|python|perl|php|powershell)",
re.I
)

BASE64_PATTERN = re.compile(rb"(?:[A-Za-z0-9+/]{20,}={0,2})")


# ---------------- Entropy ----------------

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


# ---------------- Base64 detection ----------------

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


# ---------------- Extract HTTP request ----------------

def extract_http_request(payload):

    try:
        text = payload.decode(errors="ignore")

        if "HTTP/" in text and ("GET " in text or "POST " in text):
            return text

    except:
        pass

    return None


# ---------------- Extract URL path + parameters ----------------

def extract_target(request):

    try:

        first_line = request.split("\r\n")[0]

        parts = first_line.split(" ")

        if len(parts) < 2:
            return ""

        return parts[1]

    except:
        pass

    return ""


# ---------------- File hash extraction ----------------

def extract_file_hash(payload):

    if len(payload) < 400:
        return None

    sha256 = hashlib.sha256(payload).hexdigest()
    return sha256


# ---------------- Send to GUI ----------------

def send_to_gui(result):

    dpi_queue.put((
        result["src"],
        result["dst"],
        result["proto"],
        result["len"],
        result["result"],
        result["confidence"]
    ))


# ---------------- Packet inspection ----------------

def inspect_packet(pkt):

    if TCP not in pkt or IP not in pkt:
        return

    # Only inspect HTTP requests
    if pkt[TCP].dport != 80:
        return

    payload = bytes(pkt[TCP].payload)

    if not payload:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    request = extract_http_request(payload)

    if not request:
        return

    target = extract_target(request)

    if not target:
        return

    decoded_target = unquote(target).encode()

    entropy = calculate_entropy(decoded_target)

    features = {
        "entropy": entropy,
        "packet_size": len(payload)
    }


    # ---------------- Signature detection ----------------

    for sig in SIGNATURES:

        if sig in decoded_target:

            result = {
                "src": src,
                "dst": dst,
                "proto": "HTTP",
                "len": len(payload),
                "result": "SIGNATURE_MATCH",
                "confidence": 1.0
            }

            send_to_gui(result)
            generate_explanation(src, dst, "SIGNATURE_MATCH", features)
            return


    # ---------------- SQL Injection ----------------

    if SQLI_PATTERN.search(decoded_target):

        result = {
            "src": src,
            "dst": dst,
            "proto": "HTTP",
            "len": len(payload),
            "result": "SQL_INJECTION",
            "confidence": 0.9
        }

        send_to_gui(result)
        generate_explanation(src, dst, "SQL_INJECTION", features)
        return


    # ---------------- XSS ----------------

    if XSS_PATTERN.search(decoded_target):

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
        return


    # ---------------- Path traversal ----------------

    if PATH_TRAVERSAL.search(decoded_target):

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
        return


    # ---------------- Command injection ----------------

    if CMD_INJECTION.search(decoded_target):

        result = {
            "src": src,
            "dst": dst,
            "proto": "HTTP",
            "len": len(payload),
            "result": "COMMAND_INJECTION",
            "confidence": 0.9
        }

        send_to_gui(result)
        generate_explanation(src, dst, "COMMAND_INJECTION", features)
        return


    # ---------------- Base64 malware ----------------

    if detect_base64(decoded_target):

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
        return


    # ---------------- File hash + VirusTotal ----------------

    file_hash = extract_file_hash(payload)

    if file_hash:

        vt_malicious = check_hash(file_hash)

        if vt_malicious:
            verdict = "KNOWN_MALWARE_HASH"
            confidence = 1.0
        else:
            verdict = f"BENIGN {file_hash[:12]}"
            confidence = 0.7

        result = {
            "src": src,
            "dst": dst,
            "proto": "HTTP",
            "len": len(payload),
            "result": verdict,
            "confidence": confidence
        }

        send_to_gui(result)
        generate_explanation(src, dst, verdict, features)


# ---------------- Start DPI ----------------

def start_dpi():

    sniff(
        prn=inspect_packet,
        store=False
    )