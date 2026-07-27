# QUOR Project Workflow

## Step 1 – Packet Capture

**Module:** `capture/packet_capture.py`

The firewall continuously monitors the network using **Scapy**. Every incoming and outgoing packet is intercepted before being processed by the firewall.

The `packet_capture_handler()` function extracts:

- Source IP
- Destination IP
- Protocol
- Destination Port
- Raw Packet

Each packet is pushed into a shared queue:

```python
packet_queue.put(...)
```

This queue becomes the input for the remaining modules.

---

## Step 2 – Flow Generation

**Module:** `ids/flow_based_ids.py`

The IDS continuously reads packets from `packet_queue`.

Instead of analysing every packet individually, packets belonging to the same communication session are grouped into a **network flow**.

Each flow is identified using:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol

A timeout mechanism finalizes inactive flows before feature extraction.

---

## Step 3 – Feature Extraction

**Module:** `ids/flow_based_ids.py`

After a flow is completed, statistical features are calculated.

Examples include:

- Flow duration
- Packet count
- Average packet size
- Bytes transferred
- Packet rate
- Protocol type

The generated feature vector is standardized using

```python
scaler.pkl
```

before being sent to the AI model.

---

## Step 4 – AI Intrusion Detection

**Module:** `ids/flow_based_ids.py`

Files used:

```
models/
    malicious_traffic_model.pkl
    scaler.pkl
```

The trained Random Forest model predicts whether the traffic is:

- Benign
- Malicious

Prediction results are forwarded to the XAI module and dashboard.

---

## Step 5 – Deep Packet Inspection (DPI)

**Module:** `dpi/`

The DPI engine performs payload inspection on supported protocols.

It analyses:

- HTTP
- HTTPS
- DNS
- FTP
- SMTP

The payload is inspected using custom signatures and pattern matching to identify malicious content.

Detected threats are reported to the decision engine.

---

## Step 6 – TLS/SNI Spoof Detection

**Module:** `tls_detection/sni_spoof_detector.py`

This module uses **mitmproxy** to inspect encrypted TLS traffic.

Information extracted:

- TLS Certificate
- Certificate Issuer
- Common Name (CN)
- Server Name Indication (SNI)

If the certificate does not match the requested hostname, the session is marked as suspicious.

Logs are written to:

```
sni_spoof_log.csv
```

---

## Step 7 – Ransomware Detection

**Module:**

```
ransomware/
    feature_extractor.py
    ransomware_detector.py
```

Files used:

```
models/model.pkl
```

The detector extracts file features such as:

- Entropy
- File size
- Header information

These features are passed to the trained ransomware classifier.

If malware is detected:

```
⚠ Malware Detected
```

is returned to the dashboard.

---

## Step 8 – Explainable AI

**Module:** `xai/xai_engine.py`

After the IDS predicts malicious traffic, the XAI module explains **why**.

Example explanations include:

- High payload entropy
- Large packet size
- Long flow duration
- Suspicious protocol usage

The explanation is stored inside

```python
xai_queue
```

and displayed on the GUI.

---

## Step 9 – Honeypot

**Module:** `honeypot/honeypot_controller.py`

QUOR starts a Cowrie SSH honeypot whenever suspicious traffic needs further observation.

The controller launches Cowrie using:

```python
subprocess.Popen(...)
```

The honeypot collects:

- Commands executed
- Login attempts
- Uploaded malware
- Attacker IP addresses

This information is used for later analysis.

---

## Step 10 – Threat Intelligence

**Module:** `threat_intelligence/`

The system queries external intelligence feeds such as:

- VirusTotal
- AbuseIPDB
- AlienVault OTX

Indicators checked:

- IP addresses
- Domains
- URLs
- File hashes

Matches increase the threat score before the final decision.

---

## Step 11 – Decision Engine

**Module:** `firewall/`

Results from every security module are combined.

Inputs include:

- AI IDS prediction
- DPI alerts
- TLS/SNI validation
- Threat Intelligence
- Ransomware Detection
- Honeypot observations

The firewall performs one of the following actions:

- Allow
- Block
- Redirect to Honeypot
- Quarantine
- Generate Alert

---

## Step 12 – Dashboard

**Module:** `gui.py`

The Flask dashboard displays:

- Live packet capture
- IDS predictions
- DPI alerts
- TLS/SNI spoof alerts
- Honeypot events
- Ransomware detections
- Explainable AI results
- Threat Intelligence matches

All logs are updated in real time, giving administrators complete visibility into firewall activity.
