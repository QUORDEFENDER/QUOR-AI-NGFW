import joblib
import pandas as pd
import threading
import time
import numpy as np
from queue import Queue
from capture.packet_capture import packet_queue

flow_queue = Queue()

MODEL_PATH = "models/malicious_traffic_model.pkl"
SCALER_PATH = "models/scaler.pkl"

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

flows = {}
FLOW_TIMEOUT = 5

FLOW_FEATURE_NAMES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward"
]

def run_ml(flow):

    duration = flow["last_seen"] - flow["start_time"]

    if duration <= 0:
        return

    features = [
        duration,
        flow["fwd_packets"],
        flow["bwd_packets"],
        flow["bytes"]/duration,
        flow["packets"]/duration,
        np.mean(flow["lengths"]),
        np.std(flow["lengths"]),
        flow["fin"],
        flow["syn"],
        flow["rst"],
        flow["ack"],
        flow["win_fwd"],
        flow["win_bwd"]
    ]

    X = pd.DataFrame([features], columns=FLOW_FEATURE_NAMES)

    Xs = scaler.transform(X)

    pred = model.predict(Xs)[0]
    conf = model.predict_proba(Xs)[0].max()

    flow_queue.put((
        flow["src"],
        flow["dst"],
        "TCP",
        int(duration),
        "MALICIOUS" if pred else "BENIGN",
        round(conf,3)
    ))

def flow_worker():

    while True:

        src,dst,proto,port,length = packet_queue.get()

        key = (src,dst,proto)

        if key not in flows:

            flows[key] = {
                "src":src,
                "dst":dst,
                "start_time":time.time(),
                "last_seen":time.time(),
                "packets":0,
                "bytes":0,
                "lengths":[],
                "fwd_packets":0,
                "bwd_packets":0,
                "fin":0,
                "syn":0,
                "rst":0,
                "ack":0,
                "win_fwd":0,
                "win_bwd":0
            }

        flow = flows[key]

        flow["packets"] += 1
        flow["bytes"] += length
        flow["lengths"].append(length)
        flow["last_seen"] = time.time()

        if time.time() - flow["start_time"] > FLOW_TIMEOUT:

            run_ml(flow)
            del flows[key]

def start_flow_ids():

    threading.Thread(
        target=flow_worker,
        daemon=True
    ).start()