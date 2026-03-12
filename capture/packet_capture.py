from scapy.all import sniff, IP, TCP, UDP
import queue

packet_queue = queue.Queue()

def packet_capture_handler(pkt):

    if IP in pkt:

        proto = "IP"
        port = ""

        if TCP in pkt:
            proto = "TCP"
            port = pkt[TCP].dport

        elif UDP in pkt:
            proto = "UDP"
            port = pkt[UDP].dport

        packet_queue.put((
            pkt[IP].src,
            pkt[IP].dst,
            proto,
            port,
            len(pkt)
        ))

def start_capture():

    sniff(
        iface=["enp0s3","enp0s8"],
        prn=packet_capture_handler,
        store=False
    )