from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto
        size = len(packet)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        summary = f"[{timestamp}] Src: {src} → Dst: {dst} | Proto: {proto} | Size: {size}B"

        if TCP in packet:
            summary += f" | TCP Port: {packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            summary += f" | UDP Port: {packet[UDP].sport} → {packet[UDP].dport}"

        print(summary)

        if Raw in packet:
            payload = packet[Raw].load
            print(f"   Payload: {payload}\n")

        with open("packet_log.txt", "a") as f:
            f.write(summary + "\n")
            if Raw in packet:
                f.write(f"   Payload: {payload}\n\n")

sniff(filter="ip", prn=process_packet, count=10)
