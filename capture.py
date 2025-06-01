from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        print(f"[+] Src IP: {src} → Dst IP: {dst} | Protocol: {proto}", end='')

        if TCP in packet:
            print(" | TCP", end='')
        elif UDP in packet:
            print(" | UDP", end='')
        print()

sniff(filter="ip", prn=process_packet, count=10) 
