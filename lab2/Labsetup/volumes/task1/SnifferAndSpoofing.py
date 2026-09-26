#!/usr/bin/env python3
from scapy.all import *

def spoof_reply(pkt):
    src = pkt[IP].src
    dst = pkt[IP].dst
    icmp_id = pkt[ICMP].id
    icmp_seq = pkt[ICMP].seq

    reply = IP(src = dst, dst = src) / ICMP(type = 0) / Raw(load = "Guess what I am!")
    send(reply)
    print(f"[+] 嗅到 {src} -> {dst} (id={icmp_id}, seq={icmp_seq})，已伪造回复")

if __name__ == "__main__":
    print("嗅嗅...")
    sniff(iface = "br-24e94d95f9ab", prn=spoof_reply, filter="icmp and icmp[icmptype]==8", store=0)