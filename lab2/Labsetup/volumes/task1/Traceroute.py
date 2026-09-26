#!/usr/bin/env python3
from scapy.all import *

def traceroute(target, max_hops, timeout):
    print(f"traceroute to {target}, {max_hops} hops max\n")
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst = target, ttl = ttl) / ICMP()
        reply = sr1(pkt, timeout = timeout, verbose = False)

        if reply is None:
            print(f"{ttl:2d} * * * Timeout")
            continue

        src = reply[IP].src
        if reply.haslayer(ICMP):
            t = reply[ICMP].type
            if t == 11:
                print(f"{ttl:2d} {src}")
            elif t == 0:
                print(f"{ttl:2d} {src} reach")
                break
            elif t == 3:
                print(f"{ttl:2d} {src} can't reach")
                break
            else :
                print(f"{ttl:2d} {src} (ICMP type = {t})")
        else :
            print(f"{ttl:2d} {src} Not ICMP")

if __name__ == "__main__":
    # baidu ip: 110.242.68.3
    # host-a ip: 10.9.0.5
    # host-b ip: 10.9.0.6
    traceroute("110.242.68.3", 30, 3)
                
