#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
# 只捕获icmp包
pkt = sniff(iface = "br-57c3e8392f7f", filter = "icmp", prn = print_pkt)

# 抓取tcp包，并且源ip是10.9.0.5，目的端口是23
# pkt = sniff(iface = "br-57c3e8392f7f", filter = "tcp && src host 10.9.0.5 && dst port 23", prn = print_pkt) 
# 在hostA上运行nc -zv 10.9.0.5.23进行测试

# 抓取110.242.68.3(baidu ip address)
# pkt = sniff(iface = "br-57c3e8392f7f", filter = "host 110.242.68.3", prn = print_pkt) 