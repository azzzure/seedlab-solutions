#!/usr/bin/python
from scapy.all import *
for i in range(30):
    a = IP()
    a.dst='180.101.49.11' #www.baidu.com的ip地址
    a.ttl=i
    b=ICMP()
    send(a/b)