#!/usr/bin/python
from scapy.all import *
a = IP()
a.show()
def print_pkt(pkt):
    if pkt[IP].src=='10.0.2.132':
        #如果发现目标机器发送icmp报文,则伪造结果并返回.当然,条件也可以写在filter里.
        fake=IP()
        fake.dst=pkt[IP].src
        fake.src=pkt[IP].dst
        #fake.src=pkt.dst
        fakeicmp=pkt[ICMP]
        fakeicmp.type=0
        #fake.src=pkt.dst
        send(fake/fakeicmp)
#
pkt=sniff(filter='icmp',prn=print_pkt)##1.1A

