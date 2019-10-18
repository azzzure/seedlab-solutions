#!/usr/bin/python
from scapy.all import *
a = IP()
a.show()
def print_pkt(pkt):
    pkt.show()
##pkt=sniff(filter='tcp and port 23',prn=print_pkt)##1.1B
##pkt=sniff(filter='icmp',prn=print_pkt)##1.1A

pkt=sniff(filter='ICMP',prn=print_pkt)##1.1A