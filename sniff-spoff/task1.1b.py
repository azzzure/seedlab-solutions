#!/usr/bin/python
from scapy.all import *
def print_pkt(pkt):
  pkt1.show()
  pkt2.show()
  pkt3.show()

  
pkt1 = sniff(filter='icmp',prn=print_pkt)
pkt2 = sniff(filter='tcp and port 23',prn=print_pkt)
pkt3 = sniff(filter='net 128.230',prn=print_pkt)