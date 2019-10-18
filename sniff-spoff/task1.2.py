#!/usr/bin/python
from scapy.all import *
a = IP()
ls(a)
a.dst='10.0.2.3'
ls(a)
b=ICMP()
p=a/b
send(p)
ls(a)