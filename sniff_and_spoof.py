#!/usr/bin/env python3
from scapy.all import *

def sniff_and_spoof(packet):
	if ICMP in packet and packet[ICMP].type == 8:
		
		print("Original Packet...")
		print("Source IP: ", packet[IP].src, " , Destination IP: ", packet[IP].dst)
		
		ip = IP(src=packet[IP].dst,dst=packet[IP].src, ihl=packet[IP].ihl)
		icmp = ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)
		
		raw_data = packet[Raw].load
		newpacket = ip/icmp/raw_data
		
		print("Spoofed Packet...")
		print("Source IP: ", newpacket[IP].src, " , Destination IP: ", newpacket[IP].dst)
		
		send(newpacket, verbose=0)
		
pkt = sniff(iface = 'br-80bdba498d57', filter='icmp and host 10.9.0.99', prn=sniff_and_spoof)