#!/usr/bin/env python3
from scapy.all import *

dst_ip = "8.8.8.8"
max_ttl = 30
timeout = 2

ttl = 1
print(f"Tracing route to {dst_ip}...\n")

while True:
    a = IP(dst=dst_ip, ttl=ttl)
    b = ICMP()
    p = a / b

    pkt = sr1(p, verbose=0, timeout=timeout)

    if pkt is None:
        print(f"TTL: {ttl}, No reply")
    elif pkt[ICMP].type == 0:
        print(f"TTL: {ttl}, Destination reached: {pkt[IP].src}")
        break
    else:
        print(f"TTL: {ttl}, Reply from: {pkt[IP].src}")

    ttl += 1

    if ttl > max_ttl:
        print("\nMax TTL reached — destination unreachable.")
        break
    # Stop if we exceed the maximum TTL
    if ttl > max_ttl:
        print("\nMax TTL reached — destination unreachable.")
        break
