"""
ICMP Receiver Script
====================

This script listens for incoming ICMP packets and processes the first ICMP request 
packet it receives. It uses the Scapy library to sniff the network and display packet details.

Dependencies:
-------------
- scapy

Usage:
------
Run this script in the 'receiver' container to listen for ICMP packets:
    python icmp_receiver.py

Note:
-----
The script exits automatically after receiving and processing the first ICMP request 
packet with a TTL value of 1.

Functions:
----------
- handle_packet(packet): Callback function that processes the incoming ICMP packet 
  and exits the script after successfully receiving the first one.

"""
from scapy.all import IP, ICMP, sniff


def handle_packet(packet):
    if packet.haslayer(ICMP) and packet[IP].ttl == 1:
        packet.show()
        raise SystemExit

sniff(filter="icmp", prn=handle_packet)
