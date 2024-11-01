"""
ICMP Sender Script
==================

This script sends an ICMP request packet with a Time-To-Live (TTL) value of 1 
to a receiver container. It uses the Scapy library to create and send the packet.

Dependencies:
-------------
- scapy

Usage:
------
Run this script in the 'sender' container to send an ICMP request:
    python icmp_sender.py

"""
from scapy.all import IP, ICMP, send

packet = IP(dst="receiver", ttl=1)/ICMP()
send(packet)