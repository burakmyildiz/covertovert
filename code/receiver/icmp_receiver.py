from scapy.all import IP, ICMP, sniff


def handle_packet(packet):
    if packet.haslayer(ICMP) and packet[IP].ttl == 1:
        packet.show()
        raise SystemExit

sniff(filter="icmp", prn=handle_packet)
