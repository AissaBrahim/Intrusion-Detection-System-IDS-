import scapy.all as scapy

class IntrusionDetectionSystem:
    def __init__(self):
        self.suspicious_ips = set()

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            if self.is_suspicious(packet):
                self.alert(ip_src, ip_dst)

    def is_suspicious(self, packet):
        # Example rule: Detect TCP packets with unusual port numbers
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            if tcp_layer.dport not in range(0, 1024):
                return True
        return False

    def alert(self, ip_src, ip_dst):
        print(f"Alert! Suspicious activity detected from {ip_src} to {ip_dst}")
        self.suspicious_ips.add(ip_src)

# Start sniffing packets
ids = IntrusionDetectionSystem()
scapy.sniff(prn=ids.packet_callback, store=0)
