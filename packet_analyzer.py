
from scapy.all import IP
from collections import defaultdict
import time

class PacketAnalyzer:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.last_reset_time = time.time()
        self.reset_interval = 60  # Reset counts every 60 seconds
        self.dos_threshold = 100  # Threshold for potential DoS attack

    def analyze_packet(self, packet):
        # Reset packet counts periodically
        current_time = time.time()
        if current_time - self.last_reset_time > self.reset_interval:
            self.packet_counts.clear()
            self.last_reset_time = current_time

        # Count packets from each source IP
        if IP in packet:
            src_ip = packet[IP].src
            self.packet_counts[src_ip] += 1

            # Check for potential DoS attack
            if self.packet_counts[src_ip] > self.dos_threshold:
                return f"Potential DoS attack detected from {src_ip}"

        return "Packet analyzed"
