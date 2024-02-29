from scapy.all import IP, TCP, Raw

class ThreatDetection:
    def __init__(self):
        self.basic_threat_keywords = ["malicious_keyword"]
        self.advanced_threat_keywords = ["malware", "virus", "exploit", "attack"]

    def detect_threat(self, packet):
        # Basic threat detection logic
        if IP in packet and TCP in packet and Raw in packet:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if any(keyword in payload for keyword in self.basic_threat_keywords):
                print("Basic threat detected in packet:", packet.summary())
                return True
        return False

    def detect_threat_advanced(self, packet):
        # Advanced threat detection logic
        if IP in packet and TCP in packet and Raw in packet:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            for keyword in self.advanced_threat_keywords:
                if keyword in payload:
                    print("Advanced threat detected in packet:", packet.summary())
                    return True
        return False

