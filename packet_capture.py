from scapy.all import sniff, IP, TCP
import threading

class PacketSniffer:
    def __init__(self, interface=None, packet_queue=None):
        self.interface = interface
        self.packet_queue = packet_queue
        self.keep_running = True

    def start_capture(self):
        print(f"Packet capturing started on interface: {self.interface if self.interface else 'default'}")
        # Run packet sniffing in a separate thread
        threading.Thread(target=self._sniff_packets).start()

    def _sniff_packets(self):
        try:
            sniff(iface=self.interface, prn=self.process_packet, filter="tcp", stop_filter=lambda x: not self.keep_running)
        except Exception as e:
            print(f"An error occurred during packet sniffing: {e}")

    def stop_capture(self):
        print("Stopping packet capture...")
        self.keep_running = False

    def process_packet(self, packet):
        # Process each packet captured
        if IP in packet and TCP in packet:
            # Extract IP and TCP information and put it in the queue
            if self.packet_queue is not None:
                self.packet_queue.put(packet)
            else:
                print("Packet queue is not initialized.")

# Example usage
if __name__ == "__main__":
    from queue import Queue
    packet_queue = Queue()
    sniffer = PacketSniffer(interface="Wi-Fi", packet_queue=packet_queue)  # Replace "Wi-Fi" with your actual interface
    sniffer.start_capture()
