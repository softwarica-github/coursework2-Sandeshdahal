import tkinter as tk
from tkinter import scrolledtext, filedialog
import threading
import queue
from scapy.all import Packet, wrpcap,TCP, UDP, IP
from packet_analyzer import PacketAnalyzer
import packet_capture

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitoring Application")
        self.packet_analyzer = PacketAnalyzer()
        self.packet_queue = queue.Queue()
        self.captured_packets = []
        self.init_widgets()
    def start_wifi_intercept(self):
        self.log_text.insert(tk.END, "Starting Wi-Fi packet capture...\n")
        self.packet_capture_obj = packet_capture.PacketSniffer(interface="Wi-Fi", packet_queue=self.packet_queue)
        self.capture_thread = threading.Thread(target=self.packet_capture_obj.start_capture)
        self.capture_thread.start()
        self.root.after(100, self.process_packets)

    def init_widgets(self):
        # Save, Save As, and New buttons with colors
        tk.Button(self.root, text="Save", command=self.save_capture, bg="#4CAF50", fg="white").grid(row=0, column=0,
                                                                                                    padx=10, pady=10)
        tk.Button(self.root, text="Save As", command=self.save_capture_as, bg="#008CBA", fg="white").grid(row=0,
                                                                                                          column=1,
                                                                                                          padx=10,
                                                                                                          pady=10)
        tk.Button(self.root, text="New", command=self.new_capture, bg="#f44336", fg="white").grid(row=0, column=2,
                                                                                                  padx=10, pady=10)

        # Text box for displaying packet logs
        self.log_text = scrolledtext.ScrolledText(self.root, height=15,bg="light green",fg="black", width=100)
        self.log_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

        # Start and Stop buttons with colors
        self.start_button = tk.Button(self.root, text="Start Capture", command=self.start_packet_capture,
                                      bg="light green", fg="black")
        self.start_button.grid(row=2, column=0, padx=10, pady=10)
        self.stop_button = tk.Button(self.root, text="Stop Capture", command=self.stop_packet_capture, bg="light coral",
                                     fg="black")
        self.stop_button.grid(row=2, column=1, padx=10, pady=10)
        self.analyze_button = tk.Button(self.root, text="Analyze", command=self.analyze_packets, bg="#FFD700",
                                        fg="black")
        self.analyze_button.grid(row=2, column=2, padx=10, pady=10)
        self.wifi_intercept_button = tk.Button(self.root, text="Wi-Fi Intercept", command=self.start_wifi_intercept,
                                               bg="#9C27B0", fg="white")
        self.wifi_intercept_button.grid(row=3, column=0, padx=10, pady=10)

    # ... existing methods ...
    def new_capture(self):
        # Check if a capture is already running, and stop it if necessary
        if hasattr(self, 'capture_thread') and self.capture_thread.is_alive():
            self.packet_capture_obj.stop_capture()
            self.capture_thread.join()

        # Clear the log text and the captured packets list
        self.log_text.delete('1.0', tk.END)
        self.captured_packets.clear()

        # Optionally, you can automatically start a new capture here
        # self.start_packet_capture()

        self.log_text.insert(tk.END, "New capture session started.\n")
    def save_capture(self):
        filepath = filedialog.asksaveasfilename(defaultextension="pcap", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath:
            with open(filepath, 'w') as file:
                file.write(self.log_text.get("1.0", tk.END))

    def save_capture_as(self):
        filepath = filedialog.asksaveasfilename(defaultextension="pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if filepath:
            wrpcap(filepath, self.captured_packets)

    def start_packet_capture(self):
        self.log_text.insert(tk.END, "Starting packet capture...\n")
        self.packet_capture_obj = packet_capture.PacketSniffer(interface="Wi-Fi", packet_queue=self.packet_queue)
        self.capture_thread = threading.Thread(target=self.packet_capture_obj.start_capture)
        self.capture_thread.start()
        self.root.after(100, self.process_packets)

    def stop_packet_capture(self):
        if hasattr(self, 'packet_capture_obj') and self.packet_capture_obj.keep_running:
            self.packet_capture_obj.stop_capture()
            self.capture_thread.join()
            self.log_text.insert(tk.END, "Packet capture stopped.\n")

    def analyze_packets(self):
        detailed_analysis_results = ""
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            result = self.packet_analyzer.analyze_packet(packet)
            if result is None:
                result = "Analysis not available for this packet"
            detailed_analysis_results += result + "\n"

        self.log_text.insert(tk.END, "Analysis Result:\n" + detailed_analysis_results)

    def process_packets(self):
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.log_packet(packet)
            self.packets_for_analysis.append(packet)
        if hasattr(self, 'capture_thread') and self.capture_thread.is_alive():
            self.root.after(100, self.process_packets)

    def process_packets(self):
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.log_packet(packet)
        if self.capture_thread.is_alive():
            self.root.after(100, self.process_packets)

    def log_packet(self, packet):
        if isinstance(packet, Packet):
            self.log_text.insert(tk.END, f"Packet: {packet.summary()}\n")
            self.log_text.see(tk.END)


root = tk.Tk()
app = NetworkMonitorApp(root)
root.mainloop()

if __name__ == "__main__":
 main()