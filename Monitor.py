import unittest
from unittest.mock import patch, MagicMock
import tkinter as tk
from main import NetworkMonitorApp

class TestNetworkMonitorApp(unittest.TestCase):

    def setUp(self):
        self.root = tk.Tk()
        self.app = NetworkMonitorApp(self.root)

    def test_init_widgets(self):
        self.app.init_widgets()
        # Assert that widgets are created, you can check for specific properties
        self.assertIsNotNone(self.app.log_text)
        self.assertIsNotNone(self.app.start_button)
        # Add more assertions as needed

    @patch('main.packet_capture.PacketSniffer')
    def test_start_wifi_intercept(self, mock_sniffer):
        self.app.start_wifi_intercept()
        mock_sniffer.assert_called_with(interface="Wi-Fi", packet_queue=self.app.packet_queue)

    @patch('tkinter.filedialog.asksaveasfilename')
    def test_save_capture(self, mock_save_dialog):
        mock_save_dialog.return_value = 'testpath.txt'
        self.app.save_capture()
        # Check if the file dialog was opened
        mock_save_dialog.assert_called_once()
        # Further assertions can be made based on file writing operations

    @patch('tkinter.filedialog.asksaveasfilename')
    def test_save_capture_as(self, mock_save_dialog):
        mock_save_dialog.return_value = 'testpath.pcap'
        self.app.save_capture_as()
        mock_save_dialog.assert_called_once()
        # Assert pcap file save logic here
