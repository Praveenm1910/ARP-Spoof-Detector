# ARP Spoof Detector

Overview:

ARPSniffer is a simple command-line tool designed to monitor and detect potential ARP (Address Resolution Protocol) spoofing attacks on a network. The tool listens for ARP packets on a specified network interface and identifies suspicious patterns, alerting the user if it detects potential spoofing. This can be crucial for network administrators who want to ensure the integrity of their local area network (LAN).

The tool uses libpcap to capture network packets and libnotify-bin for sending desktop notifications when a spoofing attack is detected. It works by analyzing ARP request and response packets and comparing the source MAC address with the target IP address to identify inconsistencies.


Features

Sniffs ARP packets on a specified network interface.
Detects potential ARP spoofing attacks based on repeated, unusual ARP responses.
Provides detailed information about the ARP packets including source and target IPs/MACs.
Issues an alert when suspicious ARP activity is detected.
Compatible with Linux-based systems (Ubuntu, Debian, etc.).
Option to display available network interfaces and help options.


Requirements
    
Linux/Ubuntu-based system (should work on any system with libpcap and libnotify support).
libpcap (for packet capturing).
libnotify-bin (for desktop notifications, optional but recommended).
