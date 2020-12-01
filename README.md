# Packet Sniffer
A simple python3 script that sniffs the packets that pass through a specified interface and extracts login information for a website if any.

Note: This program only works if you already have launched an ARP Spoofing or some other kind MiTM attack on the Target machine. Make sure that port forwarding is enabled on your Host machine.

This code uses *scapy* package

Pass the interface on which forwarding is enabled as the argument to the program.

Usage:
> pip3 install -r Requirements.txt

then in *src*;

> python3 packet_sniffer.py -i \<interface>


