#!/usr/bin/env python

import scapy.all as scapy
from optparse import OptionParser

def get_arguments():
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target",
                  help="Target IP or subnet on which the scan will be performed", metavar="TARGET")
    (options,arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify the target of the scan, use --help for more info")
    return options

# Printing function it process the dictionary of clients consisting of IP and MAC address
def print_clients(clients):
    print("-----------------------------------------")
    print("IP\t\t\tMAC ADDRESS")
    print("-----------------------------------------")
    for client in clients:
        print(client["ip"] + "\t\t" + client["mac"])


def parse_arp(ans_list):
    clients_list = []
    for pkt in ans_list:
        clients_dict = {"ip": pkt[1].psrc, "mac": pkt[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list


def scan(ip):
    print("The examined subnet: " + ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # append two packets
    arp_request_broadcast = broadcast / arp_request
    # srp return answered packets[0] and unaswered packets[1]
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # print(answered_list.summary())
    clients = parse_arp(answered_list)
    return clients


#    arp_request_broadcast.show()
#    scapy.ls(scapy.Ether())

options = get_arguments()
#print(options.target)
print_clients(scan(options.target))
