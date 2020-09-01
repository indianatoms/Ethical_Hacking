#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scpay_packet = scapy.IP(packet.get_payload())
    print(scpay_packet.show())
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()


