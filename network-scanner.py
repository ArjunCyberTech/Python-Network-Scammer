#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please Specify an target, use --help for more info.")  # code to handle error
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_brodcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_brodcast, timeout=1, verbose=False)[0]
    clients_list =[]
    for element in answered_list:
        clients_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n------------------------------------")
    for client in result_list:
        print(str(client["ip"]) + "\t\t" + str(client["mac"]))

options = get_argument()
scan_result = scan(options.target)
print_result(scan_result)
