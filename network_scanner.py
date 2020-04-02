#!/usr/bin/env python3

import scapy.all as scapy
import argparse


def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('-t', '--target', dest='target', help='IP range to scan. Use cidr notation: 192.168.6.0/24.')
  options = parser.parse_args()
  if not options.target:
    parser.error('[-] Please specify an IP range to scan, see --help for more info.')
  return options


def scan(ip):
  arp_request = scapy.ARP(pdst=ip)
  broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
  arp_request_broadcast = broadcast/arp_request
  answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
  clients_list = []
  for element in answered_list:
    client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}  
    clients_list.append(client_dict)
  return clients_list


def print_result(clients_list):
  print('IP\t\t\tMAC Address\n-----------------------------------------')
  for client in clients_list:
    print(client['ip'] + '\t\t' + client['mac'])


options = parse_args()
print_result(scan(options.target))

