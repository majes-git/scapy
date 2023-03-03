#!/usr/bin/env python3

import argparse
from ipaddress import AddressValueError, IPv4Address, IPv4Interface
from scapy.all import conf, get_if_hwaddr, getmacbyip, sendp, Ether, IP, UDP, Raw

from lib.log import error


def parse_arguments():
    """Get commandline arguments."""
    parser = argparse.ArgumentParser(
        description='Send DHCP ACK to client')
    parser.add_argument('-c', '--client', required=True,
                        help='IP address of DHCP Client')
    return parser.parse_args()


def find_interface(client_ip):
    interface, outgoing_ip, gateway = conf.route.route(client_ip)
    mac_address = get_if_hwaddr(interface)
    return interface, mac_address, outgoing_ip


def get_destination_mac_address(destination):
    return getmacbyip(destination)


def send_dhcp_ack(interface, destination_mac_address, mac_address, server_ip, client_ip):
    src_port = 67
    dst_port = 68
    pkt = Ether(dst=destination_mac_address, src=mac_address, type='IPv4')/ \
          IP(dst=client_ip, src=server_ip, proto='udp')/ \
          UDP(sport=src_port, dport=dst_port)/ \
          Raw(load=b'\x02\x01\x06\x01\x11"3D\x00\x00\x00\x00\n\x01\x01\x17\x00\x00\x00\x00\x00\x00\x00\x00\n\x01\x01\x01\x00\x11"3DU\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x056\x04\n\x00\x00C\x80\x0810.1.1.2\x06\x08\n\x00\x005\n\x00\x006\x01\x04\xff\xff\xff\x00\x03\x04\n\x01\x01\x01\xff')
    pkt.show()
    sendp(pkt, interface)


def main():
    args = parse_arguments()
    client_ip = args.client

    # identify own IP/MAC (based on interface)
    interface, mac_address, server_ip = find_interface(client_ip)
    print('Found interface:')
    print(' * name: {}'.format(interface))
    print(' * mac address: {}'.format(mac_address))
    print(' * ip address: {}'.format(server_ip))

    # ARP for dest IP mac
    destination_mac_address = get_destination_mac_address(client_ip)
    if destination_mac_address:
        print('Found destination mac address:', destination_mac_address)
    else:
        error('Could not resolve mac address of destination/gateway:', client_ip)

    # send dhcp-ack
    send_dhcp_ack(interface, destination_mac_address, mac_address, server_ip, client_ip)


if __name__ == '__main__':
    main()
