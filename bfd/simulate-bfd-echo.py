#!/usr/bin/env python3

import argparse
from ipaddress import AddressValueError, IPv4Address, IPv4Interface
from scapy.all import conf, get_if_hwaddr, getmacbyip, sendp, Ether, IP, UDP, Raw

from lib.log import error


def parse_arguments():
    """Get commandline arguments."""
    parser = argparse.ArgumentParser(
        description='Send BFD echo packets to BGP neighbor')
    parser.add_argument('-n', '--neighbor', required=True,
                        help='IP address of BGP neighbor')
    return parser.parse_args()


def find_interface(neighbor):
    interface, outgoing_ip, gateway = conf.route.route(neighbor)
    if gateway != '0.0.0.0':
        error('Could not find direct attached network interface for BGP neighbor:', neighbor)

    mac_address = get_if_hwaddr(interface)
    return interface, mac_address, outgoing_ip


def get_neighbor_mac_address(neighbor):
    return getmacbyip(neighbor)


def send_bfd_echo(interface, neighbor_mac_address, mac_address, ip_address):
    src_port = 12345
    dst_port = 3785
    pkt = Ether(dst=neighbor_mac_address, src=mac_address, type='IPv4')/ \
          IP(dst=ip_address, src=ip_address, proto='udp')/ \
          UDP(sport=src_port, dport=dst_port)/ \
          Raw(load=b'\x00\x00\x00\x00\x00\x00\x10\xde\x00\x00\x00 ')
    pkt.show()
    sendp(pkt, interface)


def main():
    args = parse_arguments()
    neighbor = args.neighbor

    # identify own IP/MAC (based on interface)
    interface, mac_address, ip_address = find_interface(neighbor)
    print('Found interface:')
    print(' * name: {}'.format(interface))
    print(' * mac address: {}'.format(mac_address))
    print(' * ip address: {}'.format(ip_address))

    # ARP for dest IP mac
    neighbor_mac_address = get_neighbor_mac_address(neighbor)
    if neighbor_mac_address:
        print('Found neighbor:', neighbor_mac_address)
    else:
        error('Could not resolve mac address of neighbor:', neighbor)

    # send bfd-echo
    send_bfd_echo(interface, neighbor_mac_address, mac_address, ip_address)


if __name__ == '__main__':
    main()
