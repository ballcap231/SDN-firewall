#!/usr/bin/python
# CS 6250 Summer 2018 - Project 4 - SDN Firewall

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import packets
from pyretic.core import packet


def make_firewall_policy(config):
    rules = []
    for entry in config:
        # Assume only IPv4 is used
        rule = match(ethtype=packet.IPV4)
        # If a parsed configuration field value is '-', ignore it.
        if entry['macaddr_src'] != '-':
            rule &= match(srcmac=EthAddr(entry['macaddr_src']))
        if entry['macaddr_dst'] != '-':
            rule &= match(dstmac=EthAddr(entry['macaddr_dst']))
        if entry['ipaddr_src'] != '-':
            rule &= match(srcip=IPAddr(entry['ipaddr_src']))
        if entry['ipaddr_dst'] != '-':
            rule &= match(dstip=IPAddr(entry['ipaddr_dst']))
        if entry['port_src'] != '-':
            rule &= match(srcport=int(entry['port_src']))
        if entry['port_dst'] != '-':
            rule &= match(dstport=int(entry['port_dst']))
        if entry['protocol'] != '-':
            if entry['protocol'] == 'T':
                rule &= match(protocol=packet.TCP_PROTO)
            elif entry['protocol'] == 'U':
                rule &= match(protocol=packet.UDP_PROTO)
            elif entry['protocol'] == 'I':
                rule &= match(protocol=packet.ICMP_PROTO)
            elif entry['protocol'] == 'B':
                # 'B' means TCP and UDP, so we need two rules
                rule2 = rule & match(protocol=packet.UDP_PROTO)
                rules.append(rule2)
                rule &= match(protocol=packet.TCP_PROTO)

        rules.append(rule)
        pass

    allowed = ~(union(rules))

    return allowed
