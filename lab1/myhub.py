#!/usr/bin/env python3

'''
Ethernet hub in Switchyard.
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    in_, out = 0,0

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        in_+=1
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            
            for intf in my_interfaces:
                if fromIface!= intf.name:
                    out+=1
                    log_info (f"Flooding packet {packet} to {intf.name}")
                    net.send_packet(intf, packet)
        log_info(f"in:{in_} out:{out}")
    net.shutdown()
