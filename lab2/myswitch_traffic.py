'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    forward_table = {}
    NR_entry = 5
    lowest = ('key', 99999999999999999999999999)

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug(f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            src, dst = str(packet[Ethernet].src), str(packet[Ethernet].dst)
            if forward_table.get(src) is not None:
                forward_table[src] = (fromIface, forward_table[src][1])
            else:
                if len(forward_table) >= NR_entry:
                    print(f'cur lowest : {lowest}')
                    for i in forward_table:
                        print(f"checking {i} : {forward_table[i]}")
                        if(i == lowest[0]):
                            lowest = (i, forward_table[i][1])
                        elif forward_table[i][1] < lowest[1]:
                            lowest = (i, forward_table[i][1])
                    forward_table.pop(lowest[0])
                    print(lowest)
                    lowest = ('key', 9999999999999999999999999999999)
                    forward_table[src] = (fromIface, 0)
                    for i in forward_table:
                        print(f"checking {i} : {forward_table[i]}")
                        if(i == lowest[0]):
                            lowest = (i, forward_table[i][1])
                        if forward_table[i][1] < lowest[1]:
                            lowest = (i, forward_table[i][1])
                else:
                    forward_table[src] = (fromIface, 0)
                    for i in forward_table:
                        if(i == lowest[0]):
                            lowest = (i, forward_table[i][1])
                        if forward_table[i][1] < lowest[1]:
                            lowest = (i, forward_table[i][1])
            if forward_table.get(dst) is not None:
                log_info(
                    f'packet {packet} to {forward_table.get(str(packet[Ethernet].dst))[0]}')
                net.send_packet(forward_table[dst][0], packet)
                forward_table[dst] = (
                    forward_table[dst][0], forward_table[dst][1]+1)
                for i in forward_table:
                    if(i == lowest[0]):
                        lowest = (i, forward_table[i][1])
                    if forward_table[i][1] < lowest[1]:
                        lowest = (i, forward_table[i][1])
            else:
                for intf in my_interfaces:
                    if fromIface != intf.name:
                        log_info(f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
