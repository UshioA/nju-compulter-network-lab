'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import time
import switchyard
import threading
from switchyard.lib.userlib import *


def update_time():
    while True:
        time.sleep(0.1)
        for key, value in list(forward_table.items()):
            cur_time = time.time()
            if cur_time - value[1] >= max_time:
                log_info(f"dropped {key}:{value}")
                forward_table.pop(key)


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    global forward_table
    global max_time
    max_time= 10.0
    forward_table = {}
    thread = threading.Thread(target=update_time, daemon=True)
    thread.start()
    while True:
        try:
            timestamp, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        
        log_info (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            forward_table[str(packet[Ethernet].src)] = (fromIface, time.time())
            if forward_table.get(str(packet[Ethernet].dst)) is not None:
                log_info(f'packet {packet} to {forward_table.get(str(packet[Ethernet].dst))[0]}')
                net.send_packet(forward_table.get(str(packet[Ethernet].dst))[0], packet)
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
