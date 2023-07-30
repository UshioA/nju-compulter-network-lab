#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

from cmath import log
import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_cache = {} #key : ip, val : [mac, timeout, in_use=True]
        self.timeout_limit = 10
        self.unused_count=0
        # other initialization stuff here

    def update_cache(self, thing):
        self.arp_cache[thing[0]] = [thing[1], time.time(), True]
        cur_time = time.time()
        for _ in self.arp_cache:
            if self.arp_cache[_][2] and cur_time - self.arp_cache[_][1] >= self.timeout_limit :
                self.unused_count += 1
                self.arp_cache[_][2] = False
                log_info(f"set entry {_}:{self.arp_cache[_]} unused")
        self.wash_cache() if self.unused_count / len(self.arp_cache) > 0.50 else None;
        self.print_cache()

    def wash_cache(self):
        self.unused_count=0
        cpy_cache = deepcopy(self.arp_cache)
        for _ in cpy_cache:
            if not cpy_cache[_][2]:
                log_info(f"deleted entry {_}:{self.arp_cache[_]}")
                self.arp_cache.pop(_)

    def print_cache(self):
        print("### ARP CACHE ###")
        for _ in self.arp_cache:
            print(f'{_} : {self.arp_cache[_]}')

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        if(arp is None):
            return
        t2a = arp.targetprotoaddr
        self.update_cache((arp.senderprotoaddr,arp.senderhwaddr))
        for i in self.net.ports():
            if t2a == i.ipaddr:
                #* create and send?
                pkt = create_ip_arp_reply(i.ethaddr, arp.senderhwaddr, i.ipaddr, arp.senderprotoaddr)
                self.net.send_packet(i.name, pkt)
                log_info(f"send packet {pkt} to {i.name}")


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
