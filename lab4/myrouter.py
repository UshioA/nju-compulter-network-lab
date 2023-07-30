#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

from threading import Thread
import time
import switchyard
from switchyard.lib.userlib import *
from ipaddress import *


class ForwardEntry:
    def __init__(self, net_address, mask, next_hop, interface):
        self.net_address = net_address
        self.mask = mask
        self.next_hop = next_hop
        self.interface = interface
        self.prefixip = IPv4Address(int(IPv4Address(net_address)) & int(IPv4Address(mask)))
        self.prefixnet = IPv4Network(format(self.prefixip) + '/' + str(IPv4Address(mask)))
        self.prefixlen = self.prefixnet.prefixlen

    def __str__(self):
        return f'netaddr : {self.net_address} | mask : {self.mask} | next_hop : {self.next_hop} | intf : {self.interface}'
    __repr__ = __str__

    def match(self, addr):
        # print(f'\33[32maddr : {addr} | mask : {self.mask} | next_hop : {self.next_hop}\33[0m')
        return IPv4Address(addr) in self.prefixnet

class PendItem:
    def __init__(self, pkt, args, 冤种):
        self.pkt = pkt
        self.args = args
        self.time = 0
        self.emp = 冤种
        self.retry = 5

    def forward(self, net):
        if self.emp.arp_cache.get(self.args[4]):
            self.pkt[0].dst = str(self.emp.arp_cache.get(IPv4Address(self.args[4]))[0])
            net.send_packet(self.args[1], self.pkt)
            return 0
        else:
            if not self.retry:
                return -1
            if time.time() - self.time >= 1.0:
                self.time = time.time()
                log_debug(f'{self.args[2]} : {self.args[3]} : {self.args[4]}')
                net.send_packet(self.args[1], create_ip_arp_request(self.args[2], self.args[3], self.args[4]))
                self.retry -= 1
            return 1

class ArpCache:
    def __init__(self, timeout):
        self.timeout_limit = timeout
        self.arp_cache={}
        self.unused_count = 0

    def get(self, key):
        if key in self.arp_cache:
            return self.arp_cache[key] if self.arp_cache[key][2] else None
        return None

    def update_cache(self, thing):
        self.arp_cache[thing[0]] = [thing[1], time.time(), True]
        cur_time = time.time()
        for _ in self.arp_cache:
            if self.arp_cache[_][2] and cur_time - self.arp_cache[_][1] >= self.timeout_limit :
                self.unused_count += 1
                self.arp_cache[_][2] = False
                log_info(f"set entry {_}:{self.arp_cache[_]} unused")
        if self.unused_count / len(self.arp_cache) > 0.50:
            self.wash_cache() 

    def wash_cache(self):
        self.unused_count=0
        cpy_cache = deepcopy(self.arp_cache)
        for _ in cpy_cache:
            if not cpy_cache[_][2]:
                log_info(f"deleted entry {_}:{self.arp_cache[_]}")
                self.arp_cache.pop(_)

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_cache = ArpCache(10)  #key : ip, val : [mac, timeout, in_use=True]
        self.forwarding_table = []
        self.build_forwarding()
        self.pend = []
        # other initialization stuff here

    def find_bestmatch(self, addr):
        match = None
        for entry in self.forwarding_table:
            if entry.match(addr):
                if not match or match.prefixlen < entry.prefixlen:
                    match = entry   
        return match

    def build_forwarding(self):
        for i in self.net.interfaces():
            self.forwarding_table.append(ForwardEntry(str(i.ipaddr),str(i.netmask),None,i.name)) 
        with open("forwarding_table.txt", 'r') as f:
            lines = f.read().splitlines()
            for _ in lines:
                info = _.split()
                self.forwarding_table.append(ForwardEntry(info[0], info[1], info[2], info[3]))

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        if arp is not None:
            t2a = arp.targetprotoaddr
            self.arp_cache.update_cache((arp.senderprotoaddr, arp.senderhwaddr))
            if arp.operation != 2:
                for i in self.net.ports():
                    if t2a == i.ipaddr:
                        pkt = create_ip_arp_reply(i.ethaddr, arp.senderhwaddr, i.ipaddr, arp.senderprotoaddr)
                        self.net.send_packet(i.name, pkt)
                        log_info(f"send packet {pkt} to {i.name}")
        else:
            ip = packet.get_header(IPv4)
            if ip is not None:
                packet[1].ttl -= 1
                dst = format(packet[1].dst)
                log_debug(f"want to match : {dst}")
                match = self.find_bestmatch(dst)
                if not match:
                    log_info("dst ip not match, 😭")
                    return
                match.net_address = dst
                if match.net_address in [format(i.ipaddr) for i in self.net.ports()]:
                    log_info("for me?! 🥵")
                else:
                    next_hop = match.next_hop
                    if not next_hop:
                        next_hop = packet[1].dst
                    else:
                        next_hop = IPv4Address(next_hop)
                    intf = match.interface
                    srchw = self.net.interface_by_name(intf).ethaddr
                    srcip = self.net.interface_by_name(intf).ipaddr
                    log_debug(f'srchw : {srchw} \nsrcip : {srcip}')
                    targetip = deepcopy(next_hop)
                    packet[0].src = srchw
                    if self.arp_cache.get(targetip):
                        packet[0].dst = self.arp_cache.get(targetip)[0]
                        self.net.send_packet(intf, packet)
                    else:
                        log_debug(f'target : {targetip}')
                        args=(self.net, intf, srchw, srcip, targetip)
                        self.pend.append(PendItem(packet, args, self)) # 多线程摊平了罢了🤗



    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            to_delete=[]        
            for item in self.pend:
                ret = item.forward(self.net)
                if ret == 0:
                    to_delete.append(item)
                elif ret == 1:
                    continue
                else:
                    to_delete.append(item)
            for i in to_delete:
                self.pend.remove(i)
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
