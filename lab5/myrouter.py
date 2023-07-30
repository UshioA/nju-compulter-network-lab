#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from ipaddress import *


class ForwardEntry:
    def __init__(self, net_address, mask, next_hop, interface):
        self.net_address = net_address
        self.ipaddr = IPv4Address(net_address)
        self.ip_next_hop = IPv4Address(next_hop) if next_hop else None
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
        return IPv4Address(addr) in self.prefixnet

class NetWorkException(Exception):
    def __init__(self, errortype, errorcode, origin_pkt, ip_pkt, intf):
        self.errortype = errortype
        self.errorcode = errorcode
        self.origin_pkt = origin_pkt
        self.ip_pkt = ip_pkt
        self.intf = intf

    def pkt_back(self):
        if self.errorcode == 1 and self.errortype is ICMPType.DestinationUnreachable:
            pkts= []
            for i in range(len(self.origin_pkt)):
                p = deepcopy(self.origin_pkt[i])
                index = p.get_header_index(Ethernet)
                del p[index]
                icmp = ICMP()
                icmp.icmptype = self.errortype
                icmp.icmpcode = self.errorcode
                icmp.icmpdata.data = p.to_bytes()[:28]
                icmp.icmpdata.origdgramlen = len(p)
                ip = IPv4()
                ip.protocol = IPProtocol.ICMP
                ip.src = self.intf[i].ipaddr
                ip.dst = self.origin_pkt[i][IPv4].src
                ip.ttl = 64
                pkt = ip + icmp
                pkts.append(pkt)
            return pkts
        else:
            p = deepcopy(self.origin_pkt)
            i = p.get_header_index(Ethernet)
            del p[i]
            icmp = ICMP()
            icmp.icmptype = self.errortype
            icmp.icmpcode = self.errorcode
            icmp.icmpdata.data = p.to_bytes()[:28]
            icmp.icmpdata.origdgramlen = len(p)
            ip = IPv4()
            ip.protocol = IPProtocol.ICMP
            ip.src = self.intf.ipaddr
            ip.dst = self.origin_pkt[IPv4].src
            ip.ttl = 64
            pkt = ip + icmp
            return pkt


class PendItem:
    def __init__(self, pkt, args, 冤种):
        self.pkt = pkt
        self.args = args
        self.time = 0
        self.emp = 冤种
        self.retry = 5

    def forward(self, net):
        assert type(self.args[4])==IPv4Address, "arp_cache has key typed IPv4Address"
        if self.emp.arp_cache.get(self.args[4]):
            self.pkt[0].dst = self.emp.arp_cache.get(self.args[4])[0]
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
        ip = packet.get_header(IPv4)
        icmp = packet.get_header(ICMP)
        if arp is not None:
            t2a = arp.targetprotoaddr
            self.arp_cache.update_cache((arp.senderprotoaddr, arp.senderhwaddr))
            if arp.operation != 2:
                for i in self.net.ports():
                    if t2a == i.ipaddr:
                        pkt = create_ip_arp_reply(i.ethaddr, arp.senderhwaddr, i.ipaddr, arp.senderprotoaddr)
                        self.net.send_packet(i.name, pkt)
                        log_info(f"send packet {pkt} to {i.name}")
        elif ip is not None:                
            if ip.dst in [i.ipaddr for i in self.net.interfaces()]:
                if icmp:
                    log_info("ICMP for me, 😀")
                    icmptype = icmp.icmptype
                    if icmptype == ICMPType.EchoRequest:
                        icmp_head = ICMP()
                        icmp_head.icmptype = ICMPType.EchoReply
                        data = ICMPEchoReply()
                        data.data = icmp.icmpdata.data
                        data.identifier = icmp.icmpdata.identifier
                        data.sequence = icmp.icmpdata.sequence
                        icmp_head.icmpdata = data
                        ip_header = IPv4()
                        ip_header.src, ip_header.dst = ip.dst,ip.src
                        ip_header.ttl=64
                        ip_header.protocol = IPProtocol.ICMP
                        ip_header.ipid=0
                        ether = Ethernet()
                        res = self.find_bestmatch(ip_header.dst)
                        if res:
                            res.net_address = ip_header.dst
                            next = res.ip_next_hop if res.ip_next_hop else ip_header.dst
                            intf = self.net.interface_by_name(res.interface)
                            ether.src = intf.ethaddr
                        else:
                            # * icmp unreachable 
                            raise NetWorkException(ICMPType.DestinationUnreachable, 0, ether + ip_header + icmp_head, ip, self.net.interface_by_name(ifaceName))
                        pkt_to_send = ether + ip_header + icmp_head
                        self.send_IP(pkt_to_send, intf, next)
                    else:
                        raise NetWorkException(ICMPType.DestinationUnreachable, 3, pkt_to_send, ip, self.net.interface_by_name(ifaceName))
                else:
                    raise NetWorkException(ICMPType.DestinationUnreachable, 3, packet, ip, self.net.interface_by_name(ifaceName))
            else:                
                if packet[1].ttl <= 0:
                    raise NetWorkException(ICMPType.TimeExceeded, 0, packet, ip, self.net.interface_by_name(ifaceName))
                ip.ttl -= 1
                if packet[1].ttl <= 0:
                    raise NetWorkException(ICMPType.TimeExceeded, 0, packet, ip, self.net.interface_by_name(ifaceName))
                dst = format(packet[1].dst)
                log_debug(f"want to match : {dst}")
                match = self.find_bestmatch(dst)
                if not match:
                    log_info("dst ip not match, 😭")
                    raise NetWorkException(ICMPType.DestinationUnreachable, 0, packet, ip, self.net.interface_by_name(ifaceName))
                match.net_address = dst
                if match.net_address in [format(i.ipaddr) for i in self.net.ports()]:
                    log_info("for me?! 🥵")
                else:
                    next_hop = match.next_hop
                    if not next_hop:
                        next_hop = packet[1].dst
                    else:
                        next_hop = IPv4Address(next_hop)
                    intf = self.net.interface_by_name(match.interface)
                    srchw = intf.ethaddr
                    srcip = intf.ipaddr
                    log_debug(f'srchw : {srchw} \nsrcip : {srcip}')
                    targetip = deepcopy(next_hop)
                    packet[0].src = srchw
                    self.send_IP(packet, intf, targetip)
            
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:            
                to_delete=[]   
                fail = []    
                for item in self.pend:
                    ret = item.forward(self.net)
                    if ret == 0:
                        to_delete.append(item)
                    elif ret == 1:
                        continue
                    else:
                        fail.append(item)
                if fail:
                    raise NetWorkException(ICMPType.DestinationUnreachable, 1, [i.pkt for i in fail], [i.pkt[1] for i in fail], \
                        [self.net.interface_by_macaddr(i.pkt[Ethernet].dst) for i in fail])
            except NetWorkException as e:
                self.handle_exception(e)
            finally:
                for i in to_delete+fail:
                    self.pend.remove(i)
            try:
                recv = self.net.recv_packet(timeout=1.0)
                self.handle_packet(recv)
            except NetWorkException as e:
                self.handle_exception(e)            
            except NoPackets:
                continue
            except Shutdown:
                break
        self.stop()

    def handle_exception(self, e):
        if e.errorcode == 1 and e.errortype == ICMPType.DestinationUnreachable:
            epkts = e.pkt_back()
            intfs = e.intf
            for i in range(len(epkts)):
                err_pkt = epkts[i]
                eth = Ethernet()
                eth.src = intfs[i].ethaddr
                eth.dst = e.origin_pkt[i][Ethernet].src
                eth.ethertype = EtherType.IP
                err_pkt = eth + err_pkt[0] + err_pkt[1]
                self.send_IP(err_pkt, e.intf[i], err_pkt[IPv4].dst)
        else:    
            err_pkt = e.pkt_back()
            eth = Ethernet()
            eth.src = e.intf.ethaddr
            eth.dst = e.origin_pkt[Ethernet].src
            eth.ethertype = EtherType.IP
            err_pkt = eth + err_pkt[0] + err_pkt[1]
            if e.errorcode == 3 and e.errortype == ICMPType.DestinationUnreachable:
                self.net.send_packet(e.intf, err_pkt)
            else:
                self.send_IP(err_pkt, e.intf, err_pkt[IPv4].dst)

    def send_IP(self, pkt, intf, targetip):
        if self.arp_cache.get(targetip):
            pkt[0].dst = self.arp_cache.get(targetip)[0]
            self.net.send_packet(intf, pkt)
        else:
            args = (self.net, intf, intf.ethaddr, intf.ipaddr, targetip)
            self.pend.append(PendItem(pkt, args, self))

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
