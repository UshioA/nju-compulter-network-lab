'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from cgi import print_environ_usage
import switchyard
from switchyard.lib.userlib import *

class node:
    def __init__(self, data):
        self.data = data
        self.last, self.next = None, None

class linked_list:
    capacity = 5
    def __init__(self):
        self.head = node(0)
        self.tail = node(0)
        self.len = 0
        self.head.next = self.tail
        self.tail.last = self.head
    def insert_head(self, other):
        other.next = self.head.next
        self.head.next.last = other
        self.head.next = other
        other.last = self.head
        self.len += 1

    def getHead(self):
        if self.len==0:
            return None
        return self.head.next

    def print_self(self):
        p = self.head
        print("")
        while p is not None:
            print(p.data, end='->')
            p = p.next
        print("")
    
    def is_full(self):
        return linked_list.capacity <= self.len

    def empty(self):
        return self.len == 0

    def pop_end(self):
        if self.len == 0:
            raise Exception("pop from empty, nmsl")
        self.len -= 1
        self.tail.last.last.next = self.tail
        self.tail.last = self.tail.last.last


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    global forward_table
    forward_table = {}
    lru = linked_list()
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            src, dst = str(packet[Ethernet].src), str(packet[Ethernet].dst)
            if src in forward_table.keys():
                forward_table[src] = fromIface
            else:
                if lru.is_full():
                    tail = lru.tail.last
                    forward_table.pop(tail.data[0])
                    lru.pop_end()
                    item = (src, fromIface)
                    forward_table[src] = fromIface
                    lru.insert_head(node(item))
                else:
                    item = (src, fromIface)
                    forward_table[src] = fromIface
                    lru.insert_head(node(item))
            if dst in list(forward_table.keys()):
                log_info(f'packet {packet} to {forward_table.get(str(packet[Ethernet].dst))}')
                net.send_packet(forward_table[dst], packet)
                p = lru.getHead()
                while p != lru.tail:
                    if p.data[0] == dst:
                        break
                    p = p.next
                p.last.next = p.next
                p.next.last = p.last
                p.last = p.next = None
                lru.len -= 1
                lru.insert_head(p)
            else :
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
