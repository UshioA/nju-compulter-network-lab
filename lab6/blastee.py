#!/usr/bin/env python3

from asyncio import protocols
import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    blaster = '10:00:00:00:00:01'
    blastee = '20:00:00:00:00:01'
    middlebox_mac = '40:00:00:00:00:02'
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num,
            length="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp = blasterIp
        self.num = -1
        self.length = -1

    def init_buf(self):
        self.buf = [b'0' * self.length] * self.num
        self.got = [0] * (self.num + 1)

    def make_ack(self, src_mac, dst_mac, src_ip, dst_ip, pkt):
        eth = Ethernet()
        eth.dst = dst_mac
        eth.src = src_mac

        ip = IPv4(protocol=IPProtocol.UDP)
        ip.src = src_ip
        ip.dst = dst_ip
        ip.ttl = 64
        if self.num == -1:
            self.num = int(pkt[2].src)
            self.length = int(pkt[2].dst)
            log_info(f'packet num {self.num}, each {self.length} Bytes')
            self.init_buf()
        udp = UDP(src=11451, dst=14514)

        bs = pkt[3].to_bytes()
        
        seq = RawPacketContents(bs[:4])
        sequence = int.from_bytes(bs[:4], byteorder='big')

        payload_len = int.from_bytes(bs[4:6], byteorder='big')
        if not self.got[sequence]:
            self.got[sequence] = 1
            self.num -= 1
            self.write_buf(bs[6:], sequence - 1)
        if payload_len > 8:
            payload_len = 8
        payload = bs[6:6+payload_len]
        if payload_len < 8:
            payload += b' '*(8-payload_len)
        payload = RawPacketContents(payload)
        return eth + ip + udp + seq + payload

    def write_buf(self, payload, seq):
        self.buf[seq] = payload

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")

        ack = self.make_ack(self.blastee, self.middlebox_mac, '192.168.200.1', self.blasterIp, packet)
        self.net.send_packet('blastee-eth0', ack)

    def store_buf(self):
        with open("recv.txt", 'wb') as f:
            for pkt in self.buf:
                f.write(pkt)

    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                if not self.num:
                    self.store_buf()
                    break
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
