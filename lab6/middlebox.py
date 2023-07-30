#!/usr/bin/env python3

import time
import threading
from random import randint, random

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

class Middlebox:
    blaster = '10:00:00:00:00:01'
    blastee = '20:00:00:00:00:01'
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)
        self.intfs = self.net.interfaces()
        self.macs = [i.ethaddr for i in self.intfs]
        self.ips = [i.ipaddr for i in self.intfs]

    def should_send(self):
        return self.dropRate <= random()

    def modify_packet(self, pkt, origin, to):
        pkt[0].src = origin
        pkt[0].dst = to
        pkt[1].ttl -= 1

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        # if fromIface == self.intf1: 写的什么东西😡
        if fromIface == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if self.should_send():
                self.modify_packet(packet, self.macs[0], self.blaster)
                self.net.send_packet("middlebox-eth1", packet)
        elif fromIface == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            self.modify_packet(packet, self.macs[1], self.blastee)
            self.net.send_packet("middlebox-eth0", packet)
        else:
            log_debug("Oops :))")

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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
