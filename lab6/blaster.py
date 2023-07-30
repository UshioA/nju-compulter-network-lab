#!/usr/bin/env python3

import enum
from math import ceil
import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class WindowPtr:
    def __init__(self, lval, rval, timeout, sw):
        self.lval=lval
        self.rval=rval
        self._timeout=timeout
        self.sw=sw
        self.ack_list = []
        self.cur_time = 114514  # * set this later

    def c1(self):
        return (self.rval - self.lval + 1) <= self.sw
    
    def recv(self, index):
        if index < self.lval:
            return
        self.ack_list[index-self.lval] = 1
    
    def move_left(self):
        length = 0
        for i in range(self.rval - 1 - self.lval):
            if self.ack_list[i]:
                self.lval += 1
                length += 1
                self.reset_time()
            else:
                break
        self.ack_list = self.ack_list[length:]
        if length == 0:
            return None
        log_debug(f'\33[32mleft\33[0m: {self.lval-length}->{self.lval}')
        return self.lval

    def move_right(self):
        if self.c1():
            self.rval += 1
            self.ack_list += [0]
            return self.rval
        return None

    def timeout(self):
        if time.time() - self.cur_time >= self._timeout:
            return True
        return False

    def reset_time(self):
        self.cur_time = time.time()


class BlasterState(enum.Enum):
    NORMAL = 1
    RESEND = 2


class Blaster:
    blaster = '10:00:00:00:00:01'
    blastee = '20:00:00:00:00:01'
    middlebox_mac = '40:00:00:00:00:01'
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100",
            file_to_send="send.txt"
    ):
        self.net = net
        self.blastereIp = blasteeIp
        self.num = int(num)
        self.length = int(length)
        self.senderWindow = int(senderWindow)
        self.timeout = float(timeout)
        self.recvTimeout = float(recvTimeout)
        self.window = WindowPtr(1, 1, self.timeout/1000, self.senderWindow)
        self.state = BlasterState.NORMAL
        self.start_time = 114514
        self.stop_time = 114514
        self.resend_list = []
        self.rt = 0
        self.to = 0
        self.bp = 0
        self.gbp = 0
        self.file_to_send = file_to_send
        self.file = None
        self.init_file()
        # TODO: store the parameters

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        # log_debug("I got a packet")
        bs = packet[3].to_bytes()
        seq = int.from_bytes(bs[:4], byteorder='big')
        log_debug(f'\33[33mack\33[0m : {seq}')
        self.window.recv(seq)
        self.window.move_left()
        self.handle_no_packet()

    def init_file(self):
        self.file = open(self.file_to_send, "rb")
        self.buf = self.file.read()
        self.num = ceil(len(self.buf) / self.length)

    def get_input(self, where):
        where -= 1
        return self.buf[where * self.length : (where + 1) * self.length]

    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        # Creating the headers for the packet
        if self.state == BlasterState.NORMAL:
            if self.window.cur_time == 114514:
                self.window.reset_time()
            if self.start_time == 114514:
                self.start_time = time.time()
            if self.window.c1() and self.window.rval <= self.num:
                pkt = self.make_packet(self.blaster, self.middlebox_mac, '192.168.100.1', '192.168.200.1', self.length, self.window.rval)
                self.net.send_packet('blaster-eth0', pkt)
                log_debug(f'\33[35msend\33[0m: {self.window.rval}')
                self.gbp += self.length
                self.window.move_right()
            else:
                log_debug("blocked 😢")
        else:
            if not self.resend_list:
                self.state = BlasterState.NORMAL
                self.window.reset_time()
                return
            seq = self.resend_list.pop(0)
            pkt = self.make_packet(self.blaster, self.middlebox_mac, '192.168.100.1', '192.168.200.1', self.length, seq)
            self.net.send_packet('blaster-eth0', pkt)
            log_debug(f'\33[31mresend\33[0m {seq}')
            self.rt += 1
        # Do other things here and send packet

    def make_packet(self, src_mac, dst_mac, src_ip, dst_ip, pay_len, seq):
        eth = Ethernet()
        eth.dst = dst_mac
        eth.src = src_mac

        ip = IPv4(protocol=IPProtocol.UDP)
        ip.src = src_ip
        ip.dst = dst_ip
        ip.ttl = 64

        udp = UDP(src=11451, dst=14514)

        if self.bp == 0:
            udp.src = self.num
            udp.dst = self.length

        sequence = RawPacketContents(seq.to_bytes(4, byteorder='big'))
        load = self.get_input(seq)
        payload = RawPacketContents(load)
        length = RawPacketContents(len(load).to_bytes(2, byteorder='big'))
        self.bp += len(load)

        return eth + ip + udp + sequence + length + payload

    def print_stat(self):
        self.stop_time = time.time()
        total_time = self.stop_time - self.start_time
        rt = self.rt
        to = self.to
        bps = self.bp / total_time
        gbps = self.gbp / total_time
        print(f'\33[32mTotal TX time(in seconds)\33[0m: {total_time}')
        print(f'\33[32mNumber of reTX\33[0m: {rt}')
        print(f'\33[32mNumber of rough TOs\33[0m: {to}')
        print(f'\33[32mBps\33[0m: {bps}')
        print(f'\33[32mGoodput(Bps)\33[0m: {gbps}')


    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            if self.window.lval == self.num and self.window.rval >= self.num:
                self.print_stat()
                break
            if self.state == BlasterState.NORMAL and self.window.ack_list and self.window.timeout():
                self.state = BlasterState.RESEND
                self.to += 1
                for i in range(self.window.lval, self.window.rval):
                    if not self.window.ack_list[i - self.window.lval]:
                        self.resend_list.append(i)
            try:
                recv = self.net.recv_packet(self.recvTimeout/1000)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break
            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
