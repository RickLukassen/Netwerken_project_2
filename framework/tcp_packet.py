#!/usr/local/bin/python3
import zlib
import socket, argparse, random
import sys
from random import randint
from struct import *

class Tcp_packet:
    '''For flags: 
    SYN is 2
    ACK is 16
    SYN-ACK is 18
    FIN is 1
    FIN-ACK is 17
    '''
    hFormat = "IHHBBHI"
    def __init__ (self, str_id, syn, ack, flags, window, data_len, payload):
        self.stream_id = str_id
        self.syn = syn
        self.ack = ack
        self.flags = flags
        self.window = window
        self.data_length = data_len
        self.payload = payload
        self.checksum = getChecksum
    
    def getChecksum(self):
        t = pack(hFormat, stream_id, syn, ack, flags, window, data_length, payload)
        return checksum = zlib.crc32(t)

    def to_bytes(self):
        return pack(self.hFormat, self.stream_id, self.syn, self.ack, self.flags, self.window, self.data_length, self.checksum, self.payload)
    
    def from_bytes(self, bytes_packet):
        self.payload = bytes_packet[16:]
        header = bytes_packet[:16]
        (self.stream_id, self.syn, self.ack, self.flags, self.window, self.data_length, self.checksum) = unpack(hFormat, header)
