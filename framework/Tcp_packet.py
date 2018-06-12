import zlib
from struct import *

class Tcp_packet:
    '''For flags: 
    SYN is 2
    ACK is 16
    SYN-ACK is 18
    FIN is 1
    FIN-ACK is 17
    '''
    def __init__ (self, str_id, syn, ack, flags, window, data_len, payload):
        self.stream_id = str_id
        self.syn = syn
        self.ack = ack
        self.flags = flags
        self.window = window
        self.data_length = data_len
        self.payload = payload
        self.hFormat = "IHHBBHIs"
        self.checksum = self.getChecksum()
    
    def getChecksum(self):
        pl = self.payload
        form = "IIIIII" +str(len(pl)) + "s"
        return zlib.crc32(pack(form, self.stream_id, self.syn, self.ack, self.flags, self.window, self.data_length, pl))
      

    def to_bytes(self):
        form = "IHHBBHI" + str(len(self.payload)) + "s"
        return pack(form, self.stream_id, self.syn, self.ack, self.flags, self.window, len(self.payload), self.checksum, self.payload)
    
    def from_bytes(self, bytes_packet):
        self.payload = bytes_packet[16:]
        header = bytes_packet[:16]
        (self.stream_id, self.syn, self.ack, self.flags, self.window, self.data_length, self.checksum) = unpack("IHHBBHI", header)
        self.data_length = len(self.payload)
