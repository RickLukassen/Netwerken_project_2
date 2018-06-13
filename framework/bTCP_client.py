#!/usr/local/bin/python3
import socket, argparse, random
import sys
import zlib
from Tcp_packet import Tcp_packet
from random import randint
from struct import *

#Handle arguments
parser = argparse.ArgumentParser()
parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=100)
parser.add_argument("-t", "--timeout", help="Define bTCP timeout in milliseconds", type=int, default=100)
parser.add_argument("-i","--input", help="File to send", default="tmp.file")
args = parser.parse_args()

destination_ip = "127.0.0.1"
destination_port = 9001

WINDOW_SIZE = 5
buffer_window = []

#bTCP header
header_format = "I"
header_format2 = "IHHBBHIs" 
#bTCP_header = pack(header_format, randint(0,100))
#bTCP_payload = ""
#udp_payload = bTCP_header

str_id = randint(0,100)
syn_number = 50
ack_number = 0
#Flags: CEUAPRSF
'''So, 
SYN is 2
ACK is 16
SYN-ACK is 18
FIN is 1
FIN-ACK is 17
'''
SYN_FLAG = 2
ACK_FLAG = 16
SYN_ACK_FLAG = 18
FIN_FLAG = 1
FIN_ACK_FLAG = 17
NO_FLAG = 0

flags = 0
window = 1
data_len = 1000
checksum = 1234

def getChecksum(header, payload):
    (str_id, syn_number, ack_number, flags, window, data_len, checksum) = unpack("IHHBBHI", header)    
    form = "IHHBBH" +str(len(payload)) + "s"
    return zlib.crc32(pack(form, str_id, syn_number, ack_number, flags, window, data_len, payload), 0)  & 0xffffffff

#udp_payload = pack(header_format2, str_id, syn_number, ack_number, flags, window, data_len, checksum, bTCP_payload)

#UDP socket which will transport your bTCP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def sendPacket(header, payload, addr):
    (str_id, syn_number, ack_number, SYN_FLAG, window, data_len, checksum) = unpack("IHHBBHI", header)
    checksum = getChecksum(header, payload)
    packet = pack("IHHBBHI" + str(data_len) + "s", str_id, syn_number, ack_number, SYN_FLAG, window, data_len, checksum, payload )
    print(packet)
    sock.sendto(packet, addr)

def handleData(data):
    payload = data[16:]
    header = data[:16]
    (str_id, syn_number, ack_number, flags, window, data_len, checksum) = unpack("IHHBBHI", header)
    return (payload, (str_id, syn_number, ack_number, flags, window, data_len, checksum))


'''Handshake: '''
connected = False
#send syn
print("Send SYN(", syn_number, ",", ack_number, ")")
payload = bytes("\x00", 'utf8')
header = pack("IHHBBHI", str_id, syn_number, ack_number, SYN_FLAG, 0, len(payload), checksum)
sendPacket(header, payload, (destination_ip, destination_port))


#receive syn-ack, deal with dropped packets etc: TODO
data, addr = sock.recvfrom(1016)
(str_id, server_syn_number, server_ack_number, flags, window, data_len, checksum, pl) = unpack(header_format2,data)
(payload_a, header_a) = handleData(data)

#Send ACK, open connection
if(flags == SYN_ACK_FLAG):
    if(server_ack_number == syn_number+1):
        syn_number+=1
        print("Received SYN-ACK (", server_syn_number, ",", server_ack_number, ")")
        print("Send ACK(", syn_number, ",", server_syn_number + 1, ")")
        connected = True
        (str_id, syn_number, ack_number, flags, window, data_len, checksum) = header_a
        pl = bytes("\x00", 'utf8')
        hdr = pack("IHHBBHI", str_id, syn_number, server_syn_number + 1, ACK_FLAG, window, len(pl), checksum)
        sendPacket(hdr, pl, (destination_ip, destination_port))
    else:
        print("SYN or SYN-ACK was lost. Resend.")

'''Send data. '''
if(connected):
    #Read the file contents as bytes.
    with open(args.input, "rb") as f:
        bytes_ = f.read(1000)
        while(bytes_):
            pl = bytes_
            hdr = pack("IHHBBHI", str_id, syn_number, ack_number, NO_FLAG, window, len(pl), checksum)
            sendPacket(hdr,pl,(destination_ip, destination_port))
            bytes_ = f.read(1000)
            data, addr = sock.recvfrom(1016)
    print("File was sent, send fin")
    '''Close connection.'''
    #Send fin
    pl = bytes("\x00", 'utf8')
    hdr = pack("IHHBBHI", str_id, syn_number, ack_number, FIN_FLAG, window, len(pl), checksum)
    sendPacket(hdr,pl,(destination_ip, destination_port))
    #Receive FIN-ACK
    data, addr = sock.recvfrom(1016)
    (pl_a, hdr_a) = handleData(data)
    (str_id, syn_number, ack_number, flags, window, data_len, checksum) = hdr_a
    #Send ACK, close connection
    if(flags == FIN_ACK_FLAG):
        print("Fin-ack received, send ack, close connection")
        pl = bytes("\x00", 'utf8')        
        hdr = pack("IHHBBHI", str_id, syn_number, ack_number, ACK_FLAG, window, len(pl), 0)
        sendPacket(hdr,pl,(destination_ip, destination_port))
        connected = False
    
    #disconnect after all data is sent
