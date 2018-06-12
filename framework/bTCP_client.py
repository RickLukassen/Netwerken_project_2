#!/usr/local/bin/python3
import socket, argparse, random
import sys
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

#bTCP header
header_format = "I"
header_format2 = "IHHBBHIs" 
bTCP_header = pack(header_format, randint(0,100))
bTCP_payload = ""
udp_payload = bTCP_header
str_id = randint(0,100)
syn_number = 2222
ack_number = 3333
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

#udp_payload = pack(header_format2, str_id, syn_number, ack_number, flags, window, data_len, checksum, bTCP_payload)

#UDP socket which will transport your bTCP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#send payload
#sock.sendto(udp_payload, (destination_ip, destination_port))
payload = bytes("", 'utf8')
connected = False
'''Handshake: '''
#send syn
print("Send syn", syn_number, ack_number)
syn_payload = pack(header_format2, str_id, syn_number, ack_number, SYN_FLAG, window, data_len, checksum, payload)
#tcp_packet = Tcp_packet.Tcp_packet(str_id, syn_number, ack_number, SYN_FLAG, window, data_len, payload)
sock.sendto(syn_payload, (destination_ip, destination_port))
#sock.sendto(tcp_packet.to_bytes(), (destination_ip, destination_port))
#print(tcp_packet.to_bytes())
#print(syn_payload)

#receive syn-ack, deal with dropped packets etc: TODO
data, addr = sock.recvfrom(1016)
(str_id, syn_number, ack_number, flags, window, data_len, checksum, pl) = unpack(header_format2,data)
print("Received syn-ack, ", syn_number, ack_number, "send ack")


if(flags == SYN_ACK_FLAG):
    connected = True
    packet = pack(header_format2, str_id, syn_number, ack_number, ACK_FLAG, window, data_len, checksum, payload)
    sock.sendto(packet, addr)

#send data: TODO
if(connected):
# Read the file contents as bytes.
    with open(args.input, "rb") as f:
        bytes = f.read(1000)
        while(bytes):
            header_format2 = "IHHBBHI" + str(len(bytes)) + "s"
            #test_packet = Tcp_packet(str_id, syn_number, ack_number, NO_FLAG, window, data_len, bytes)
            packet = pack(header_format2, str_id, syn_number, ack_number, NO_FLAG, window, data_len, checksum, bytes)
            sock.sendto(packet,addr)
            print(packet)
            bytes = f.read(1000)
    print("File was sent!")
    packet = pack(header_format2, str_id, syn_number, ack_number, FIN_FLAG, window, data_len, checksum, payload)
    print("Send fin")
    sock.sendto(packet, addr)
    print(data)
    data, addr = sock.recvfrom(1016)
    header_format3 = "IHHBBHIs"
    (str_id, syn_number, ack_number, flags, window, data_len, checksum, pl) = unpack(header_format3,data)
    if(flags == FIN_ACK_FLAG):
        print("Fin-ack received, send ack, close connection")
        packet = pack(header_format2, str_id, syn_number, ack_number, ACK_FLAG, window, data_len, checksum, payload)
        sock.sendto(packet,addr)
        connected = False
    
    #disconnect after all data is sent: TODO
