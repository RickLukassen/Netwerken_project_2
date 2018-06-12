#!/usr/local/bin/python3
import socket, argparse, random
import sys
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
header_format2 = "IIIIIIIs"
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

flags = 0
window = 1
data_len = 0
checksum = 1234

#udp_payload = pack(header_format2, str_id, syn_number, ack_number, flags, window, data_len, checksum, bTCP_payload)

#UDP socket which will transport your bTCP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#bunchofbytes = bytes(967)

#print(sys.getsizeof(bunchofbytes.nbytes))
#send payload
#sock.sendto(udp_payload, (destination_ip, destination_port))
payload = bytes("", 'utf8')
connected = False
'''Handshake: '''
#send syn
print("Send syn", syn_number, ack_number)
syn_payload = pack(header_format2, str_id, syn_number, ack_number, SYN_FLAG, window, data_len, checksum, payload)
sock.sendto(syn_payload, (destination_ip, destination_port))


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
            bytes = f.read(1000)
    print("File was sent! (Actually TODO)")
    packet = pack(header_format2, str_id, syn_number, ack_number, FIN_FLAG, window, data_len, checksum, payload)
    print("Send fin")
    sock.sendto(packet, addr)
    data, addr = sock.recvfrom(1016)
    (str_id, syn_number, ack_number, flags, window, data_len, checksum, pl) = unpack(header_format2,data)
    if(flags == FIN_ACK_FLAG):
        print("Fin-ack received, send ack, close connection")
        packet = pack(header_format2, str_id, syn_number, ack_number, ACK_FLAG, window, data_len, checksum, payload)
        sock.sendto(packet,addr)
        connected = False
    
    #disconnect after all data is sent: TODO
