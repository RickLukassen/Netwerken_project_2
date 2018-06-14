#!/usr/local/bin/python3
import socket, argparse, random
import sys
import zlib
import queue
#from Tcp_packet import Tcp_packet
from random import randint
from struct import *
import _thread, time

#Handle arguments
parser = argparse.ArgumentParser()
parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=3)
parser.add_argument("-t", "--timeout", help="Define bTCP timeout in milliseconds", type=int, default=100)
parser.add_argument("-i","--input", help="File to send", default="tmp.file")
args = parser.parse_args()

destination_ip = "127.0.0.1"
destination_port = 9001

buffer = {}
baseSentIndex = 0

#bTCP header
header_format = "I"
header_format2 = "IHHBBHIs" 
fin_sent = False
send_fin = False
rec_done = False
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
    (str_id, packet_syn_number, packet_ack_number, SYN_FLAG, window, data_len, checksum) = unpack("IHHBBHI", header)
    checksum = getChecksum(header, payload)
    packet = pack("IHHBBHI" + str(data_len) + "s", str_id, packet_syn_number, packet_ack_number, SYN_FLAG, window, data_len, checksum, payload )
    #print(packet)
    sock.sendto(packet, addr)

def handleData(data):
    payload = data[16:]
    header = data[:16]
    (str_id, packet_syn_number, packet_ack_number, flags, window, data_len, checksum) = unpack("IHHBBHI", header)
    return (payload, (str_id, packet_syn_number, packet_ack_number, flags, window, data_len, checksum))


'''Handshake: '''
connected = False
#send syn
print("Send SYN(", syn_number, ",", ack_number, ")")
payload = bytes("\x00", 'utf8')
header = pack("IHHBBHI", str_id, syn_number, ack_number, SYN_FLAG, 0, len(payload), checksum)
sendPacket(header, payload, (destination_ip, destination_port))
syn_number += 1

#receive syn-ack, deal with dropped packets etc: TODO
data, addr = sock.recvfrom(1016)
(str_id, server_syn_number, server_ack_number, flags, window, data_len, checksum, pl) = unpack(header_format2,data)
WINDOW_SIZE = window
(payload_a, header_a) = handleData(data)

#Send ACK, open connection
if(flags == SYN_ACK_FLAG):
    if(server_ack_number == syn_number):
        print("Received SYN-ACK (", server_syn_number, ",", server_ack_number, ")")
        server_syn_number += 1
        ack_number = server_syn_number
        print("Send ACK(", syn_number, ",", ack_number, ")")
        connected = True
        (str_id, server_syn_number, server_ack_number, flags, window, data_len, checksum) = header_a
        pl = bytes("\x00", 'utf8')
        hdr = pack("IHHBBHI", str_id, syn_number, ack_number, ACK_FLAG, window, len(pl), checksum)
        sendPacket(hdr, pl, (destination_ip, destination_port))
        syn_number += 1
    else:
        print("SYN or SYN-ACK was lost. Resend.")

'''Send data. '''
def sendStream(connected, server_syn_number, syn_number, ack_number, str_id, window, checksum):
    global send_fin, sent_all
    if(connected):
        #Read the file contents as bytes.
        with open(args.input, "rb") as f:
            bytes_ = f.read(1000)
            while(bytes_):
                pl = bytes_
                print("Send data (", syn_number, ",", ack_number, ")")
                server_syn_number += 1
                hdr = pack("IHHBBHI", str_id, syn_number, ack_number, NO_FLAG, window, len(pl), checksum)
                sendPacket(hdr,pl,(destination_ip, destination_port))
                buffer[syn_number + 1] = (hdr,pl)
                syn_number = (syn_number + len(pl)) % 65536
                ack_number += 1
                bytes_ = f.read(1000)
    sent_all = True
    time.sleep(2*args.timeout/1000)
    while(buffer):
        while(q.qsize() > 0):
            received_ack = q.get()
            if(received_ack in buffer):
                del buffer[received_ack]
        for b in buffer:
            (hdr, pl) = buffer[b]
            sendPacket(hdr,pl,(destination_ip, destination_port))
        time.sleep(args.timeout/1000)
    send_fin = True
    print("File was sent, send FIN(", syn_number ,",", ack_number , ")")
    return True

def getStream():
    global rec_done
    time.sleep(0.1)
    while(not(send_fin)): #this shouldn't go on forever.
        data, addr = sock.recvfrom(1016)
        (payload_ack, header_ack) = handleData(data)
        (_, ss, sa, flags, _, _, checksum) = header_ack
        if(flags == ACK_FLAG):            
            print("GOT ACK! ", sa)
            q.put(sa)
        if(flags == FIN_ACK_FLAG):
            pass
            #TODO fix dit, dit pakket wordt bij regel 187 eigenlijk gehandeld.
    rec_done = True
    return True

q = queue.Queue()
sent_all = False
try:
    a = _thread.start_new_thread(sendStream, (connected,server_syn_number,syn_number,ack_number,str_id,window,checksum) )
    b = _thread.start_new_thread(getStream, ())
    a.join()
    b.join()
except:
    print("Error: unable to start thread")


'''Close connection.'''
while(not(send_fin) and not(rec_done)):
    time.sleep(0.1)

print("BBBBBBBBB")
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
