#!/usr/local/bin/python3
import socket, argparse, random
import sys
import zlib
import queue
#from Tcp_packet import Tcp_packet
from random import randint
from struct import *
import _thread, time

''' 
Rick Lukassen, s4263812
Bas Steeg, s4259181
'''

#Handle arguments
parser = argparse.ArgumentParser()
parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=3)
parser.add_argument("-t", "--timeout", help="Define bTCP timeout in milliseconds", type=int, default=100)
parser.add_argument("-i","--input", help="File to send", default="tmp.file")
args = parser.parse_args()

destination_ip = "127.0.0.1"
destination_port = 9001

buffer = {}

header_format2 = "IHHBBHIs" 
fin_sent = False
send_fin = False
rec_done = False


str_id = randint(0,100)
syn_number = 50
ack_number = 0
'''
Flags: CEUAPRSF
So, 
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

#UDP socket which will transport your bTCP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

'''Useful functions, sorry for the mess. '''

def getChecksum(header, payload):
    (str_id, syn_number, ack_number, flags, window, data_len, checksum) = unpack("IHHBBHI", header)    
    form = "IHHBBH" +str(len(payload)) + "s"
    return zlib.crc32(pack(form, str_id, syn_number, ack_number, flags, window, data_len, payload), 0)  & 0xffffffff


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

'''Remove ack'd messages from buffer, then retransmit what's left. '''
def retransmit():
    if(q.qsize() > 0):
        received_ack = q.get()
        if(received_ack in buffer):
            del buffer[received_ack]
    for b in buffer:
        ((hdr, pl),_) = buffer[b]
        sendPacket(hdr,pl,(destination_ip, destination_port))

'''Send data. We're sorry for the mess. But working code is more important than pretty code, we have added quite some comments to explain the code.
'''
def sendStream(connected, server_syn_number, syn_number, ack_number, str_id, window, checksum):
    global send_fin, sent_all
    #counter for messages, used to maintain proper window size.
    i = 1
    if(connected):
        #Read the file contents as bytes.
        with open(args.input, "rb") as f:
            bytes_ = f.read(1000)
            while(bytes_):
                pl = bytes_
                print("Send data (", syn_number, ",", ack_number, ")")
                server_syn_number += 1
                #construct and send message.
                hdr = pack("IHHBBHI", str_id, syn_number, ack_number, NO_FLAG, window, len(pl), checksum)
                sendPacket(hdr,pl,(destination_ip, destination_port))
                #save the packet so it can be resend if it was not ack'd.
                buffer[syn_number + len(pl)] = ((hdr,pl) , i)
                i += 1
                #get lowest and highest value of the counter in the buffer, used to stay within the window.
                lowest = buffer[sorted(buffer)[0]][1]
                highest = buffer[sorted(buffer)[len(buffer)-1]][1]
                #if the next message would not fit in the window, it's time to re-transmit older packets.
                while(not((highest - WINDOW) + 2 <= lowest)):
                    #timeout timer.
                    time.sleep(args.timeout/1000) 
                    #re-transmit older packets
                    retransmit()
                    lowest = buffer[sorted(buffer)[0]][1]
                    highest = buffer[sorted(buffer)[len(buffer)-1]][1]
                    #clean the buffer after the retransmissions.
                    while(buffer and q.qsize() > 0):
                        received_ack = q.get()
                        if(received_ack in buffer):
                            del buffer[received_ack]
                #calculate next sequence number, modulo 65536.
                syn_number = (syn_number + len(pl)) % 65536
                ack_number += 1
                #read next part of the input.
                bytes_ = f.read(1000)
    sent_all = True
    time.sleep(args.timeout/1000)
    #clean buffer and retransmit packets which were not ack'd until all packets are ack'd.
    while(buffer):
        while(q.qsize() > 0):
            received_ack = q.get()
            if(received_ack in buffer):
                del buffer[received_ack]
        for b in buffer:
            ((hdr, pl),_) = buffer[b]
            sendPacket(hdr,pl,(destination_ip, destination_port))
    #Entire file was succesfully transferred, now close the connection.
    send_fin = True
    print("File was sent, send FIN(", syn_number ,",", ack_number , ")")
    pl = bytes("\x00", 'utf8')
    hdr = pack("IHHBBHI", str_id, syn_number, ack_number, FIN_FLAG, window, len(pl), checksum)
    sendPacket(hdr,pl,(destination_ip, destination_port))

def getStream():
    global rec_done
    while(not(send_fin) or connected):
        data, addr = sock.recvfrom(1016)
        (payload_ack, header_ack) = handleData(data)
        (_, ss, sa, flags, _, _, checksum) = header_ack
        if(flags == ACK_FLAG):            
            print("GOT ACK! ", sa)
            q.put(sa)
    #Entire file was succesfully transferred, now close the connection.
        if(flags == FIN_ACK_FLAG):
            endConnection(data,addr)
    rec_done = True

def endConnection(data, addr):
    (pl_a, hdr_a) = handleData(data)
    (str_id, syn_number, ack_number, flags, window, data_len, checksum) = hdr_a
    #Send ACK, close connection
    print("Fin-ack received, send ack, close connection")
    pl = bytes("\x00", 'utf8')
    hdr = pack("IHHBBHI", str_id, syn_number, ack_number, ACK_FLAG, window, len(pl), 0)
    sendPacket(hdr,pl,(destination_ip, destination_port))
    connected = False



#Handshake: 
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
        WINDOW = window
        hdr = pack("IHHBBHI", str_id, syn_number, ack_number, ACK_FLAG, window, len(pl), checksum)
        sendPacket(hdr, pl, (destination_ip, destination_port))
        syn_number += 1
    else:
        print("SYN or SYN-ACK was lost. Resend.")

#Setup to send/receive data.
q = queue.Queue()
sent_all = False
#Start threads to do the sending and receiving.
try:
    a = _thread.start_new_thread(sendStream, (connected,server_syn_number,syn_number,ack_number,str_id,window,checksum) )
    b = _thread.start_new_thread(getStream, ())
except:
    print("Error: unable to start thread")

#Wait until we are done.
while(not(send_fin) and not(rec_done) and connected):
    time.sleep(0.05)

'''
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
'''
#disconnect after all data is sent
