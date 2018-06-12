#!/usr/local/bin/python3
import socket, argparse
from struct import *

#Handle arguments
parser = argparse.ArgumentParser()
parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=100)
parser.add_argument("-t", "--timeout", help="Define bTCP timeout in milliseconds", type=int, default=100)
parser.add_argument("-o","--output", help="Where to store file", default="tmp2.file")
args = parser.parse_args()

server_ip = "127.0.0.1"
server_port = 9001

#flags
SYN_FLAG = 2
ACK_FLAG = 16
SYN_ACK_FLAG = 18
FIN_FLAG = 1
FIN_ACK_FLAG = 17

#Define a header format
header_format = "I"
header_format2 = "IHHBBHIs"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
sock.bind((server_ip, server_port))

actions = ['connect1', 'connect2', 'disconnect_server', 'disconnect_client', 'close']
states = ['waiting', 'handshake', 'connected', 'closing_server', 'closing_client']
        

class State:
    '''Initializes the current state: waiting.'''
    def __init__(self):
        self.current = 0

    '''Depending on current state and the action to perform the state is changed. If it was succesful, true is returned otherwise false.'''
    def changeState(self, action):
        if(self.current == 0 and action == 'connect1'):
            self.current = 1
            return True
        if(self.current == 1 and action == 'connect2'):
            self.current = 2
            return True
        if(self.current == 2 and action == 'disconnect_server'):
            self.current = 3
            return True
        if(self.current == 2 and action == 'disconnect_client'):
            self.current = 4
            return True
        if(self.current == 3 and action == 'close'):
            self.current = 0
            return True
        if(self.current == 4 and action == 'close'):
            self.current = 0
            return True
        return False

    def getState(self):
        return states[self.current]
        
current_ack = 0
current_syn = 0
empty = bytes("", 'utf8')
state = State()
with open(args.output, "wb") as f:
    while True:
        print('Waiting for input...', state.getState())
        data, addr = sock.recvfrom(1016)
        print(data[16:])
        pl = data[16:]
        if(len(pl)> 1):
            header = data[:16]
            (str_id, syn_number, ack_number, flags, window, data_len, checksum) = unpack("IHHBBHI", header)
            payload = pl
        else:
            (str_id, syn_number, ack_number, flags, window, data_len, checksum, payload) = unpack(header_format2,data)
        #receive SYN-packet
        if(state.getState() == states[0] and flags == SYN_FLAG):
            if(state.changeState('connect1')):
                print("Received syn",syn_number, ack_number, "send syn-ack", addr)
                syn_ack_payload = pack(header_format2, str_id, syn_number, ack_number, SYN_ACK_FLAG, window, data_len, checksum, empty)
                sock.sendto(syn_ack_payload, addr)
        #receive ACK after SYN-ACK
        if(state.getState() == states[1] and flags == ACK_FLAG):
            if(state.changeState('connect2')):
                print("Received ack, open connection")
        #stuff to deal with incoming data... TODO
        if(state.getState() == states[2] and flags == 0):
            f.write(payload)
        #receive FIN-packet
        if(state.getState() == states[2] and flags == FIN_FLAG):
            if(state.changeState('disconnect_client')):
                print("Received FIN, send FIN-ACK")
                fin_ack_payload = pack(header_format2, str_id, syn_number, ack_number, FIN_ACK_FLAG , window, data_len, checksum, empty)
                sock.sendto(fin_ack_payload, addr)
        #receive ACK after FIN-ACK, close connection
        if(state.getState() == states[4] and flags == ACK_FLAG):
            if(state.changeState('close')):
                print('Connection closed.')          


