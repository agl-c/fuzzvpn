#! /usr/bin/env python3
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from scapy.all import *
import random 
import secrets
import argparse
import sys
import itertools


# edit this to map local port numbers to a list of host:port destinations
# source site: https://distrustsimplicity.net/articles/a-simple-udp-forwarder-in-twisted/

# args will determine fuzzing type, currently we add 
# 
args = None 
# should first fill in the client_ip, server_ip, ( if it's manual testing, we select the vulnerability type: replay_select)

# sys.stdout = uncaching_output_stream(sys.stdout)

# "openvpn" or "wireguard"
test_type = "openvpn"
# 50000 for openvpn and 60000 for wireguard
binding_port = 50000
# "192.168.1.33" 
# now we use the same IP as it's in docker
client_ip = "172.17.0.4"
# "192.168.1.155" 
server_ip = "172.17.0.4"
# we use 40000 in docker vpn client
client_port = 40000
# 1194 for openvpn, 60683 for wireguard for now
server_port = 1194


# below part is for manual testing
# "control_v1" "client_restart_v2"; "ndss_restart" means the forced negotiation crash attack in the ndss 2022 paper
replay_select = "none"
allowed_control_v1_num = 100 # we increase it from 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
sent_control_v1_num = 0

# below for fuzzing
# when a P_CONTROL_V1 pkt comes, we remember its order for the client / server respectively
ctr_from_c = ""
ctr_from_s = ""
nowpkt = ""

fuzzed_dic = ["original", "fuzzed"]
s1_bunch_pkts = ["s_hello_1", "s_hello_2"]
c1_bunch_pkts = ["ccs", "c_c1", "c_c2"]
s2_bunch_pkts = ["s_c1", "s_c2", "s_c3"]
# pkt_array=("hard_reset_c_v2" "hard_reset_s_v2" "c_hello" "s_hello_1" "s_hello_2" "ccs" "c_c1" "c_c2" "ack_v1" "s_c1" "s_c2" "s_c3" "data_v2")

s1_saved_pkts = [None, None]
c1_saved_pkts = [None, None, None]
s2_saved_pkts = [None, None, None]

c_saved_acks = [None, None, None, None] # in total 4 acks from client
s_saved_acks = [None] # in total 1 ack from server
# 10, 3210, 4321, 5432
c_ack_mid_arr =[b'\x00\x00\x00\x01\x00\x00\x00\x00', b'\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00',
b'\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01', b'\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x02']
# 21, 
s_ack_mid_arr = [b'\x00\x00\x00\x02\x00\x00\x00\x01']
# nowack = ""

# 10,3210,4321,5432, 21,  0,1, 210, 321 
mid_arr = [b'\x00\x00\x00\x01\x00\x00\x00\x00', b'\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00',
b'\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01', b'\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x02',
b'\x00\x00\x00\x02\x00\x00\x00\x01', b'\x00\x00\x00\x00', b'\x00\x00\x00\x01',  b'\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00',
b'\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01'
]


# a normal connection mostly use below opcodes
P_CONTROL_HARD_RESET_CLIENT_V2 = 7
P_CONTROL_HARD_RESET_SERVER_V2 = 8 
P_CONTROL_V1 = 4
P_ACK_V1 = 5
P_DATA_V2 = 9

# below are some less used OPcodes: from openvpn-2.6.8/src/openvpn/ssl_pkt.h
P_CONTROL_SOFT_RESET_V1 = 3           # graceful transition from old to new key
P_CONTROL_HARD_RESET_CLIENT_V3 = 10   # indicates key_method >= 2 and client-specific tls-crypt key

# and some deprecated opcodes, we also want to see how the newer versions of openvpn respond to them
P_CONTROL_HARD_RESET_CLIENT_V1 = 1  
P_CONTROL_HARD_RESET_SERVER_V1 = 2 
P_DATA_V1 = 6 
P_CONTROL_WKC_V1 = 11     # Variant of P_CONTROL_V1 but with appended wrapped key, like P_CONTROL_HARD_RESET_CLIENT_V3


opcode_array = [P_CONTROL_HARD_RESET_CLIENT_V2, P_CONTROL_HARD_RESET_SERVER_V2, P_CONTROL_V1, 
                P_ACK_V1, P_DATA_V2, P_CONTROL_SOFT_RESET_V1, P_CONTROL_HARD_RESET_CLIENT_V3, 
                P_CONTROL_HARD_RESET_CLIENT_V1, P_CONTROL_HARD_RESET_SERVER_V1, P_DATA_V1, 
                P_CONTROL_WKC_V1]
OPCODE_MASK = 0b11111000
KEYID_MASK = 0b00000111 

mpid_array = [0, 1, 2, 3, 4, 5]
tls_ctype_array = [22, 20, 23, 21, 24] # handshake, ccs, and application data; alert(21) and heartbeat(24)
tls_v_array = [0x301, 0x302, 0x303, 0x304] # tls 1.0~tls1.3
tls_htype_array = [0, 1, 2, 4, 5, 6, 8, 11, 12 ,13, 14, 15, 16, 20] # tls handshake record types 
hs_v_array = [0x301, 0x302, 0x303, 0x304]
ccs_array = [0, 1]

# we use some simple words to remember the message state right now
CH_sent = "CH_sent"
SH_sent = "SH_sent"
Sctd_sent = "Sctd_sent"
CCS_sent = "CCS_sent"
Cctd_sent1 = "Cctd_sent1"
Cctd_sent2 = "Cctd_sent2"
S2app_sent = "S2app_sent"
S1app_sent = "S1app_sent"
# C1app_sent = "C1app_sent"
Slastapp_sent = "Slastapp_sent"


# there are various OpenVPN headers to adapt to 
# after receiving the pkt, we have to tell which by using the Opcode
# so we'd better write a single class definition for getting opcode dissection?
# or shall we define 5-bit field and 3-bit field? 
class to_get_op_code(Packet):
    name = "to_get_op_code"
    fields_desc = [XByteField("Type", None)] # it's one byte, while 5 bits for opcode,  3 bits for keyid 


# the "raw" means this version is for no tls-auth or tls-crypt, i.e., no replay protection/MAC/wholy encrypted control messages

# for now, we use fixed-length field for some length, maybe we can use the lenstr type, too
# client hard reset
class OpenVPN_raw_c_hr(Packet):
    name = "OpenVPN_raw_c_hr"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    XIntField("Message_Packet_ID", None)
                    ]  # the Data field will be in Raw field, which is default
    
# server hard reset 
class OpenVPN_raw_s_hr(Packet):
    name = "OpenVPN_raw_s_hr"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None),
                    XIntField("Message_Packet_ID", None)
                    ]  # the Data field will be in Raw field, which is default
    

# we notice that we can also fuzz the cleartext TLS record layer part
# the class below serves for help determining using which detailed class to dissect
class OpenVPN_raw_ctr(Packet):
    name = "OpenVPN_raw_ctr"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None),
                    XIntField("Message_Packet_ID", None),

                    # below are TLS record part
                    XByteField("TLS_Content_type", None) # Handshake (22), Change Cipher Spec (20), Application Data (23)
                  ]

# client hello
class OpenVPN_raw_ctr_ch(Packet):
    name = "OpenVPN_raw_ctr_ch"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None),
                    XIntField("Message_Packet_ID", None),

                    # TLS record layer
                    XByteField("TLS_Content_type", None), # Handshake (22)
                    XShortField("TLS_Version", None), # e.g. TLS 1.0 0x0301
                    XShortField("Record_Length", None),  
                    XByteField("Handshake_Type", None),  # Client Hello (1)
                    StrFixedLenField("HS_Length", "", length=3),
                    XShortField("HS_Version", None),  # handshake protocol version TLS 1.2 (0x0303)
                    StrFixedLenField("Random", "", length=32), 
                    # fmt=B indicates it is 1-byte type
                    FieldLenField("Session_ID_Length", None, length_of="Session ID", fmt="B"),
                    StrLenField("TLS_Session_ID", "", length_from=lambda pkt: pkt.Session_ID_Length),
                    XShortField("Cipher_Suites_Length", None),  # 
                    StrLenField("Cipher_Suites", "", length_from=lambda pkt: pkt.Cipher_Suites_Length),
                    # fmt=B indicates it is 1-byte type
                    FieldLenField("Compression_Methods_Length", None, length_of="Compression Methods", fmt="B"),
                    StrLenField("Compression_Methods", "", length_from=lambda pkt: pkt.Compression_Methods_Length),
                    XShortField("Extensions_Length", None),  # not sure about the format allowed in ""
                    # below are some extensions
                    StrFixedLenField("Extension_ec_point_formats", "", length=8),
                    StrFixedLenField("Extension_supported_groups", "", length=16),
                    StrFixedLenField("Extension_encrypt_then_mac", "", length=4),
                    StrFixedLenField("Extension_extended_master_secret", "", length=4),
                    StrFixedLenField("Extension_signature_algorithms", "", length=52),
                    StrFixedLenField("Extension_supported_versions", "", length=13),
                    StrFixedLenField("Extension_psk_key_exchange_modes", "", length=6),
                    StrFixedLenField("Extension_key_share", "", length=42)
                    # not sure about the rest JA4, JA4_r, JA3 Fullstring, JA3 stuff
                    ]

# server hello, change cipher spec, 2 app data, and segment data
class OpenVPN_raw_ctr_sh(Packet):
    name = "OpenVPN_raw_ctr_sh"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None),
                    XIntField("Message_Packet_ID", None),

                    # TLS record layer
                    XByteField("TLS_Content_type", None), # Handshake (22)
                    XShortField("TLS_Version", None), # e.g. TLS 1.0 0x0301
                    XShortField("Record_Length", None),  
                    XByteField("Handshake_Type", None), # Server Hello (2)
                    StrFixedLenField("HS_Length", "", length=3),
                    XShortField("HS_Version", None),  # handshake protocol version TLS 1.2 (0x0303)
                    StrFixedLenField("Random", "", length=32), 
                    # fmt=B indicates it is 1-byte type
                    FieldLenField("Session_ID_Length", None, length_of="Session ID", fmt="B"),
                    StrLenField("TLS_Session_ID", "", length_from=lambda pkt: pkt.Session_ID_Length),
                    # the cipher suite selected by the server
                    XShortField("Cipher_Suite", None), 
                    # compression method selected by the server
                    XByteField("Compression_Method", None),
                    XShortField("Extensions_Length", None),  # the format allowed in "", space not allowed, since we have to cite it next, use _ 
                    # below are some extensions
                    StrFixedLenField("Extension_supported_versions", "", length=6),
                    StrFixedLenField("Extension_key_share", "", length=40),
                    # not sure about the rest JA3S Fullstring, JA3S stuff

                    # TLS record layer
                    # next are the Change Cipher Spec parts
                    XByteField("TLS_Content_type_ccs", None), # Change Cipher Spec (20)
                    XShortField("TLS_Version_ccs", None), # e.g. TLS 1.0 0x0301
                    XShortField("Record_Length_ccs", None),  
                    XByteField("Change_Cipher_Spec_Message", None),

                    # TLS record layer
                    # next is the first application data
                    XByteField("TLS_Opaque_type_ead1", None),  # Application Data (23)
                    XShortField("TLS_Version_ead1", None), # e.g. TLS 1.2 0x0303
                    XShortField("Record_Length_ead1", None),  
                    StrLenField("Encrypted_Application_Data1", "", length_from=lambda pkt: pkt.Record_Length_ead1),

                    # TLS record layer
                    # next is the second application data
                    XByteField("TLS_Opaque_type_ead2", None),  # Application Data (23)
                    XShortField("TLS_Version_ead2", None), # e.g. TLS 1.2 0x0303
                    XShortField("Record_Length_ead2", None),  
                    StrLenField("Encrypted_Application_Data2", "", length_from=lambda pkt: pkt.Record_Length_ead2)
                    # the below raw field part is the TLS segment data

                    ]


# P_CONTROL_V1 continuation data 
class OpenVPN_raw_ctr_ctd(Packet):
    name = "OpenVPN_raw_ctr_ctd"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None),
                    XIntField("Message_Packet_ID", None)
                    # TLS data
                    # I think the below raw field part is the TLS segment data
                    ]


# P_ACK_V1
class OpenVPN_raw_ack1(Packet):
    name = "OpenVPN_raw_ack1"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None)
                    ]


# change cipher spec from client and segment data
class OpenVPN_raw_ctr_ccs(Packet):
    name = "OpenVPN_raw_ctr_ccs"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                   XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None),
                    XIntField("Message_Packet_ID", None),
          
                    # TLS record layer
                    # the Change Cipher Spec 
                    XByteField("TLS_Content_type", None), # Change Cipher Spec (20)
                    XShortField("TLS_Version", None), # e.g. TLS 1.0 0x0301
                    XShortField("Record_Length", None),  
                    XByteField("Change_Cipher_Spec_Message", None)

                    # the below raw field part is the TLS segment data
                    ]


# P_CONTROL_V1 TLS 2 application data in one pkt
class OpenVPN_raw_ctr_2app(Packet):
    name = "OpenVPN_raw_ctr_2app"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long; 3---->12 bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4*pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None),
                    XIntField("Message_Packet_ID", None),

                    # TLS Record Layer, application data 
                    # next is the first application data
                    XByteField("TLS_Content_type", None),  # Application Data (23)
                    XShortField("TLS_Version", None), # e.g. TLS 1.2 0x0303
                    XShortField("Record_Length", None),  
                    StrLenField("Encrypted_Application_Data1", "", length_from=lambda pkt: pkt.Record_Length),

                    # TLS record layer
                    # next is the second application data
                    XByteField("TLS_Content_type2", None),  # Application Data (23)
                    XShortField("TLS_Version_ead2", None), # e.g. TLS 1.2 0x0303
                    XShortField("Record_Length_ead2", None),  
                    StrLenField("Encrypted_Application_Data2", "", length_from=lambda pkt: pkt.Record_Length_ead2)
                   
                    ]


# P_CONTROL_V1 TLS 1 application data in one pkt
class OpenVPN_raw_ctr_1app(Packet):
    name = "OpenVPN_raw_ctr_1app"
    fields_desc = [ XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long; 3---->12 bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4* pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None),
                    XIntField("Message_Packet_ID", None),

                    # TLS Record Layer, application data 
                    # next is the first application data
                    XByteField("TLS_Content_type", None),  # Application Data (23)
                    XShortField("TLS_Version", None), # e.g. TLS 1.2 0x0303
                    XShortField("Record_Length", None),  
                    StrLenField("Encrypted_Application_Data1", "", length_from=lambda pkt: pkt.Record_Length)
                    ]

# P_DATA_V2
class OpenVPN_raw_data(Packet):
    name = "OpenVPN_raw_data"
    fields_desc = [ XByteField("Type", None),
                    StrFixedLenField("Peer_ID", "", length=3)
                    # the below raw filed part is simply data, i.e., encrypted app data in the vpn data channel 
                    ]

# we define the mutation behaviors below, including field-wise, packet-wise, sequence-wise


class Forward(DatagramProtocol):
    def datagramReceived(self, data, addr):
        # print(f"the proxy received {data!r} from {addr}")
        # print(f"the proxy received {len(data)} bytes data from {addr}")
        # print("the type of data is ", type(data)) # class bytes 
        global client_ip
        global server_ip
        global client_port
        global server_port 
        global ctr_from_c
        global ctr_from_s
        global nowpkt
      
        global s1_saved_pkts 
        global c1_saved_pkts 
        global s2_saved_pkts 
        global c_saved_acks
        global s_saved_acks

        global replay_select
        global allowed_control_v1_num
        global sent_control_v1_num


        if test_type == "openvpn":
            to_get_op_code_pkt = to_get_op_code(data)
            packet_type = to_get_op_code_pkt.Type
            type_opcode = ( packet_type & OPCODE_MASK) >> 3
            type_keyid = ( packet_type & KEYID_MASK)
            len_data = len(data)
            print(f"*************** we got a {len_data}-bytes packet from {addr}, with opcode: {type_opcode} ***************")
            # print("before modifictaion, the type is:", type(openvpn_packet.Type))

            # according to the type_opcode, we suit the data to corresponding class
            # Firstly, those pkts where opcodes determines how to dissect
            if type_opcode == P_CONTROL_HARD_RESET_CLIENT_V2:
                openvpn_packet = OpenVPN_raw_c_hr(data)
                nowpkt = "hard_reset_c_v2"

            elif type_opcode == P_CONTROL_HARD_RESET_SERVER_V2:
                openvpn_packet = OpenVPN_raw_s_hr(data)
                nowpkt = "hard_reset_s_v2"

            # we don't consider the ACK type pkts a lot, but it should be useful since it indicates which pkts have been received
            elif type_opcode == P_ACK_V1:
                openvpn_packet = OpenVPN_raw_ack1(data)
                # nowpkt = "ack_v1"
                # the only ack from server, mark and save
                if addr[1]==1194: 
                    nowpkt = "s_ack"
                    s_saved_acks[0] = openvpn_packet
                    print("~~~~~~~~~~~~~~~~ we got s_ack ~~~~~~~~~~~~~~~~~~")
                    openvpn_packet.show()

                # the acks from client 
                elif openvpn_packet.Packet_ID_Array == c_ack_mid_arr[0]:
                    nowpkt = "c_ack1"
                    c_saved_acks[0] = openvpn_packet
                    print("~~~~~~~~~~~~~~~~ we got c_ack1 ~~~~~~~~~~~~~~~~~~")
                elif openvpn_packet.Packet_ID_Array == c_ack_mid_arr[1]:
                    nowpkt = "c_ack2"
                    c_saved_acks[1] = openvpn_packet
                    print("~~~~~~~~~~~~~~~~ we got c_ack2 ~~~~~~~~~~~~~~~~~~")
                elif openvpn_packet.Packet_ID_Array == c_ack_mid_arr[2]:
                    nowpkt= "c_ack3"
                    c_saved_acks[2] = openvpn_packet
                    print("~~~~~~~~~~~~~~~~ we got c_ack3 ~~~~~~~~~~~~~~~~~~")
                elif openvpn_packet.Packet_ID_Array == c_ack_mid_arr[3]:
                    nowpkt= "c_ack4"
                    c_saved_acks[3] = openvpn_packet
                    print("~~~~~~~~~~~~~~~~ we got c_ack4 ~~~~~~~~~~~~~~~~~~")
                else:
                    print("~~~~~~~~~~~~~~~~~~~~ unknown ack ~~~~~~~~~~~~~~~~~~~~")
                    nowpkt="new_ack"
                    openvpn_packet.show()


            elif type_opcode == P_DATA_V2:
                openvpn_packet = OpenVPN_raw_data(data)
                # openvpn_packet.show()
                nowpkt = "data_v2"

            # secondly, the control_v1 pkts, we determine by looking at the TLS record first field?
            # from client
            elif type_opcode == P_CONTROL_V1 and addr[1]!=1194:
                control_packet = OpenVPN_raw_ctr(data)
                if control_packet.TLS_Content_type == 22: # handshake, so client hello 
                    openvpn_packet = OpenVPN_raw_ctr_ch(data)
                    nowpkt = "c_hello"
                    ctr_from_c = CH_sent

                elif control_packet.TLS_Content_type == 20: # CCS
                    openvpn_packet = OpenVPN_raw_ctr_ccs(data)
                    nowpkt = "ccs" 
                    ctr_from_c = CCS_sent

                # we combine length feature to differ betwen c_c1 and c_c2
                else:
                    if len_data>1000: # 1222; use length for a rough mapping
                        openvpn_packet = OpenVPN_raw_ctr_ctd(data)
                        nowpkt = "c_c1"
                        ctr_from_c = Cctd_sent1
                    else: # 173
                        openvpn_packet = OpenVPN_raw_ctr_ctd(data)
                        nowpkt = "c_c2"
                        ctr_from_c = Cctd_sent2

            # from server
            elif type_opcode == P_CONTROL_V1 and addr[1]==1194:
                control_packet = OpenVPN_raw_ctr(data)
                if control_packet.TLS_Content_type == 22: # handshake, so server hello
                    openvpn_packet = OpenVPN_raw_ctr_sh(data)
                    nowpkt = "s_hello_1"
                    ctr_from_s = SH_sent

                elif control_packet.TLS_Content_type == 23: # application data
                # we combine length feature to differ betwen 2pp or 1app 
                    if len_data < 200: # 192
                        openvpn_packet = OpenVPN_raw_ctr_2app(data)
                        nowpkt = "s_c1"
                        ctr_from_s = S2app_sent
                    elif len_data < 240:  # 238
                        openvpn_packet = OpenVPN_raw_ctr_1app(data)
                        nowpkt = "s_c2"
                        ctr_from_s = S1app_sent
                    else: # 256
                        openvpn_packet = OpenVPN_raw_ctr_1app(data)
                        nowpkt = "s_c3"
                        ctr_from_s = Slastapp_sent

                else: # ctd
                    openvpn_packet = OpenVPN_raw_ctr_ctd(data)
                    nowpkt = "s_hello_2"
                    ctr_from_s = Sctd_sent

            else: 
                nowpkt =  "unknown"
                openvpn_packet = OpenVPN_raw_ctr(data)
                print("*************** unsupported OpenVPN packet type, use raw_ctr parsing *******************")
               
            # old dissection method deleted: by remembering the last sent pkt from that party, which only works well when no fuzzing exists
          
            # openvpn_packet.show() 

            # after correct dissection, we change certain parts according to the fuzzing parameters
            fuzzed = False

            if args.fuzzway=="1p1f" and args.pkt==nowpkt: # find the matched pkt
                # print("~~~~~~~~~~~~~~~ we arrived here ~~~~~~~~~~~~~")
                if args.field=="op":
                    # ensure choosing a different op_code
                    new_opcode = type_opcode
                    
                    if args.howto=="rand_vali": # random value from the valid value list
                        while new_opcode==type_opcode: 
                            new_opcode = random.choice(opcode_array)
                    elif args.howto=="rand_any": # random value which occupies 5bit, i.e., from [0, 31]
                        while new_opcode==type_opcode: 
                            new_opcode = random.randint(0, 31)
                    elif args.howto=="rand_zero":
                        new_opcode = 0
                    else:
                        print("**************** unknown howto parameter ******************")

                    new_type = (new_opcode << 3) | type_keyid
                    openvpn_packet.Type = new_type
                    print("the new opcode:", new_opcode, " keyid:", type_keyid, " type:", openvpn_packet.Type)
                    fuzzed = True

                elif args.field == "sid":
                    old_sid = openvpn_packet.Session_ID
                    new_sid = old_sid
                    if args.howto== "rand_any": # random value which occupies 8bytes, i.e., 64bits
                        while new_sid == old_sid: 
                            new_sid = random.getrandbits(64)
                    elif args.howto=="rand_zero":
                        new_sid = 0
                    else: 
                        print("~~~~~~~~~~~ unknown howto method ~~~~~~~~~~~~~")
                    openvpn_packet.Session_ID = new_sid

                elif args.field == "sid_r":
                    old_sid_r = openvpn_packet.Remote_Session_ID
                    new_sid_r = old_sid_r
                    
                    if args.howto== "rand_any": # random value which occupies 8bytes, i.e., 64bits
                        while new_sid_r == old_sid_r: 
                            new_sid_r = random.getrandbits(64)
                    elif args.howto=="rand_zero":
                        new_sid_r = 0 
                    else: 
                        print("~~~~~~~~~~~ unknown howto method ~~~~~~~~~~~~~")
                    openvpn_packet.Remote_Session_ID = new_sid_r

                elif args.field=="mid_array": # ack-target experiments
                    # print(" ~~~~~~~~~~~~~~~~~~~~~~ it's mid_array experiment ~~~~~~~~~~~~~")
                    old_mid_array = openvpn_packet.Packet_ID_Array
                    new_mid_array = old_mid_array
                    old_mid_arrlen = openvpn_packet.Message_Packet_ID_Array_Lenth

                    if args.howto == "rand_vali":
                        while new_mid_array==old_mid_array:
                            new_mid_array = random.choice(mid_arr)
                    elif args.howto == "rand_any":
                        while new_mid_array==old_mid_array:
                            new_mid_array = random.getrandbits(32).to_bytes(4*old_mid_arrlen, 'big')
                    elif args.howto == "rand_zero":
                        new_mid_array = b"\x00\x00\x00\x00"

                    elif args.howto=="rm_some": # for now, we change the 2nd element to be 0
                        mutable_mid_array = bytearray(old_mid_array)
                        mutable_mid_array[4:8] = b'\x00\x00\x00\x00'
                        new_mid_array = bytes(mutable_mid_array)
                    elif args.howto=="large":
                        mutable_mid_array = bytearray(old_mid_array)
                        mutable_mid_array[0:4] = b'\x00\x00\x00\x09' # for now, we replace the 1st element to be 9
                        new_mid_array = bytes(mutable_mid_array)

                    openvpn_packet.Packet_ID_Array = new_mid_array
                    openvpn_packet.Message_Packet_ID_Array_Lenth = int(len(new_mid_array)/4)
                    print(f"we dispaly the {args.howto} fuzzed {nowpkt} packet:")
                    openvpn_packet.show()
                    fuzzed = True

                elif args.field=="mpid":
                    # ensure a different mpid
                    old_mpid=openvpn_packet.Message_Packet_ID
                    new_mpid=old_mpid

                    if args.howto=="rand_vali":
                        while new_mpid==old_mpid:
                            new_mpid = random.choice(mpid_array)
                    elif args.howto=="rand_any":
                        while new_mpid==old_mpid:
                            new_mpid = random.randint(0, 0xFFFFFFFF) # random 4 byte int
                    elif args.howto=="rand_zero":
                        new_mpid=0
                    else:
                        print("**************** unknown howto parameter ******************")

                    openvpn_packet.Message_Packet_ID=new_mpid
                    print("the new Message_Packet_ID:", new_mpid)
                    fuzzed = True

                elif args.field=="tls_ctype":
                    old_ctype=openvpn_packet.TLS_Content_type
                    new_ctype=old_ctype

                    if args.howto=="rand_vali":
                        while new_ctype==old_ctype:
                            new_ctype=random.choice(tls_ctype_array)
                    elif args.howto=="rand_any":
                        while new_ctype==old_ctype:
                            new_ctype=random.randint(0, 255) # random 1 byte int
                    elif args.howto=="rand_zero":
                        new_ctype=0
                    else:
                        print("**************** unknown howto parameter ******************")

                    openvpn_packet.TLS_Content_type=new_ctype
                    print("the new TLS_Content_type:", new_ctype)
                    fuzzed=True

                elif args.field=="tls_v":
                    old_tlsv=openvpn_packet.TLS_Version
                    new_tlsv=old_tlsv

                    if args.howto=="rand_vali":
                        while new_tlsv==old_tlsv:
                            new_tlsv=random.choice(tls_v_array)
                    elif args.howto=="rand_any":
                        while new_tlsv==old_tlsv:
                            new_tlsv=random.randint(0, 65535) # random 2-byte int
                    elif args.howto=="rand_zero":
                        new_tlsv=0
                    else:
                        print("**************** unknown howto parameter ******************")

                    openvpn_packet.TLS_Version=new_tlsv
                    print("the new TLS_Version:", new_tlsv)
                    fuzzed=True

                elif args.field=="tls_htype":
                    old_htype=openvpn_packet.Handshake_Type
                    new_htype=old_htype

                    if args.howto=="rand_vali":
                        while new_htype==old_htype:
                            new_htype=random.choice(tls_htype_array)
                    elif args.howto=="rand_any":
                        while new_htype==old_htype:
                            new_htype=random.randint(0, 255) # random 1 byte int
                    elif args.howto=="rand_zero":
                        new_htype=0
                    else:
                        print("**************** unknown howto parameter ******************")

                    openvpn_packet.Handshake_Type=new_htype
                    print("the new Handshake_Type:", new_htype)
                    fuzzed=True

                elif args.field=="hs_v":
                    old_hsv=openvpn_packet.HS_Version
                    new_hsv=old_hsv

                    if args.howto=="rand_vali":
                        while new_hsv==old_hsv:
                            new_hsv=random.choice(hs_v_array)
                    elif args.howto=="rand_any":
                        while new_hsv==old_hsv:
                            new_hsv=random.randint(0, 65535) # random 2-byte int
                    elif args.howto=="rand_zero":
                        new_hsv=0
                    else:
                        print("**************** unknown howto parameter ******************")

                    openvpn_packet.HS_Version=new_hsv
                    print("the new HS_Version:", new_hsv)
                    fuzzed=True

                # howto can be rand_any or rand_zero
                elif args.field=="ccs": # 
                    old_ccs=openvpn_packet.Change_Cipher_Spec_Message
                    new_ccs=old_ccs
                    if args.howto=="rand_any":
                        while new_ccs==old_ccs:
                            new_ccs = random.randint(0, 255) # random 1 byte int
                    elif args.howto=="rand_zero":
                        new_ccs=0
                    else:
                        print("**************** unknown howto parameter ******************")
                    
                    openvpn_packet.Change_Cipher_Spec_Message=new_ccs
                    print("the new Change_Cipher_Spec_Message:", new_ccs)
                    fuzzed = True

                elif args.field=="rlen":
                    old_rlen=openvpn_packet.Record_Length
                    new_rlen=old_rlen
                    if args.howto=="rand_any":
                        while new_rlen==old_rlen:
                            new_rlen=random.randint(0, 65535) # random 2-byte int
                    elif args.howto=="rand_zero":
                        new_rlen=0
                    else:
                        print("**************** unknown howto parameter ******************")
                    
                    openvpn_packet.Record_Length=new_rlen
                    print("the new Record_Length:", new_rlen)
                    fuzzed = True

                elif args.field=="hslen":
                    old_hslen=openvpn_packet.HS_Length
                    new_hslen=old_hslen
                    if args.howto=="rand_any":
                        while new_hslen==old_hslen:
                            new_hslen=random.randint(0, 0xffffff) # random 3-byte int
                    elif args.howto=="rand_zero":
                        new_hslen=0
                    else:
                        print("**************** unknown howto parameter ******************")
                    
                    openvpn_packet.HS_Length=new_hslen
                    print("the new HS_Length:", new_hslen)
                    fuzzed = True

                elif args.field=="tls_slen":
                    old_sidlen=openvpn_packet.Session_ID_Length
                    new_sidlen=old_sidlen
                    if args.howto=="rand_any":
                        while new_sidlen==old_sidlen:
                            new_sidlen=random.randint(0, 255) # random 1 byte int
                    elif args.howto=="rand_zero":
                        new_sidlen=0
                    else:
                        print("**************** unknown howto parameter ******************")
                    
                    openvpn_packet.Session_ID_Length=new_sidlen
                    print("the new Session_ID_Length:", new_sidlen)
                    fuzzed = True

                elif args.field=="tls_cslen":
                    old_cslen=openvpn_packet.Cipher_Suites_Length
                    new_cslen=old_cslen
                    if args.howto=="rand_any":
                        while new_cslen==old_cslen:
                            new_cslen=random.randint(0, 65535) # random 2-byte int
                    elif args.howto=="rand_zero":
                        new_cslen=0
                    else:
                        print("**************** unknown howto parameter ******************")
                    
                    openvpn_packet.Cipher_Suites_Length=new_cslen
                    print("the new Cipher_Suites_Length:", new_cslen)
                    fuzzed = True
                
                elif args.field=="tls_cmlen":
                    old_cmlen=openvpn_packet.Compression_Methods_Length
                    new_cmlen=old_cmlen
                    if args.howto=="rand_any":
                        while new_cmlen==old_cmlen:
                            new_cmlen=random.randint(0, 255) # random 1 byte int
                    elif args.howto=="rand_zero":
                        new_cmlen=0
                    else:
                        print("**************** unknown howto parameter ******************")
                    
                    openvpn_packet.Compression_Methods_Length=new_cmlen
                    print("the new Compression_Methods_Length:", new_cmlen)
                    fuzzed = True

                elif args.field=="tls_extlen":
                    old_extlen=openvpn_packet.Extensions_Length
                    new_extlen=old_extlen
                    if args.howto=="rand_any":
                        while new_extlen==old_extlen:
                            new_extlen=random.randint(0, 65535) # random 2-byte int
                    elif args.howto=="rand_zero":
                        new_extlen=0
                    else:
                        print("**************** unknown howto parameter ******************")
                    
                    openvpn_packet.Extensions_Length=new_extlen
                    print("the new Extensions_Length:", new_extlen)
                    fuzzed = True
                
            
            elif args.fuzzway=="reorder" and args.bunch=="s1" and nowpkt in s1_bunch_pkts:
                if nowpkt=="s_hello_1":
                    s1_saved_pkts[0]=openvpn_packet
                else: # must be s_hello_2
                    s1_saved_pkts[1]=openvpn_packet

            elif args.fuzzway=="reorder" and args.bunch=="c1" and nowpkt in c1_bunch_pkts:
                if nowpkt=="ccs":
                    c1_saved_pkts[0]=openvpn_packet
                elif nowpkt=="c_c1":
                    c1_saved_pkts[1]=openvpn_packet
                else: # must be c_c2
                    c1_saved_pkts[2]=openvpn_packet

            elif args.fuzzway=="reorder" and args.bunch=="s2" and nowpkt in s2_bunch_pkts:
                if nowpkt=="s_c1":
                    s2_saved_pkts[0]=openvpn_packet
                elif nowpkt=="s_c2":
                    s2_saved_pkts[1]=openvpn_packet
                else: # must be s_c3
                    s2_saved_pkts[2]=openvpn_packet

            elif args.fuzzway=="replace" and args.howto=="ack21" and nowpkt=="c_ack2":
                openvpn_packet = c_saved_acks[0] # use c_ack1 to replace the c_ack2
                print(f"we display the {args.fuzzway} {args.howto} fuzzed ack packet:")
                openvpn_packet.show()

            elif args.fuzzway=="replace" and args.howto=="ack32" and nowpkt=="c_ack3":
                openvpn_packet = c_saved_acks[1] # use 2nd to replace 3rd
                print(f"we display the {args.fuzzway} {args.howto} fuzzed ack packet:")
                openvpn_packet.show()

            elif args.fuzzway=="replace" and args.howto=="ack43" and nowpkt=="c_ack4":
                openvpn_packet = c_saved_acks[2] # use 3rd to replace 4th
                print(f"we display the {args.fuzzway} {args.howto} fuzzed ack packet:")
                openvpn_packet.show()

            elif args.fuzzway=="replace" and nowpkt==args.pkt and args.howto=="sid_exchange": # replace sid_c with sid_s, sid_s with sid_c
                sid_local = openvpn_packet.Session_ID
                sid_remote = openvpn_packet.Remote_Session_ID
                openvpn_packet.Session_ID = sid_remote
                openvpn_packet.Remote_Session_ID = sid_local
                print("we display the ack with sid_c and sid_s exchanged:")
                openvpn_packet.show()

            elif args.fuzzway=="replace" and type_opcode==0x05 and args.howto=="cli2s" and args.pkt=="None":
                print("~~~~~~~~~~~~~~~~~ we replace using client2's sid_c and sid_s ~~~~~~~~~~~~~~~~ ")
                openvpn_packet.Session_ID = 14176572716850146438
                openvpn_packet.Remote_Session_ID = 17724891805362139753
                openvpn_packet.show()

            elif args.fuzzway=="replace" and type_opcode==0x05 and args.howto=="cli2s" and args.pkt==nowpkt:
                print(f"~~~~~~~~~~~~~~~~~ we replace {nowpkt} using client2's sid_c and sid_s ~~~~~~~~~~~~~~~~ ")
                openvpn_packet.Session_ID = 14648865146479322262
                openvpn_packet.Remote_Session_ID = 17784427170696230921
                openvpn_packet.show()

            # openvpn_packet.Message_Packet_ID_Array_Lenth =0
            # openvpn_packet.Message_Packet_ID = 0
            # openvpn_packet[Raw].load = 0
            # openvpn_packet.show()
            bytes_opacket = bytes(openvpn_packet)

            # not reorder 
            if args.fuzzway!="reorder":
                if type_opcode!=0x05 or args.fuzzway!="drop":
                    # if the packet is from the client 
                    if addr[1] == 40000:
                        self.transport.write(bytes_opacket, (server_ip, server_port))
                        print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to server:", server_port)
                    # else must be from the server port 1194
                    elif addr[1] == 1194:
                        self.transport.write(bytes_opacket, (client_ip, client_port))
                        print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to client:", client_port)

                    else: # should be from other ports which use nc to send data packets
                        print("************************* we got nc sent packets here *************************** ")
                        print("the raw part length:", len(openvpn_packet[Raw].load))
                        openvpn_packet.show()
                        self.transport.write(bytes_opacket, ("10.30.1.1", 4455))
                elif args.fuzzway=="drop" and type_opcode==0x05 : # and it's ack type packets
                    print(f"~~~~~~~~~~~~~~~~~~ we delibrately drop {nowpkt} to see effects ~~~~~~~~~~~~~~~~~~~~")


            else: # fuzzway="reorder", two possiblities, when non-related, just forward, otherwise, see if should forward
                if args.bunch=="s1":
                    if nowpkt not in s1_bunch_pkts: # just forward
                        # if the packet is from the client 
                        if addr[1]!=1194:
                            self.transport.write(bytes_opacket, (server_ip, server_port))
                            print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to server:", server_port)
                        # else must be from the server port 1194
                        elif addr[1] == 1194:
                            self.transport.write(bytes_opacket, (client_ip, client_port))
                            print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to client:", client_port)

                    else: # nowpkt in ..., we will see if we should reorder and send
                        if (s1_saved_pkts[0] is not None) and (s1_saved_pkts[1] is not None):
                            # the only way to reorder 
                            # must be from server, so send to client
                            bytes_opacket = bytes(s1_saved_pkts[1])
                            self.transport.write(bytes_opacket, (client_ip, client_port))
                            print(f"sent the {len(bytes_opacket)} bytes s_hello_2 packet to client:", client_port)
                            bytes_opacket = bytes(s1_saved_pkts[0])
                            self.transport.write(bytes_opacket, (client_ip, client_port))
                            print(f"sent the {len(bytes_opacket)} bytes s_hello_1 packet to client:", client_port)
                            print("**************** reordering s_hello_1 and s_hello_2 done *******************")
                        else:
                            print("**************** reordering s1 stocked, not ready to send ********************")

                elif args.bunch=="c1":
                    if nowpkt not in c1_bunch_pkts: # just forward
                         # if the packet is from the client 
                        if addr[1]!=1194:
                            self.transport.write(bytes_opacket, (server_ip, server_port))
                            print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to server:", server_port)
                        # else must be from the server port 1194
                        elif addr[1] == 1194:
                            self.transport.write(bytes_opacket, (client_ip, client_port))
                            print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to client:", client_port)

                    else: # nowpkt in..., we will see if we should reorder and send
                        if all(item is not None for item in c1_saved_pkts): # ready to send 
                            order_array = [0,1,2]
                            permutations = list(itertools.permutations(order_array))
                            permutations.remove(tuple(order_array)) # remove the original order
                            chosen_permutation = random.choice(permutations) # choose a random reordered array
                            print(f"************** the chosen reordered index array is {chosen_permutation} ****************")

                            for element in chosen_permutation:
                                bytes_opacket = bytes(c1_saved_pkts[element])
                                self.transport.write(bytes_opacket, (server_ip, server_port))
                                print(f"sent the {len(bytes_opacket)} bytes {c1_bunch_pkts[element]} packet to server:", server_port)
                            print("**************** reordering ccs, c_c1, c_c2 done *******************")
                        else: # not ready to send
                            print("**************** reordering c1 stocked, not ready to send ********************")

                elif args.bunch=="s2":
                    if nowpkt not in s2_bunch_pkts: # just forward
                        # if the packet is from the client 
                        if addr[1]!=1194:
                            self.transport.write(bytes_opacket, (server_ip, server_port))
                            print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to server:", server_port)
                        # else must be from the server port 1194
                        elif addr[1] == 1194:
                            self.transport.write(bytes_opacket, (client_ip, client_port))
                            print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to client:", client_port)

                    else: # must be nowpkt in..., we will see if we should reorder and send
                        if all(item is not None for item in s2_saved_pkts): # ready to send 
                            order_array = [0,1,2]
                            permutations = list(itertools.permutations(order_array))
                            permutations.remove(tuple(order_array)) # remove the original order
                            chosen_permutation = random.choice(permutations) # choose a random reordered array
                            print(f"************** the chosen reordered index array is {chosen_permutation} ****************")

                            for element in chosen_permutation:
                                bytes_opacket = bytes(s2_saved_pkts[element])
                                self.transport.write(bytes_opacket, (client_ip, client_port))
                                print(f"sent the {len(bytes_opacket)} bytes {s2_bunch_pkts[element]} packet to client:", client_port)
                            print("**************** reordering s_c1, s_c2, s_c3 done *******************")  

                        else: # not ready to send
                            print("**************** reordering s2 stocked, not ready to send ********************")

                else: # now it should be the ack reorders
                    if addr[1] == 40000:
                        self.transport.write(bytes_opacket, (server_ip, server_port))
                        print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to server:", server_port)
                    # else must be from the server port 1194
                    elif addr[1] == 1194:
                        self.transport.write(bytes_opacket, (client_ip, client_port))
                        print(f"sent the {fuzzed_dic[fuzzed]} {len(bytes_opacket)} bytes packet to client:", client_port)




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

    global args 
    args = parser.parse_args()

    reactor.listenUDP(binding_port, Forward())
    reactor.run()


if __name__ == "__main__":
    main()