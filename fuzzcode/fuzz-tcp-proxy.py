#! /usr/bin/env python3
from twisted.internet import protocol
from twisted.internet import reactor
from scapy.all import *
import random 
import secrets
import argparse
import sys
import itertools


# edit this to map local port numbers to a list of host:port destinations
# source site: https://distrustsimplicity.net/articles/a-simple-udp-forwarder-in-twisted/
# TCP version: https://robertheaton.com/2018/08/31/how-to-build-a-tcp-proxy-3/

# args will determine fuzzing type, currently we add 
args = None 
# should first fill in the client_ip, server_ip, ( if it's manual testing, we select the vulnerability type: replay_select)

# sys.stdout = uncaching_output_stream(sys.stdout)

# "openvpn" or "wireguard"
test_type = "openvpn"
# 50000 for openvpn and 60000 for wireguard
binding_port = 50000
# "192.168.1.33" 
# now we use the same IP as it's in docker
client_ip = "172.17.0.3"
# "192.168.1.155" 
server_ip = "172.17.0.3"
# we use 40000 in docker vpn client
client_port = 40000
# 1194 for openvpn, 60683 for wireguard for now
server_port = 1194


# below part is for manual testing
# "control_v1" "client_restart_v2" "ack_c" "ack_s"
# "ndss_restart" means the forced negotiation crash attack in the ndss 2022 paper
replay_select = "none"

# allowed_pkt_num = 3 will cause retransmission of M3(from client) and M4, M6 (from server)
# allowed_pkt_num = 4 will cause retransmission of M4, M6 (from server) and the M5(ack) from client
# allowed_pkt_num = 5(ack) will cause sending of M6 from server
#  allowed_pkt_num = 6 will cause retransmission of M6 from server and sneding of M7, M8 from client
# allowed_pkt_num =7(ack) will cause restransimission of pid=3 inside M6 from server, and sending of M8 from client
# allowed_pkt_num =8 will cause restransimission of M8 from client, and sending of M9 and M10 from client
# allowed_pkt_num =9(ack) will cause sending of M10 from server, and retransmission of pid=3 and pid =4 inside M8 from client
# after reading the second part of M8, actually the first part of M10(tls sessuin ticekt) will be written out; since the left thing is Rc, Rs
# allowed_pkt_num =10 will cause restransimission of M10 from server, and sending of M11, M12, M15(push request) from client
# allowed_pkt_num =11 (ack) will cause restransimission of the second part of M10 from server, and sending of M12, M15(push request) from client
# allowed_pkt_num =12 (ack) will cause sending of M13 and DATA messages from server, and sending of M15(push request) from client
# allowed_pkt_num =13 will cause client sending M14 and DATA messages to server, and server retransmitting M13

allowed_pkt_num = 10000
resume_pkt_num = 16
sent_pkt_num = 0
pktnum = 0

allowed_control_v1_num = 100 # we increase it from 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
sent_control_v1_num = 0

# below for fuzzing
# when a P_CONTROL_V1 pkt comes, we remember its order for the client / server respectively
ctr_from_c = ""
ctr_from_s = ""
# nowpkt = ""

fuzzed_dic = ["original", "fuzzed"]
s1_bunch_pkts = ["s_hello1", "sh2in1"]
c1_bunch_pkts = ["ccs", "c_c1", "c_c2"] # maybe we reorder the openvpn parts inside one tcp packet 
s2_bunch_pkts = ["s_c1", "s_c2"] # here since the last control packet from server is not send together with the previous two, we consider only reordering the first two 
# pkt_array=("hard_reset_c_v2" "hard_reset_s_v2" "c_hello" "s_hello_1" "s_hello_2" "ccs" "c_c1" "c_c2" "ack_v1" "s_c1" "s_c2" "s_c3" "data_v2")

s1_saved_pkts = [None, None, None]
c1_saved_pkts = [None, None, None]
s2_saved_pkts = [None, None]

c_saved_acks = [None, None, None, None, None] # in total 5 acks from client
s_saved_acks = [None] # in total 1 ack from server
# 10, 210, 4321, 5432, 6543
c_ack_mid_arr =[b'\x00\x00\x00\x01\x00\x00\x00\x00', b'\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00',
b'\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01', b'\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x02',
b'\x00\x00\x00\x06\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x03']
# 210
s_ack_mid_arr = [b'\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00']
# nowack = ""

# all the valid mid_arr's in a normal connection 
# 10,210,4321,5432,6543,   0,3210, 543210
mid_arr = [b'\x00\x00\x00\x01\x00\x00\x00\x00', b'\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00',
b'\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01', b'\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x02',
b'\x00\x00\x00\x06\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x03',
b'\x00\x00\x00\x00', 
b'\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00',
b'\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00'
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

mpid_array = [0, 1, 2, 3, 4, 5, 6]
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
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None)  # it's one byte, while 5 bits for opcode,  3 bits for keyid 
                   ] 


# the "raw" means this version is for no tls-auth or tls-crypt, i.e., no replay protection/MAC/wholy encrypted control messages

# for now, we use fixed-length field for some length, maybe we can use the lenstr type, too
# client hard reset
class OpenVPN_raw_c_hr(Packet):
    name = "OpenVPN_raw_c_hr"
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    XIntField("Message_Packet_ID", None)
                    ]  # the Data field will be in Raw field, which is default
    
# server hard reset 
class OpenVPN_raw_s_hr(Packet):
    name = "OpenVPN_raw_s_hr"
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
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
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
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
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
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
                    StrFixedLenField("Extension_ec_point_formats", "", length=8)
                    # StrFixedLenField("Extension_supported_groups", "", length=16),
                    # StrFixedLenField("Extension_encrypt_then_mac", "", length=4),
                    # StrFixedLenField("Extension_extended_master_secret", "", length=4),
                    # StrFixedLenField("Extension_signature_algorithms", "", length=52),
                    # StrFixedLenField("Extension_supported_versions", "", length=13),
                    # StrFixedLenField("Extension_psk_key_exchange_modes", "", length=6),
                    # StrFixedLenField("Extension_key_share", "", length=42)
                    # not sure about the rest JA4, JA4_r, JA3 Fullstring, JA3 stuff
                    ]

# server hello, change cipher spec, 2 app data, and segment data
class OpenVPN_raw_ctr_sh(Packet):
    name = "OpenVPN_raw_ctr_sh"
    fields_desc = [ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
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
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
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
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
                    XByteField("Message_Packet_ID_Array_Lenth", None),
                    # 1-->4 bytes; 2---> 8bytes long
                    StrLenField("Packet_ID_Array", "", length_from = lambda pkt: 4 * pkt.Message_Packet_ID_Array_Lenth),
                    XLongField("Remote_Session_ID", None)
                    ]


# change cipher spec from client and segment data
class OpenVPN_raw_ctr_ccs(Packet):
    name = "OpenVPN_raw_ctr_ccs"
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
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


# P_CONTROL_V1 TLS 3 application data in one pkt
class OpenVPN_raw_ctr_3app(Packet):
    name = "OpenVPN_raw_ctr_3app"
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
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
                    StrLenField("Encrypted_Application_Data2", "", length_from=lambda pkt: pkt.Record_Length_ead2),

                    # TLS record layer
                    # next is the third application data
                    XByteField("TLS_Content_type3", None),  # Application Data (23)
                    XShortField("TLS_Version_ead3", None), # e.g. TLS 1.2 0x0303
                    XShortField("Record_Length_ead3", None),  
                    StrLenField("Encrypted_Application_Data3", "", length_from=lambda pkt: pkt.Record_Length_ead3)
                   
                    ]


# P_CONTROL_V1 TLS 2 application data in one pkt
class OpenVPN_raw_ctr_2app(Packet):
    name = "OpenVPN_raw_ctr_2app"
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
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
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None), XLongField("Session_ID", None), 
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
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None),
                    XStrFixedLenField("Peer_ID", "", length=3) # might be 0, so we display the x way 
                    # the below raw filed part is simply data, i.e., encrypted app data in the vpn data channel 
                    ]

# we define the mutation behaviors below, including field-wise, packet-wise, sequence-wise


# since it's TCP proxy, there are two connections we have to maintain 
class TCPProxyProtocol(protocol.Protocol):
    """
    TCPProxyProtocol listens for TCP connections from a
    client (eg. a phone) and forwards them on to a
    specified destination (eg. an app's API server) over
    a second TCP connection, using a ProxyToServerProtocol.

    It assumes that neither leg of this trip is encrypted.
    """
    def __init__(self):
        self.buffer = None
        self.proxy_to_server_protocol = None
 
    def connectionMade(self):
        """
        Called by twisted when a client connects to the
        proxy. Makes an connection from the proxy to the
        server to complete the chain.
        """
        print("Connection made from CLIENT => PROXY")
        proxy_to_server_factory = protocol.ClientFactory()
        proxy_to_server_factory.protocol = ProxyToServerProtocol
        proxy_to_server_factory.server = self
 
        reactor.connectTCP(server_ip, server_port,
                           proxy_to_server_factory)
 
    def dataReceived(self, data):
        """
        Called by twisted when the proxy receives data from
        the client. Sends the data on to the server.

        CLIENT ===> PROXY ===> DST
        """
        global sent_pkt_num
        global allowed_pkt_num
        global resume_pkt_num
        global pktnum
        global c1_saved_pkts
        nowpkt = "" # we have to reset the nowpkt for each new pkt 

        data1 = None
        data2 = None
        data3 = None
        fuzzeddata = data 
        pktnum+=1

        get2fields = to_get_op_code(data) 
        getopcode = (get2fields.Type & OPCODE_MASK) >> 3
        print("Before parsing, data len: ", len(data), ", openvpn packet len: ", get2fields.plen, " and opcode ", getopcode)

        # decide if this pkt has multiple openvpn pkts inside
        if len(data) > get2fields.plen+2:
            # print("this pkt has multiple openvpn pkts inside")
            # we have to dissect the data into multiple pkts
            data1 = data[:get2fields.plen+2]
            data2 = data[get2fields.plen+2:]
            get2fields2 = to_get_op_code(data2)
            getopcode2 = (get2fields2.Type & OPCODE_MASK) >> 3
            print("the second openvpn packet len", get2fields2.plen, " and opcode", getopcode2)

            if get2fields.plen + get2fields2.plen + 4 == len(data):
                print("the dissection is done with 2 sub pkts")
            else:
                data3 = data[(get2fields.plen + get2fields2.plen + 4):]
                get2fields3 = to_get_op_code(data3)
                getopcode3 = (get2fields3.Type & OPCODE_MASK) >> 3

                # we should also update the data2 part 
                data2 = data[get2fields.plen + 2:get2fields.plen + get2fields2.plen + 4]  

                print("the third openvpn packet len", get2fields3.plen, " and opcode", getopcode3)
                if get2fields.plen + get2fields2.plen + get2fields3.plen + 6 == len(data):
                    print("the dissection is done with 3 sub pkts")
                # in case the M7 and M8 are together in one pkt
                else:
                    data4 = data[(get2fields.plen + get2fields2.plen + get2fields3.plen + 6):]
                    get2fields4 = to_get_op_code(data4)
                    getopcode4 = (get2fields4.Type & OPCODE_MASK) >> 3
                    data3 = data[(get2fields.plen + get2fields2.plen + 4):get2fields.plen + get2fields2.plen + get2fields3.plen + 6]
                    print("the fourth openvpn packet len", get2fields4.plen, " and opcode", getopcode4)
                    print("the dissection is done with 4 sub pkts")

        if getopcode == P_CONTROL_HARD_RESET_CLIENT_V2:
            openvpn_packet = OpenVPN_raw_c_hr(data)
            nowpkt = "hard_reset_c_v2"

        elif getopcode == P_ACK_V1: # 5 kinds of acks
            openvpn_packet = OpenVPN_raw_ack1(data)
            if openvpn_packet.Packet_ID_Array == c_ack_mid_arr[0]:
                nowpkt = "c_ack1"
            elif openvpn_packet.Packet_ID_Array == c_ack_mid_arr[1]:
                nowpkt = "c_ack2"
            elif openvpn_packet.Packet_ID_Array == c_ack_mid_arr[2]:
                nowpkt = "c_ack3"
            elif openvpn_packet.Packet_ID_Array == c_ack_mid_arr[3]:
                nowpkt = "c_ack4"
            elif openvpn_packet.Packet_ID_Array == c_ack_mid_arr[4]:
                nowpkt = "c_ack5"
            
        elif getopcode == P_DATA_V2:
            openvpn_packet = OpenVPN_raw_data(data)
            nowpkt = "data_v2"

        elif getopcode == P_CONTROL_V1:
            control_packet = OpenVPN_raw_ctr(data)
            if control_packet.TLS_Content_type == 22: # handshake, so client hello
                openvpn_packet = OpenVPN_raw_ctr_ch(data)
                nowpkt = "c_hello"

            elif control_packet.TLS_Content_type == 20: # change cipher spec
                # this should be 3 packets inside one, we deal with data1, data2,data3 separately
                # if all the three exist 
                if data1 and data2 and data3: 
                    openvpn_packet1 = OpenVPN_raw_ctr_ccs(data1)
                    # we parse like this since segmentation happens which prevents us from parsing the logically following application records 
                    openvpn_packet2 = OpenVPN_raw_ctr(data2) 
                    openvpn_packet3 = OpenVPN_raw_ctr(data3) 
                    nowpkt = "3in1"
                else:
                    # should not go to this branch 
                    print("Not 3 in one, maybe only the change cipher spec packet")
                    openvpn_packet = control_packet 

            else:
                # might be application data? 
                openvpn_packet = OpenVPN_raw_ctr(data)
                   

        # now we do the fuzzing part 
        # first, for 1p1f, we confirm we should fuzz the current pkt, either directly the same pkt or we can find the target pkt in the 3 in 1 pkt
        if args.fuzzway == "1p1f" and (nowpkt == args.pkt or (nowpkt == "3in1" and args.pkt in ["ccs", "c_c1", "c_c2"])):
            # for 3 in 1 case, we first locate the target pkt 
            if args.pkt == "ccs" and data1:
                openvpn_packet = openvpn_packet1 
            elif args.pkt == "c_c1" and data2:
                openvpn_packet = openvpn_packet2
            elif args.pkt == "c_c2" and data3:
                openvpn_packet = openvpn_packet3 
            else:
                # should be only one pkt 
                pass 

            if args.field=="op":
                # ensure choosing a different op_code
                old_opcode = (openvpn_packet.Type & OPCODE_MASK) >> 3
                old_keyid = openvpn_packet.Type & KEYID_MASK
                new_opcode = old_opcode

                if args.howto=="rand_vali": # random value from the valid value list
                    while new_opcode==old_opcode: 
                        new_opcode = random.choice(opcode_array)
                elif args.howto=="rand_any": # random value which occupies 5bit, i.e., from [0, 31]
                    while new_opcode==old_opcode: 
                        new_opcode = random.randint(0, 31)
                elif args.howto=="rand_zero":
                    new_opcode = 0
                else:
                    print("**************** unknown howto parameter ******************")

                new_type = (new_opcode << 3) | old_keyid
                openvpn_packet.Type = new_type
                print("the new opcode:", new_opcode, " keyid:", old_keyid, " type:", openvpn_packet.Type)
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
        
            # now we should use openvpn_packet to replace the original pkt which is 3 in one
            if args.pkt == "ccs":
                openvpn_packet1 = openvpn_packet
            elif args.pkt == "c_c1":
                openvpn_packet2 = openvpn_packet
            elif args.pkt == "c_c2":
                openvpn_packet3 = openvpn_packet
            else:
                # no need to replace 
                pass 

        # now the reorder part fuzzing, prepare stuff from client to reorder, i.e., only c1 bunch which is 3 in 1 
        elif args.fuzzway=="reorder" and args.bunch=="c1" and nowpkt=="3in1":
            if data1 and data2 and data3:
                c1_saved_pkts[0]=openvpn_packet1
                c1_saved_pkts[1]=openvpn_packet2
                c1_saved_pkts[2]=openvpn_packet3
            else:
                # should not go to this branch
                print("we should not go to this branch")
                sys.exit(1)


        # since fuzzing is done, now prepare the bytes to be sent
        # print("~~~~~~~~~~~~~~~~ since fuzzing is done, now prepare the bytes to be sent and show packet ~~~~~~~~~~~~~~~~~")
        if data1==None: # not multiple in one pkt
            # openvpn_packet.show()
            tosend = bytes(openvpn_packet) 
        elif data1 and data2 and data3: # client side should only have 3 in one pkt if multiple in one pkt
            # openvpn_packet1.show()
            # openvpn_packet2.show()
            # openvpn_packet3.show()

            if args.fuzzway=="reorder" and args.bunch=="c1":
                order_array = [0,1,2]
                permutations = list(itertools.permutations(order_array))
                permutations.remove(tuple(order_array)) # remove the original order
                chosen_permutation = random.choice(permutations) # choose a random reordered array
                print(f"************** the chosen reordered index array for c1 bunch is {chosen_permutation} ****************")
    
                tosend = bytes(c1_saved_pkts[chosen_permutation[0]]) + bytes(c1_saved_pkts[chosen_permutation[1]]) + bytes(c1_saved_pkts[chosen_permutation[2]])
                print("**************** reordering ccs, c_c1, c_c2 done *******************")

            else:
                tosend = bytes(openvpn_packet1) + bytes(openvpn_packet2) + bytes(openvpn_packet3)   

        else:
            print("we should not go to this branch")
            sys.exit(1) 

        # below, just sending logic, send or not.
        if sent_pkt_num < allowed_pkt_num or pktnum >= resume_pkt_num:
            if self.proxy_to_server_protocol:
                self.proxy_to_server_protocol.write(tosend)
            else:
                self.buffer = tosend 
            print("CLIENT => SERVER, data length:", len(tosend))
            sent_pkt_num += 1
        else:
            print("CLIENT => SERVER: we delibrately stop sending with sent_pkt_num", sent_pkt_num, "and pkt len", len(tosend))
 
    def write(self, data):
        self.transport.write(data)
 
 
class ProxyToServerProtocol(protocol.Protocol):
    """
    ProxyToServerProtocol connects to a server over TCP.
    It sends the server data given to it by an
    TCPProxyProtocol, and uses the TCPProxyProtocol to
    send data that it receives back from the server on
    to a client.
    """

    def connectionMade(self):
        """
        Called by twisted when the proxy connects to the
        server. Flushes any buffered data on the proxy to
        server.
        """
        print("Connection made from PROXY => SERVER")
        self.factory.server.proxy_to_server_protocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''
 
    def dataReceived(self, data):
        """
        Called by twisted when the proxy receives data
        from the server. Sends the data on to to the client.

        DST ===> PROXY ===> CLIENT
        """
        global sent_pkt_num
        global allowed_pkt_num
        global resume_pkt_num
        global pktnum
        global s1_saved_pkts
        global s2_saved_pkts

        nowpkt = "" # we have to reset the nowpkt for each new pkt 

        data1 = None
        data2 = None
        data3 = None
        fuzzeddata = data 
        pktnum+=1

        get2fields = to_get_op_code(data) 
        getopcode = (get2fields.Type & OPCODE_MASK) >> 3
        print("Before parsing, data len: ", len(data), ", openvpn packet len: ", get2fields.plen, " and opcode ", getopcode)

        # decide if this pkt has multiple openvpn pkts inside
        if len(data) > get2fields.plen+2:
            print("this pkt has multiple openvpn pkts inside")
            # we have to dissect the data into multiple pkts
            data1 = data[:get2fields.plen+2]
            data2 = data[get2fields.plen+2:]
            get2fields2 = to_get_op_code(data2)
            getopcode2 = (get2fields2.Type & OPCODE_MASK) >> 3
            print("the second openvpn packet len", get2fields2.plen, " and opcode", getopcode2)

            if get2fields.plen + get2fields2.plen + 4 == len(data):
                print("the dissection is done with 2 sub pkts")
            else:
                data3 = data[(get2fields.plen + get2fields2.plen + 4):]
                get2fields3 = to_get_op_code(data3)
                getopcode3 = (get2fields3.Type & OPCODE_MASK) >> 3
                print("the third openvpn packet len", get2fields3.plen, " and opcode", getopcode3)
                print("the dissection is done with 3 sub pkts")

        else:
            print("this pkt has only one openvpn pkt inside")
            
        if getopcode == P_CONTROL_HARD_RESET_SERVER_V2:
            openvpn_packet = OpenVPN_raw_s_hr(data)
            nowpkt = "hard_reset_s_v2" 

        elif getopcode == P_ACK_V1: # 1 kind of ack
            openvpn_packet = OpenVPN_raw_ack1(data) 
            nowpkt = "s_ack"
            # in case ack and ctr2in1 together
            if data1 and data2 and data3:
                openvpn_packet1 = OpenVPN_raw_ctr(data2)
                openvpn_packet2 = OpenVPN_raw_ctr(data3)
                nowpkt = "ctr2in1"

        elif getopcode == P_DATA_V2:
            openvpn_packet = OpenVPN_raw_data(data)
            nowpkt = "data_v2"

        elif getopcode == P_CONTROL_V1:
            # might be 1 in 1 pkt, 2 in 1 pkt, 2 in 1 pkt, we can use mid to differ?
            control_packet = OpenVPN_raw_ctr(data) 
            if control_packet.TLS_Content_type == 22: # handshake, so server hello
                openvpn_packet = OpenVPN_raw_ctr_sh(data) 
                nowpkt = "s_hello1"
            elif control_packet.Message_Packet_ID == 2:
                # should be the first 2 in one; actually sever hello continual pkt where segmentation happens 
                if data1 and data2:
                    openvpn_packet1 = OpenVPN_raw_ctr(data1)
                    openvpn_packet2 = OpenVPN_raw_ctr(data2)
                    nowpkt = "sh2in1"
                else:
                    openvpn_packet = OpenVPN_raw_ctr(data)

            elif control_packet.Message_Packet_ID == 4:
                # should be the second last control pkt sent, where segmentation didn't happen
                if data1 and data2:
                    openvpn_packet1 = OpenVPN_raw_ctr_2app(data1)
                    openvpn_packet2 = OpenVPN_raw_ctr_1app(data2)
                    nowpkt = "ctr2in1"
                else:
                    openvpn_packet = OpenVPN_raw_ctr(data) 

            elif control_packet.Message_Packet_ID == 6:
                # should be the last control pkt sent, where segmentation didn't happen
                openvpn_packet = OpenVPN_raw_ctr_1app(data) 
                nowpkt = "s_c3" 
            else: 
                # might be application data? 
                openvpn_packet = OpenVPN_raw_ctr(data)


        # print("******************* the nowpkt is", nowpkt, "and args.pkt is", args.pkt)
        # now we do the fuzzing part 
        # first, for 1p1f, we confirm we should fuzz the current pkt, either directly the same pkt or we can find the target pkt in the 2 in 1 pkt
        if args.fuzzway == "1p1f" and (nowpkt == args.pkt or (nowpkt == "sh2in1" and args.pkt in ["s_hello21", "s_hello22"]) or (nowpkt == "ctr2in1" and args.pkt in ["s_c1", "s_c2"])):
            # for 3 in 1 case, we first locate the target pkt 
            # print("******************* we are in 1p1f, and nowpkt is", nowpkt, "and args.pkt is", args.pkt)
            if (args.pkt == "s_hello21" or args.pkt == "s_c1") and data1:
                openvpn_packet = openvpn_packet1 
            elif (args.pkt == "s_hello22" or args.pkt == "s_c2" ) and data2:
                openvpn_packet = openvpn_packet2
            else:
                # should be only one pkt 
                pass 

            if args.field=="op":
                # ensure choosing a different op_code
                old_opcode = (openvpn_packet.Type & OPCODE_MASK) >> 3
                old_keyid = openvpn_packet.Type & KEYID_MASK
                new_opcode = old_opcode

                if args.howto=="rand_vali": # random value from the valid value list
                    while new_opcode==old_opcode: 
                        new_opcode = random.choice(opcode_array)
                elif args.howto=="rand_any": # random value which occupies 5bit, i.e., from [0, 31]
                    while new_opcode==old_opcode: 
                        new_opcode = random.randint(0, 31)
                elif args.howto=="rand_zero":
                    new_opcode = 0
                else:
                    print("**************** unknown howto parameter ******************")

                new_type = (new_opcode << 3) | old_keyid
                openvpn_packet.Type = new_type
                print("the new opcode:", new_opcode, " keyid:", old_keyid, " type:", openvpn_packet.Type)
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
            
            # now we should use openvpn_packet to replace the original pkt which is 3 in one
            if args.pkt == "s_hello21" or args.pkt == "s_c1":
                openvpn_packet1 = openvpn_packet
            elif args.pkt == "s_hello22" or args.pkt == "s_c2":
                openvpn_packet2 = openvpn_packet
            else:
                # no need to replace
                pass 

        # now the reorder part fuzzing, prepare stuff from server to reorder, i.e., s1 bunch which includes M4 and M6; and s2 bunch which is 2 in 1
        # s_hello1 or sh2in1  
        elif args.fuzzway=="reorder" and args.bunch=="s1" and (nowpkt=="s_hello1" or nowpkt=="sh2in1"):
            if nowpkt=="s_hello1":
                s1_saved_pkts[0]=openvpn_packet
            else: # must be sh2in1
                if data1 and data2:
                    s1_saved_pkts[1]=openvpn_packet1
                    s1_saved_pkts[2]=openvpn_packet2
                else:
                    # should not go to this branch
                    print("we should not go to this branch")
                    sys.exit(1) 

        # ctr2in1 
        elif args.fuzzway=="reorder" and args.bunch=="s2" and nowpkt=="ctr2in1":
            if data1 and data2:
                s2_saved_pkts[0]=openvpn_packet1
                s2_saved_pkts[1]=openvpn_packet2
            else: 
                # should not go to this branch
                print("we should not go to this branch")
                sys.exit(1)       
           
        # since fuzzing is done, now prepare the bytes to be sent 
        # print("~~~~~~~~~~~~~~~~ since fuzzing is done, now prepare the bytes to be sent and show packet ~~~~~~~~~~~~~~~~~")
        if data1==None: # not multiple in one pkt
            # openvpn_packet.show()
            tosend = bytes(openvpn_packet)
        elif data1 and data2: # server side should only have 2 in one pkt if multiple in one pkt
            # openvpn_packet1.show()
            # openvpn_packet2.show()

            if args.fuzzway == "reorder" and args.bunch=="s1" and nowpkt=="sh2in1":
                order_array = [0,1,2]
                permutations = list(itertools.permutations(order_array))
                permutations.remove(tuple(order_array))
                chosen_permutation = random.choice(permutations)
                print(f"************** the chosen reordered index array for s1 bunch is {chosen_permutation} ****************")
           
                tosend = bytes(s1_saved_pkts[chosen_permutation[0]]) + bytes(s1_saved_pkts[chosen_permutation[1]]) + bytes(s1_saved_pkts[chosen_permutation[2]])
                print("**************** reordering s_hello and sh2in1 done *******************") 
            

            elif args.fuzzway == "reorder" and args.bunch=="s2" and nowpkt=="ctr2in1":
                # only one reorder way which is reverse the order 
                tosend = bytes(s2_saved_pkts[1]) + bytes(s2_saved_pkts[0])
                print("**************** reordering server ctr2in1 done *******************")

            else:
                tosend = bytes(openvpn_packet1) + bytes(openvpn_packet2)

        else: 
            print("we should not go to this branch")
            sys.exit(1) 

        # below, just sending logic, send or not.
        if sent_pkt_num < allowed_pkt_num or pktnum >= resume_pkt_num:
            # the only case we don't send now 
            if args.fuzzway == "reorder" and args.bunch=="s1" and nowpkt=="s_hello1":
                # cannot send now, we have to wait for sh2in1
                pass
            else:
                self.factory.server.write(tosend)
                print("SERVER => CLIENT, data length:", len(tosend))
                sent_pkt_num += 1
        else:
            print("SERVER => CLIENT: we delibrately stop sending with sent_pkt_num", sent_pkt_num, "and pkt len", len(tosend))
      
 
    def write(self, data):
        if data:
            self.transport.write(data)


def main():
    parser = argparse.ArgumentParser(description="Parse the fuzzing selection")
    parser.add_argument("--fuzzway", type=str, help="the selected fuzzing way", default="None")
    parser.add_argument("--pkt", type=str, help="the selected pkt to fuzz", default="None")
    parser.add_argument("--field", type=str, help="the selectd field to fuzz", default="None")
    parser.add_argument("--howto", type=str, help="how to change the field value", default="None")
    parser.add_argument("--bunch", type=str, help="the selected bunch of messages to reorder", default="None")

    global args 
    args = parser.parse_args()

    # Start the TCP forwarder (proxy)
    local_host = client_ip
    local_port = binding_port  # The port your proxy listens on
    factory = protocol.ServerFactory()
    factory.protocol = TCPProxyProtocol
    reactor.listenTCP(local_port, factory, interface=local_host)
    print(f"TCP forwarder listening on {local_host}:{local_port}")
    reactor.run()


if __name__ == "__main__":
    main()

