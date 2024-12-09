#! /usr/bin/env python3
from twisted.internet import protocol
from twisted.internet import reactor
from scapy.all import *
import random 
import secrets
import argparse
import sys
import itertools
import time

# we use this src for the replay testing part, since it will use some measurement of replay intensity

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
num_replay = 10000000
saved_client_restart_v2 = None
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
resume_control_v1_num = 20

# below for fuzzing
# when a P_CONTROL_V1 pkt comes, we remember its order for the client / server respectively
ctr_from_c = ""
ctr_from_s = ""
nowpkt = ""

fuzzed_dic = ["original", "fuzzed"]
s1_bunch_pkts = ["s_hello_1", "s_hello_2"]
c1_bunch_pkts = ["ccs", "c_c1", "c_c2"] # maybe we reorder the openvpn parts inside one tcp packet 
s2_bunch_pkts = ["s_c1", "s_c2"] # here since the last control packet from server is not send together with the previous two, we consider only reordering the first two 
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
    fields_desc = [ ShortField("plen", None), # 2-byte expresses the openvpn packet length, the field is unique for TCP version 
                    XByteField("Type", None)  # it's one byte, while 5 bits for opcode,  3 bits for keyid 
                   ] 


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

        global num_replay
        global allowed_control_v1_num
        global control_v1_num
        global resume_control_v1_num
        global saved_client_restart_v2

        num_replay = args.num_replay
        allowed_control_v1_num = args.allowed_control_v1_num
        resume_control_v1_num = args.resume_control_v1_num

        fuzzeddata = data 
        pktnum+=1

        get2fields = to_get_op_code(data) 
        getopcode = (get2fields.Type & OPCODE_MASK) >> 3
        print("openvpn packet len", get2fields.plen, " and opcode", getopcode)
        openvpn_packet = get2fields
        
        if sent_pkt_num < allowed_pkt_num or pktnum >= resume_pkt_num:
            if self.proxy_to_server_protocol:
                self.proxy_to_server_protocol.write(data)
            else:
                self.buffer = data
                print("late launch of right part happens")
            print("CLIENT => SERVER, length:", len(data))
            sent_pkt_num += 1

        else:
            print("CLIENT => SERVER: we delibrately stop sending with sent_pkt_num", sent_pkt_num, "and pkt len", len(data))

        # replay part 
        # if the pkt is Client_hard_reset_v2, we generate 100 such pkts to see the effects
        if getopcode == 0x07 and args.fuzzway == "replay" and args.pkt == "client_restart_v2":
            saved_client_restart_v2 = openvpn_packet
            print("we first save the client_restart_v2 and wait later to replay")
                # else:
                #     self.buffer = bytes(new_pkt)
                #     print("late launch of right part happens") 
                #     print("use buffer to send a copy of client-restart-v2, ", len(bytes(new_pkt)))

        # we think the right part protocol has launched up now, and current op is no 7, we have stored the one to replay, do it 
        if args.fuzzway == "replay" and args.pkt == "client_restart_v2" and saved_client_restart_v2 and getopcode !=0x07:
            print("we use the initial pkt from client and tart sending", num_replay, " copies of it")
            for i in range(num_replay):
                new_pkt = saved_client_restart_v2
                # create a new random 8 byte client session ID in the type of int
                # print("SHOULD DEBUG SETTING THE NEW RANDOM SESSION ID.....")
                # new_pkt.Session_ID = int.from_bytes(secrets.token_bytes(8), byteorder='big')
                # print("sent a new packet with randomly-created client session_id to server: 1194")
            
                if self.proxy_to_server_protocol:
                    self.proxy_to_server_protocol.write(bytes(new_pkt))
                    # print("use write to send a copy of client-restart-v2, ", len(bytes(new_pkt)))
    

        if getopcode == 0x05 and args.fuzzway == "replay" and args.pkt == "ack_c":
            print("we got an ack packet from client")
            new_pkt = openvpn_packet
            bytes_new_pkt = bytes(new_pkt)
            len_bytes_new_pkt = len(bytes_new_pkt)
            start_time = time.time() 
            total_bytes_sent = 0 

            print(f"Below we will send {num_replay} copies of {len_bytes_new_pkt}-bytes ack pkt to server: 1194")
            for i in range(num_replay): # 100000 for ack_c no tls-auth, 100000 for tls-auth
                self.proxy_to_server_protocol.write(bytes(new_pkt))
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


        if getopcode == 0x04 and args.fuzzway == "replay" and args.pkt == "control_v1":
            print("we got the p_control_v1 pkt from client")
            new_pkt = openvpn_packet
            bytes_new_pkt = bytes(new_pkt)
            len_bytes_new_pkt = len(bytes_new_pkt)
            start_time = time.time() 
            total_bytes_sent = 0 

            print(f"Below we will send {num_replay} copies of {len_bytes_new_pkt}-bytes p_control_v1 pkt to server: 1194")
            for i in range(num_replay): # 1000 for no tls-auth, 100000 for tls-auth
                # simply replay the p_control_v1 pkt since it won't be checked with rate limit
                self.proxy_to_server_protocol.write(bytes(new_pkt))
                total_bytes_sent += len_bytes_new_pkt
                
                if i==1000:
                    print("we measure the sending rate when 1000 packets are sent")
                    end_time = time.time() 
                    total_time = end_time - start_time
                    if total_time > 0:  
                        bytes_per_second = total_bytes_sent / total_time  
                        print(f"Total bytes sent: {total_bytes_sent} bytes in {total_time:.2f} seconds.")
                        print(f"Bytes per second: {bytes_per_second:.2f} bytes/sec")

 
 
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

        fuzzeddata = data 
        pktnum+=1

        get2fields = to_get_op_code(data) 
        getopcode = (get2fields.Type & OPCODE_MASK) >> 3
        print("openvpn packet len", get2fields.plen, " and opcode", getopcode)
        
        if sent_pkt_num < allowed_pkt_num or pktnum >= resume_pkt_num:
            self.factory.server.write(data)
            print("SERVER => CLIENT, length:", len(data))
            sent_pkt_num += 1
        else:
            print("SERVER => CLIENT: we delibrately stop sending with sent_pkt_num", sent_pkt_num, "and pkt len", len(data))

     
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
    parser.add_argument("--num_replay", type=int, help="the num of replay", default=10000000)
    parser.add_argument("--allowed_control_v1_num", type=int, help="the threshold of allowed control_v1 pkt num", default=200000)
    parser.add_argument("--resume_control_v1_num", type=int, help="the threshold of control_v1 pkt num to resume sending", default=20000)


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

