#!/bin/bash
# PYTHONUNBUFFERED=1 ./fuzz-udp-proxy.py --fuzzway=none --pkt=none --field=none >"/822logs/fuzzout.log" 2>&1 &

tcpdump -i any udp port 1194 -w "/822logs/ser_pcap_file.pcap" &
ser_tcpdump_pid=$!
tcpdump -i any udp port 40000 -w "/822logs/cli_pcap_file.pcap" &
cli_tcpdump_pid=$!

PYTHONUNBUFFERED=1 ./udp-proxy-manualtest.py  &
fuzz_pid=$!


cd /etc/openvpn
openvpn --config server-raw-fuzz.conf  --verb 9 1>"/822logs/server_log.log" 2>"/822logs/server_err.log" &
server_pid=$!
openvpn --config client1-raw-fuzz.ovpn  --verb 9 1>"/822logs/client_log.log" 2>"/822logs/client_err.log" &
client_pid=$!


sleep 60
echo "start killing all"
kill -9 $fuzz_pid $server_pid $client_pid 
kill -INT $ser_tcpdump_pid $cli_tcpdump_pid