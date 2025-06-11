#!/bin/bash
# This script measures the time taken to establish a VPN connection using OpenVPN. 
directory="/1207"
start_time=$(date +%s.%N)
openvpn --config /etc/openvpn/tcp-client2-raw.ovpn > $directory/tcp-cli-$start_time.log 2>&1 &
pid=$!


while ! grep -q "Initialization Sequence Completed" $directory/tcp-cli-$start_time.log; do
  sleep 0.1
done

end_time=$(date +%s.%N)
elapsed_time=$(awk "BEGIN {print $end_time - $start_time}")
echo "start time:$start_time"
echo "end time:$end_time"
echo "VPN client connection time: $elapsed_time seconds"
kill $pid
