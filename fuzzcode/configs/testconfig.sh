#!/bin/bash
# This script is designed to test OpenVPN configurations by running them in a controlled manner. 
# It processes all .conf and .ovpn files in the /fuzzedconfigs directory, runs them with OpenVPN, and logs the output. 
# The estimated time for each configuration is 3 seconds, after which the process is killed to prevent long-running instances.
# So in total, it will take around 5s * 141(files) = 705 seconds or approximately 12 minutes for the script to complete. 
# The logging directory takes around 1.4MB of disk space. 

cd /etc/openvpn
# find /fuzzedconfigs -type f -name "*.conf" | xargs -I {} openvpn --config {}
# find /fuzzedconfigs -type f -name "*.ovpn" | xargs -I {} openvpn --config {}
#!/bin/bash

for conf_file in /fuzzedconfigs/*.conf; do
    echo "Processing $conf_file..."
    openvpn --config "$conf_file" &> "/fuzzedconfigs/$(basename "$conf_file" .conf).log" &
    pid=$!
    sleep 3
    kill $pid
    wait $pid 2>/dev/null
    echo "$conf_file processed and logged to $(basename "$conf_file" .conf).log"
done

echo "All .conf files processed."


for conf_file in /fuzzedconfigs/*.ovpn; do
    echo "Processing $conf_file..."
    openvpn --config "$conf_file" &> "/fuzzedconfigs/$(basename "$conf_file" .ovpn).log" &
    pid=$!
    sleep 3
    kill $pid
    wait $pid 2>/dev/null
    echo "$conf_file processed and logged to $(basename "$conf_file" .ovpn).log"
done

echo "All .ovpn files processed."