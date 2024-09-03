#!/bin/bash

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