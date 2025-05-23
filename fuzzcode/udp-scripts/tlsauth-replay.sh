#!/bin/bash

directory_name="/tlsauth-udp-replay-logs"
mkdir -p "$directory_name"
# Ensure the log directory exists

run_fuzz(){
    local fuzzway="$1"
    local pkt="$2"
    local field="$3"
    local howto="$4"
    local bunch="$5"
    local num_replay="$6" 
    local allowed_control_v1_num="$7"
    local resume_control_v1_num="$8"

    # Get the current date and time in the format YYYYMMDD-HHMMSS
    # current_time=$(date "+%Y%m%d-%H%M%S")

    # change to the fuzzcode directory
    cd /fuzzcode
    # Start the fuzz program
    fuzz_log="$directory_name/$fuzzway-$pkt-$field-$howto-$bunch-$howto-$bunch-udpproxy.log"
    # PYTHONUNBUFFERED=1 ./fuzz-udp-proxy.py --fuzzway="$fuzzway" --pkt="$pkt" --field="$field" >"$fuzz_log" 2>&1 &
    PYTHONUNBUFFERED=1 ./udp-proxy-manualtest.py --fuzzway="$fuzzway" --pkt="$pkt" --field="$field" --howto="$howto" --bunch="$bunch" --num_replay="$num_replay" --allowed_control_v1_num="$allowed_control_v1_num" --resume_control_v1_num="$resume_control_v1_num" &
    echo "Running: ./udp-proxy-manualtest.py --fuzzway=$fuzzway --pkt=$pkt --field=$field --howto=$howto --bunch=$bunch --num_replay=$num_replay --allowed_control_v1_num=$allowed_control_v1_num --resume_control_v1_num=$resume_control_v1_num"
    fuzz_pid=$!
    echo "fuzz $fuzzway $pkt $field program started as a background process with PID: $fuzz_pid"


    # we'd better also capture the packet sequence as one of the experiment's results, too
    # we record the packets in and out of the server UDP port 1194
    # server side tcpdump
    ser_pcap_file="$directory_name/$fuzzway-$pkt-$field-$howto-$bunch-ser-raw.pcap"
    tcpdump -i any udp port 1194 -w "$ser_pcap_file" &
    ser_tcpdump_pid=$!
    echo "server side tcpdump program started as a background process with PID: $ser_tcpdump_pid"

    # client side tcpdump, for now we fixed client using port 40000
    cli_pcap_file="$directory_name/$fuzzway-$pkt-$field-$howto-$bunch-cli-raw.pcap"
    tcpdump -i any udp port 40000 -w "$cli_pcap_file" &
    cli_tcpdump_pid=$!
    echo "client side tcpdump program started as a background process with PID: $cli_tcpdump_pid"


    # change to the openvpn configuration directory
    cd /etc/openvpn
    # selection branches: raw; tls-auth; tls-crypt

    # e.g. the raw configuration
    # Start the OpenVPN server
    # since we integrated ASan UBSan with OpenVPN, we should redirect stdout and stderr respectively
    server_log="$directory_name/$fuzzway-$pkt-$field-$howto-$bunch-server-raw"
    server_err="$directory_name/$fuzzway-$pkt-$field-$howto-$bunch-err-server-raw"
    openvpn --config server-tlsauth.conf 1>"$server_log.log" 2>"$server_err.log" &
    server_pid=$!
    echo "openvpn server started as a background process with PID: $server_pid"

    # Start the OpenVPN client
    client_log="$directory_name/$fuzzway-$pkt-$field-$howto-$bunch-client-raw"
    client_err="$directory_name/$fuzzway-$pkt-$field-$howto-$bunch-err-client-raw"
    openvpn --config client1-tlsauth.ovpn 1>"$client_log.log" 2>"$client_err.log" &
    client_pid=$!
    echo "openvpn client started as a background process with PID: $client_pid"


    # Monitor the server process status and memory usage
    # every 1 second, execute the following code to check 
    # watch -n 1 -d "
    #     # Check memory usage
    #     mem_usage=\$(ps --pid $server_pid --no-headers --format '%mem')
    #     if [ \"\$mem_usage\" -gt 90 ]; then
    #         echo 'OpenVPN server memory usage too high: \$mem_usage%'
    #         kill -9 $fuzz_pid $server_pid $client_pid $tcpdump_pid
    #         exit 1
    #     fi
    # "

    # we created a new container to test the memory and undefined-behavior sanitizer usage
    # we use the below commands to build the openvpn again: 
    # ./configure
    # make  CFLAGS="-Wall -Wno-stringop-truncation -g -O2 -std=c99 -I/usr/include/libnl3 -fsanitize=address -fsanitize=undefined" CXXFLAGS="-fsanitize=address -fsanitize=undefined -g" LDFLAGS="-fsanitize=address -fsanitize=undefined" 
    # && make CFLAGS="-Wall -Wno-stringop-truncation -g -O2 -std=c99 -I/usr/include/libnl3 -fsanitize=address -fsanitize=undefined" CXXFLAGS="-fsanitize=address -fsanitize=undefined -g" LDFLAGS="-fsanitize=address -fsanitize=undefined" install


    # debugged with "wait" to monitor the program exit status, but gave up due to conflict with father/son process

    # set a timer 60s, after that we check the status, kill 4 processes
    echo "start sleeping for 70s"
    sleep 70
    echo "end sleep"
    # server process exit check
    if kill -0 $server_pid > /dev/null 2>&1; then
    # kill returns zero, pid still exist and we kill it
        echo "server 1 branch"
        kill $server_pid
        wait $server_pid  
        echo "Server Process $server_pid was killed after 60 seconds."
    
    else
        # kill retuns nonzero, pid has exited
        echo "server 0 branch"
        wait $server_pid
        exit_status=$?
        echo "Server Process $server_pid exited with status: $exit_status"
        mv "$server_log.log" "$server_log-crash.log"
        mv "$server_err.log" "$server_err-crash.log"
    fi

    # client process exit check
    if kill -0 $client_pid > /dev/null 2>&1; then
        # kill returns zero, pid still exist and we kill it
        # echo "C 1 branch"
        kill $client_pid
        wait $client_pid  
        echo "Client Process $client_pid was killed after 60 seconds."
    else
        # kill retuns nonzero, pid has exited
        # echo "C 0 branch"
        wait $client_pid
        exit_status=$?
        echo "Client Process $client_pid exited with status: $exit_status"
        mv "$client_log.log" "$client_log-crash.log"
        mv "$client_err.log" "$client_err-crash.log"
        
    fi

    kill -9 $fuzz_pid $ser_tcpdump_pid $cli_tcpdump_pid 
    echo "killed the fuzz program and 2 tcpdump programs"

    wait
    echo "All background processes have finished."
}



# we also write the replay actions here
fuzzway="replay"
pkt_array=("ack_c" "control_v1" "client_restart_v2" )
# pkt_array=("client_restart_v2")
field="None"
howto="None"
bunch="None"
num_replay=10000000
allowed_control_v1_num=200000
resume_control_v1_num=20
for pkt in "${pkt_array[@]}"; do
    echo "********************** we started a new fuzzing experiment *****************************"
    run_fuzz $fuzzway $pkt $field $howto $bunch $num_replay $allowed_control_v1_num $resume_control_v1_num
done 