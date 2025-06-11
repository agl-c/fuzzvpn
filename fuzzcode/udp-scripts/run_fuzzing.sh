#!/bin/bash
# This script is used to run fuzzing experiments on the OpenVPN UDP proxy combining different fuzzing strategies, 
# except the replay and restrict strategies that are in other scripts 
# Every single fuzzing experiment will run for 60 seconds, 
# so in total, it will take around 5 hour for the script to complete.
# And the looging directory may take around 1GB space 
log_dir="/udp-run-logs"   
# Ensure the log directory exists
mkdir -p "$log_dir"

run_fuzz(){
    local fuzzway="$1"
    local pkt="$2"
    local field="$3"
    local howto="$4"
    local bunch="$5"

    # Get the current date and time in the format YYYYMMDD-HHMMSS
    # current_time=$(date "+%Y%m%d-%H%M%S")

    # change to the fuzzcode directory
    cd /fuzzcode
    # Start the fuzz program
    fuzz_log="$log_dir/$fuzzway-$pkt-$field-$howto-$bunch-$howto-$bunch-udpproxy.log"
    # PYTHONUNBUFFERED=1 ./fuzz-udp-proxy.py --fuzzway="$fuzzway" --pkt="$pkt" --field="$field" >"$fuzz_log" 2>&1 &
    PYTHONUNBUFFERED=1 ./fuzz-udp-proxy.py --fuzzway="$fuzzway" --pkt="$pkt" --field="$field" --howto="$howto" --bunch="$bunch" &
    echo "Running: ./fuzz-udp-proxy.py --fuzzway=$fuzzway --pkt=$pkt --field=$field --howto=$howto --bunch=$bunch"
    fuzz_pid=$!
    echo "fuzz $fuzzway $pkt $field program started as a background process with PID: $fuzz_pid"


    # we'd better also capture the packet sequence as one of the experiment's results, too
    # we record the packets in and out of the server UDP port 1194
    # server side tcpdump
    ser_pcap_file="$log_dir/$fuzzway-$pkt-$field-$howto-$bunch-ser-raw.pcap"
    tcpdump -i any udp port 1194 -w "$ser_pcap_file" &
    ser_tcpdump_pid=$!
    echo "server side tcpdump program started as a background process with PID: $ser_tcpdump_pid"

    # client side tcpdump, for now we fixed client using port 40000
    cli_pcap_file="$log_dir/$fuzzway-$pkt-$field-$howto-$bunch-cli-raw.pcap"
    tcpdump -i any udp port 40000 -w "$cli_pcap_file" &
    cli_tcpdump_pid=$!
    echo "client side tcpdump program started as a background process with PID: $cli_tcpdump_pid"


    # change to the openvpn configuration directory
    cd /etc/openvpn
    # selection branches: raw; tls-auth; tls-crypt

    # e.g. the raw configuration
    # Start the OpenVPN server
    # since we integrated ASan UBSan with OpenVPN, we should redirect stdout and stderr respectively
    server_log="$log_dir/$fuzzway-$pkt-$field-$howto-$bunch-server-raw"
    server_err="$log_dir/$fuzzway-$pkt-$field-$howto-$bunch-err-server-raw"
    openvpn --config server-raw-fuzz.conf --verb 9 1>"$server_log.log" 2>"$server_err.log" &
    server_pid=$!
    echo "openvpn server started as a background process with PID: $server_pid"

    # Start the OpenVPN client
    client_log="$log_dir/$fuzzway-$pkt-$field-$howto-$bunch-client-raw"
    client_err="$log_dir/$fuzzway-$pkt-$field-$howto-$bunch-err-client-raw"
    openvpn --config client1-raw-fuzz.ovpn --verb 9 1>"$client_log.log" 2>"$client_err.log" &
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
    echo "start sleeping for 60s"
    sleep 60
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

# now we run fuzzing code with arguments which select fuzz strategy 
# firsly, change 1 selected type of pkt and change 1 selected field with selected value
fuzzway="1p1f"
# since we fuzz different fields for different pkts, we enumerate them respectively
# we can update with the full array of all acks to replace ack_v1
pkt_array=("hard_reset_c_v2" "hard_reset_s_v2" "c_hello" "s_hello_1" "s_hello_2" "ccs" "c_c1" "c_c2" "c_ack1" "c_ack2" "c_ack3" "c_ack4" "s_ack" "s_c1" "s_c2" "s_c3" "data_v2")
field_array=("op")
# how to change field value, now we have 3 ways: random value from valid value list(ensure nonequal); random any value; set as zero 
howto_array=("rand_vali" "rand_any" "rand_zero")
bunch="None"

field="op"
for pkt in "${pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 

# except ack_v1 and data_v2, all other pkts have the mpid field
mpid_pkt_array=("hard_reset_c_v2" "hard_reset_s_v2" "c_hello" "s_hello_1" "s_hello_2" "ccs" "c_c1" "c_c2" "s_c1" "s_c2" "s_c3")
field="mpid"
for pkt in "${mpid_pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 

# only the pkts below have tls_ctype field, note that tls continuting data won't
tls_ctype_pkt_array=("c_hello" "s_hello_1" "ccs" "s_c1" "s_c2" "s_c3")
field="tls_ctype"
for pkt in "${tls_ctype_pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 

#
tls_v_pkt_array=("c_hello" "s_hello_1" "ccs" "s_c1" "s_c2" "s_c3")
field="tls_v"
for pkt in "${tls_v_pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 

tls_htype_pkt_array=("c_hello" "s_hello_1")
field="tls_htype"
for pkt in "${tls_htype_pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 

hs_v_pkt_array=("c_hello" "s_hello_1")
field="hs_v"
for pkt in "${hs_v_pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 

howto_array2=("rand_any" "rand_zero")
ccs_pkt_array=("ccs")
field="ccs"
for pkt in "${ccs_pkt_array[@]}"; do
    for howto in "${howto_array2[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done 
done 

field="rlen"
rlen_pkt_array=("c_hello" "s_hello_1" "ccs" "s_c1" "s_c2" "s_c3")
for pkt in "${rlen_pkt_array[@]}"; do
    for howto in "${howto_array2[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done 
done 

field="hslen"
hslen_pkt_array=("c_hello" "s_hello_1")
for pkt in "${hslen_pkt_array[@]}"; do
    for howto in "${howto_array2[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done 
done 

field="tls_slen"
# ccs... does not have it
tls_slen_pkt_array=("c_hello" "s_hello_1")
for pkt in "${tls_slen_pkt_array[@]}"; do
    for howto in "${howto_array2[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done 
done 

field="tls_cslen"
pkt="c_hello"
for howto in "${howto_array2[@]}"; do
    echo "********************** we started a new fuzzing experiment *****************************"
    run_fuzz $fuzzway $pkt $field $howto $bunch
done 

field="tls_cmlen"
pkt="c_hello"
for howto in "${howto_array2[@]}"; do
    echo "********************** we started a new fuzzing experiment *****************************"
    run_fuzz $fuzzway $pkt $field $howto $bunch
done 


field="tls_extlen"
tls_extlen_pkt_array=("c_hello" "s_hello_1")
for pkt in "${tls_extlen_pkt_array[@]}"; do
    for howto in "${howto_array2[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done 
done 

# other fields 108 min to run , op field 39+12=51 min, reorder 3min, sum=163min, i.e. < 3h
# num of experiments: 163? 
# Secondly, reorder a selected bunch of packets
fuzzway="reorder"
pkt="None"
field="None"
howto="None"
bunch_array=("s1" "c1" "s2")
for bunch in "${bunch_array[@]}"; do
    echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
done


fuzzway="1p1f"
pkt_array=("hard_reset_c_v2" "hard_reset_s_v2" "c_hello" "s_hello_1" "s_hello_2" "ccs" "c_c1" "c_c2" "c_ack1" "c_ack2" "c_ack3" "c_ack4" "s_ack" "s_c1" "s_c2" "s_c3")
field="sid"
howto_array=("rand_any" "rand_zero")
bunch="None"
for pkt in "${pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 

# M1 doesn't have sid_r
pkt_array=("hard_reset_s_v2" "c_hello" "s_hello_1" "s_hello_2" "ccs" "c_c1" "c_c2" "c_ack1" "c_ack2" "c_ack3" "c_ack4" "s_ack" "s_c1" "s_c2" "s_c3")
field="sid_r"
for pkt in "${pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 


fuzzway="1p1f"
pkt_array=("hard_reset_s_v2" "c_hello" "s_hello_1" "s_hello_2" "ccs" "c_c1" "c_c2" "c_ack1" "c_ack2" "c_ack3" "c_ack4" "s_ack" "s_c1" "s_c2" "s_c3")
field="mid_array"
howto_array=("rand_vali" "rand_any" "rand_zero")
bunch="None"
for pkt in "${pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 

# we replace using client2's sid_c and sid_s for all acks
# fuzzway="drop"
# pkt="c_ack4"
# field="None"
# howto="None" 
# bunch="None"
# echo "********************** we started a new fuzzing experiment *****************************"
# run_fuzz $fuzzway $pkt $field $howto $bunch

# 16 * 2 + 15*2 = 62

# 15*3=45 min


# we exchange the sid_c and sid_s for all acks
fuzzway="replace"
pkt_array=("c_ack1" "c_ack2" "c_ack3" "c_ack4" "s_ack")
field="None"
howto="sid_exchange" 
bunch="None"
for pkt in "${pkt_array[@]}"; do
    echo "********************** we started a new fuzzing experiment *****************************"
    run_fuzz $fuzzway $pkt $field $howto $bunch
done 


# only except c_ack1, we can try to remove one of the element in mid array
# 10, 3210, 4321, 5432; 21
fuzzway="1p1f"
# 3210, 4321, 5432; 21
pkt_array=("c_ack2" "c_ack3" "c_ack4" "s_ack")
field="mid_array"
howto="rm_some" # for now, we remove the second element
# "large" then we replace the 1st element to be 9
bunch="None"

for pkt in "${pkt_array[@]}"; do
    echo "********************** we started a new fuzzing experiment *****************************"
    run_fuzz $fuzzway $pkt $field $howto $bunch
done 

# we try howto=large with all the acks
pkt_array=("c_ack1" "c_ack2" "c_ack3" "c_ack4" "s_ack")
howto="large"
for pkt in "${pkt_array[@]}"; do
    echo "********************** we started a new fuzzing experiment *****************************"
    run_fuzz $fuzzway $pkt $field $howto $bunch
done 


# now we run fuzzing code with arguments which select fuzz strategy 
fuzzway="replace"
pkt="None"
field="None"
bunch="None"
howto_array=("ack21" "ack32" "ack43")
for howto in "${howto_array[@]}"; do
    echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
done

# firsly, change 1 selected type of pkt and change 1 selected field with selected value
fuzzway="1p1f"
pkt_array=("c_ack1" "c_ack2" "c_ack3" "c_ack4")
howto_array=("rand_vali" "rand_any" "rand_zero")
field="mid_array"
bunch="None"

for pkt in "${pkt_array[@]}"; do
    for howto in "${howto_array[@]}"; do
        echo "********************** we started a new fuzzing experiment *****************************"
        run_fuzz $fuzzway $pkt $field $howto $bunch
    done
done 

pkt="s_ack"
howto_array=("rand_any" "rand_zero")
for howto in "${howto_array[@]}"; do
    echo "********************** we started a new fuzzing experiment *****************************"
    run_fuzz $fuzzway $pkt $field $howto $bunch
done

# 5 + 4 + 5 + 3 + 12 + 2 = 31

fuzzway="drop"
pkt="ack"
field="None"
howto="None" 
bunch="None"
echo "********************** we started a new fuzzing experiment *****************************"
run_fuzz $fuzzway $pkt $field $howto $bunch

# 32 + 45 + 62 + 163 = 139 + 163 = 302min = 5h
# replay 3*2 = 6 
# 2 
# 