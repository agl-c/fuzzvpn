#!/bin/bash
# This script is used to analyse the OpenVPN logs after fuzzing experiments, searching for errors, warnings and connection success messages.

directory_name="/udp-run-logs" 

client_logs="*-client-raw*.log"
echo "~~~~~~~~~~~~~~~~~~~ we firstly search for the connection success sentence of client log ~~~~~~~~~~~~~~~~~~~~~~~~~~"
grep "Initialization Sequence Completed" $(echo "$directory_name/$client_logs")
# use -i to ignore captial letter or lower case
grep -i "error" $(echo "$directory_name/$client_logs")
grep -i "warning" $(echo "$directory_name/$client_logs")


server_logs="*-server-raw*.log"
echo "~~~~~~~~~~~~~~~~~~~ we then search for the connection success sentence of server log ~~~~~~~~~~~~~~~~~~~~~~~~~~"
grep "Peer Connection Initiated with" $(echo "$directory_name/$server_logs")
# use -i to ignore captial letter or lower case
grep -i "error" $(echo "$directory_name/$server_logs")
grep -i "warning" $(echo "$directory_name/$server_logs")
