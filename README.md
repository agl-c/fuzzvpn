[![DOI](https://zenodo.org/badge/851500012.svg)](https://doi.org/10.5281/zenodo.15476514)

# 1. Environment Setup
Download the repository first. 
Our experiments are done on an x86_64 machine with Docker version 27.1.1.

```
# The Dockerfile prepares the source code of OpenVPN 2.6.12, builds it with ASan and UBSan enabled, 
# and prepares the /etc/openvpn directory with configuration files.
# Use the Dockerfile to build an image named openvpn2.6.12. (it takes around 5 minutes)
docker build -t openvpn2.6.12 .

# Then create a container using the openvpn2.6.12 image.
# Map the local fuzzcode directory to /fuzzcode inside the container.
# Note: --privileged and --net options are necessary for TUN device access.
# For example, if user "alice" downloaded this repo to /home/alice:
docker run --privileged -it \
  -v /home/alice/fuzzvpn/fuzzcode:/fuzzcode \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --name fuzzvpn \
  openvpn2.6.12
```


**Ensure you use the correct IP address!!** 

Take UDP mode for example, for TCP mode, similar things should be checked.

```
# The user should ensure the IP addresses in fuzz-udp-proxy.py and udp-proxy-manualtest.py are correct
# in our experiment environment, the IP addresses in those two python files are
# client_ip = "172.17.0.4"
# server_ip = "172.17.0.4"
# The user should change them to suit the experiment environment: the IP address can be found with ifconfig command, net-tools package should provide the command 
# since the above python files are in /fuzzcode directory that is mapped with the volumne method, the user can directly edit them outside the container and the changes will be reflected inside the container

# Besides, the IP address of the server should also be updated in each of the client configuration files. /etc/openvpn stores all the client and server configuration files 
# in /etc/openvpn, all the client configuration files are ended in .ovpn, so the user should change the IP address in each of the files, 
# e.g. the client1-raw-fuzz.ovpn has the line "remote 172.17.0.4 50000"
# the user should change "172.17.0.4" to be the correct IP address found in the experiment environment
# the user can edit the above configuration files under /etc/openvpn directory inside the container
```


# 2. (Functional) active learning and constructing the MSC. 

Take UDP mode for example. Go to the udp-scripts directory, and run the script.

```
cd udp-scripts
./active-learning.sh 
```

Then you will find in the /udp-active-learning-logs directory all the logs, and the detailed client or server behavior is analyzed from the client/server logs to construct the MSC (shown in the paper in Figure 2, page 6). 

E.g. restrict-1-client-raw.log shows the behaviors of the client side when only one control_v1 packet is allowed to be exchanged. 

For TCP mode, similarly,

```
cd tcp-scripts
./active-learning.sh 
```

Then you will find in the /tcp-active-learning-logs directory all the logs, and the detailed client or server behavior is analyzed from the client/server logs to construct the MSC (shown in the paper in Figure 17, pPage 17 ). 

# 3. (Functional) fuzzing with attack strategies in Section 4.2.  

**(1)Evaluate the malformed configuration file part** 

configs directory includes the malformed configuration part.
```
# in the configs directory, fuzzconfig.py generates the malformed configuration files for both the client and server for UDP mode
# For now in fuzzconfig.py, the output directory is '/fuzzedconfigs/'  
cd configs
./fuzzconfig.py 
# After the program finishes running, the user can find all the malformed configuration files generated in /fuzzedconfigs
# testconfig.sh run the malformed configuration files one by one, and the output log files can be found as .log files in /fuzzedconfigs
./testconfig.sh
# The user can use analyse-log.sh to detect suspicious behavior, as well as manually look into individual log files to confirm any problems
./analyse-log.sh
# for TCP mode, the corresponding program is tcp-fuzzconfig.py and tcp-testconfig.py
./tcp-fuzzconfig.py
./tcp-testconfig.sh
./tcp-analyse-log.sh
```
We give the instructions on detecting the port validation problem (shown in the paper, Section 5.3 Port Validation).

The user can follow this example to find other improperly validated configuration options (shown in the paper in Appendix Table 5.)
in /fuzzedconfigs.
``` 
cd /fuzzedconfigs
vim server-raw-port-malport.log
```
And the line "UDPv4 link local (bound): [AF_INET][undef]:4464" could be found, implying that when we set an invalid port 70000 exceeding 65535, the program used actually the port number 4464 which is the lowest 16 bits of 70000.


**(2)Evaluate the packet fuzzing part**

This part includes strategies like replay packets; field-level modification; reordering packets; and acknowledgment-related attacks.

For TCP and UDP mode respectively, there are two Python files for the packet fuzzing functionalities: 
udp-proxy-manualtest.py and tcp-proxy-manualtest.py for replay, restrict packet-number strategies; 
fuzz-udp-proxy.py and fuzz-tcp-proxy.py for 1p1f field-level modification, reorder, replace, drop and acknowledgment-related strategies.

The two directories tcp-scripts and udp-scripts include the experiment running scripts for TCP and UDP respectively,
e.g. in udp-scripts directory, run_fuzzing.sh organizes experiments (for 1p1f field-level modification, reorder, replace, drop ,and acknowledgment-related strategies) using fuzz-udp-proxy.py

replay.sh and restrict-controlv1.sh use udp-proxy-manualtest.py to test the replay attacks and when restricting the number of control_v1 packets sent.

The user can change in the script the directory to store experiment logs: for now, the log directory in run_fuzzing.sh is "/udp-run-logs", the log directory in replay.sh is "/udp-replay-logs" and the log directory in restrict-controlv1.sh is "/udp-restrict-logs". 

The user can change fuzzing parameters in the script if they want, e.g. replay packet number.

The user can use analyse-log.sh to detect potential bugs, but the current log directory in the script is only "/udp-run-logs", and the user should change it to the corresponding directory if needed (e.g."/udp-restrict-logs" and "/udp-replay-logs").

Below we explain how to run the code for UDP mode, for TCP mode, the user can follow a similar process. 
```
cd udp-scripts
./replay.sh
./restrict.sh
./run_fuzzing.sh
cd /fuzzcode 
# The user may update the directory_name="/udp-run-logs" in analyse-log.sh to other directories (e.g."/udp-restrict-logs" and "/udp-replay-logs")
./analyse-log.sh
# the user can also go to /udp-replay-logs , /udp-restrict-logs and /udp-run-logs to look into individual experiment logs to detect the problems
```

# 4. (Results reproducible) Find the attacks we reported in the paper (Section 5)
(1) To find the malformed configuration validation bugs (paper Section 5.3), follow the 3.(1) instructions above.

(2) To find the new DoS attacks (paper Section 5.2), take the UDP mode for example
```
cd udp-scripts
./replay.sh
```
And then go to /udp-replay-logs, take replay control_v1 packets for example, 
```
cd /udp-replay-logs
vim replay-control_v1-None-None-None-server-raw.log
```
And the lines "TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)... TLS Error: TLS handshake failed" showed that the Server connection cannot succeed. 

As to tls-auth mode, use 
```
cd udp-scripts
./tlsauth-replay.sh
```
And then go to /tlsauth-udp-replay-logs, take replay control_v1 packets for example, 
```
cd /tlsauth-udp-replay-logs
vim replay-control_v1-None-None-None-server-raw.log
```
And although we can find the warning sentences, the connection still failed. 
Check the corresponding replay-control_v1-None-None-None-client-raw.log, we can also see "TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)... TLS Error: TLS handshake failed".


(3) To find that the previous DoS attack was fixed (paper Appendix E.1), take the UDP mode for example
```
cd /udp-replay-logs
vim replay-client_restart_v2-None-None-None-server-raw.log
```
The line "Connection Attempt Note: --connect-freq-initial 100 10 rate limit exceeded, dropping initial handshake packets for the next 10 seconds" showed that a patch of rate limiting is implemented so that the connection can succeed. 

(4) To find the server prematurely sends data (paper Section 5.4) problem
Take UDP mode for example. The experiments are the two discussed in Section 5.4. 
```
cd /udp-scripts
./restrict.sh
```
The logs are stored in /udp-restrict-logs
```
cd /udp-restrict-logs
vim restrict-8-20000-client-raw.log 
vim restrict-8-20000-server-raw.log
# The 2 log files show that if we drop the M17 packets from the client as well as the reply packets from the server, then the client will face connection failure while the server can keep sending P_DATA_V2 packets.
vim restrict-8-20-client-raw.log 
# The 2 log files show that in the second attack, when we resume packet sending, although the connection can succeed, the client is not aware that it actually dropped data that was sent prematurely by the server.
# From the client log file we can see the data packets are dropped (UDPv4 READ [72] from [AF_INET]172.17.0.4:50000: P_DATA_V2 kid=0 DATA 00000000 00000157 [more...]... Key [AF_INET]172.17.0.4:50000 [0] not initialized (yet), dropping packet.) 
```

(5) To find the ACK-related attacks (paper Section 5.5)
Take TCP mode for example.
```
cd tcp-scripts
./tcp-ack-fuzz.sh
```
Then the logs are stored inside /tcp-ack directory. 

Take the attack "(1) changing the Message Packet-ID Array of M_12 (or M_11 or M_7 or M_5) in rand_zero way;" (Paper Section 5.5 last paragraph.) for example.
```
cd /tcp-ack
vim 1p1f-s_ack-mid_array-rand_zero-None-server-raw.log
```
And in the file, there is no server connection success sentence "Peer Connection Initiated with [Client Address]", so we know the attack blocked the connection.

In comparison, if the user did the same experiments with UDP mode.
```
cd udp-scripts
./ack-fuzzing.sh
cd /udp-ack-logs
vim 1p1f-s_ack-mid_array-rand_zero-None-server-raw.log
```
The user will find the server connection success sentence "Peer Connection Initiated with [Client Address]", so that we know UDP mode is robust to the attack.

