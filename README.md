[![DOI](https://zenodo.org/badge/851500012.svg)](https://doi.org/10.5281/zenodo.15476514)

This repository is the artifact for the paper FUZZVPN: Finding Vulnerabilities in OpenVPN in USENIX WOOT 2025 conference. 

It includes the environment setup instructions with Dockerfile provided, the main functional component code, the scripts to execute the experiments, as well as instructions on how to reproduce the findings reported in the paper. 

It also includes the unmodified OpenVPN 2.6.12 version source code as the fuzzing target. And we have prepared the configuration files to run OpenVPN in the artifact.

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
# We provide a script in fuzzcode/ to replace the IP in python files to be the specified IP of the user. 
# since the python files are in /fuzzcode directory that is mapped with the volumne method, the changes will be reflected inside the container
# assume the the user wants to use the IP 172.17.0.4, execute the script below outside the container 
./update_py_ip.sh 172.17.0.4


# Besides, the IP address of the server should also be updated in client configuration files. Inside the container, /etc/openvpn stores all the client and server configuration files 
# in /etc/openvpn, all the client configuration files are ended in .ovpn, so the user should change the IP address in each of the files, 
# e.g. the client1-raw-fuzz.ovpn has the line "remote 172.17.0.4 50000", the user should change "172.17.0.4" to be the correct IP address found in the experiment environment
# We provide a script in fuzzcode/ to replace the IP in config files to be the specified IP of the user 
# assume the the user wants to use the IP 172.17.0.4, execute the script below inside the container
cd /fuzzcode 
./update_config_ip.sh 172.17.0.4 

```


# 2. (Functional) active learning and constructing the MSC. 

Take UDP mode for example. Go to the udp-scripts directory, and run the script.

```
cd udp-scripts
./active-learning.sh 
```

The script takes around 10 min to finishe, then you will find in the /udp-active-learning-logs directory all the logs, and the detailed client or server behavior is manually analyzed from the client/server logs to construct the MSC (shown in the paper in Figure 2, page 6). 

E.g. restrict-1-client-raw.log shows the behaviors of the client side when only one control_v1 packet is allowed to be exchanged. Looking into this log file, we will find the sentences showing the behavior "TCPv4_CLIENT WRITE [14] to [AF_INET]172.17.0.5:50000: P_CONTROL_HARD_RESET_CLIENT_V2 kid=0 sid=f3447239 db694d12 [ ] pid=0 DATA", i.e., the client sends the above content in the first openvpn packet to the server. Analysing the client and server logs when different numbers of packets are allowed to be transmitted allow the user to know the inner behavior of both protocol sides. 

For TCP mode, similarly,

```
cd tcp-scripts
./active-learning.sh 
```

Then you will find in the /tcp-active-learning-logs directory all the logs, and the detailed client or server behavior is analyzed from the client/server logs to construct the MSC (shown in the paper in Figure 17, Page 17 ). For example, the file restrict-3-client-raw.log means the client side logs when we only allow the first 3 packets to be transmitted between the 2 parties, and we can infer the content of ciphertext in the third openvpn packet from the log sentences " SSL state (connect): before SSL initialization ... SSL state (connect): SSLv3/TLS write client hello", i.e., TLS client hello messages. These logging information provides a way to peek into the semantics of the ciphertext part of the Openvpn packets. 

# 3. (Functional) fuzzing with attack strategies in Section 4.2.  

**(1)Evaluate the malformed configuration file part** 

configs directory includes the malformed configuration part.
```
# in the configs directory, fuzzconfig.py generates the malformed configuration files for both the client and server for UDP mode
# For now in fuzzconfig.py, the output directory is '/fuzzedconfigs/'  
cd configs
./fuzzconfig.py 
# After the program finishes running, the user can find all the malformed configuration files generated in /fuzzedconfigs
# testconfig.sh run the malformed configuration files one by one, and the output log files can be found as .log files in /fuzzedconfigs. 
# it takes around 12 minutes to finish 
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
e.g. in udp-scripts directory, run_fuzzing.sh organizes almost all the experiments (for 1p1f field-level modification, reorder, replace, drop ,and acknowledgment-related strategies) using fuzz-udp-proxy.py, besides,
replay.sh and restrict-controlv1.sh use udp-proxy-manualtest.py to test the replay attacks and when restricting the number of control_v1 packets sent. 

The other scripts are for a small set of experiments if the user wants to focus on a specific type of attacks. The user is free to reuse those scripts and we attach a comment summary of their focus in the beginging of each scripts.

The user can change in the script the directory to store experiment logs: for now, the log directory in run_fuzzing.sh is "/udp-run-logs", the log directory in replay.sh is "/udp-replay-logs" and the log directory in restrict-controlv1.sh is "/udp-restrict-logs". 

The user can change fuzzing parameters in the script if they want, e.g. replay packet number.

The user can use analyse-log.sh to detect potential bugs, but the current log directory in the script is only "/udp-run-logs", and the user should change it to the corresponding directory if needed (e.g."/udp-restrict-logs" and "/udp-replay-logs").

Below we explain how to run the code for UDP mode, for TCP mode, the user can follow a similar process. 
```
cd udp-scripts
# the replay.sh takes around 5 minutes and may generate 2.3GB logs as observed in our experiments
./replay.sh
./restrict.sh
# the run_fuzzing.sh takes around 5 hours to finish and may generate 1GB logs 
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
vim replay-control_v1-None-None-None-server-tlsauth.log
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
# The 2 log files show that if we drop the M17 packets from the client as well as the reply packets from the server, then the client will face connection failure while the server can keep sending P_DATA_V2 packets, 
# since in the server's log we can find server connection success sentence “Peer Connection Initiated with [Client Address]" and the data packets sent by the server, 
# but cannot find in the client's log the client connection success sentence "Initialization Sequence Completed" 

vim restrict-8-20-client-raw.log 
# The log file show that in the second attack, when we resume packet sending, although the connection can succeed, the client is not aware that it actually dropped data that was sent prematurely by the server, 
# since from the client log file we can see the data packets are dropped: (UDPv4 READ [72] from [AF_INET]172.17.0.4:50000: P_DATA_V2 kid=0 DATA 00000000 00000157 [more...]... Key [AF_INET]172.17.0.4:50000 [0] not initialized (yet), dropping packet.) 
```

(5) To find the ACK-related attacks (paper Section 5.5)
Take TCP mode for example.
```
cd tcp-scripts
# it takes around 40 minutes to finish running and may generate 11MB logs 
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
# it takes around 33 minutes to finish running 
./ack-fuzzing.sh
cd /udp-ack-logs
vim 1p1f-s_ack-mid_array-rand_zero-None-server-raw.log
```
The user will find the server connection success sentence "Peer Connection Initiated with [Client Address]", so that we know UDP mode is robust to the attack.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.