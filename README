[![DOI](https://zenodo.org/badge/851500012.svg)](https://doi.org/10.5281/zenodo.15476514)
# use the Dockerfile to build an image openvpn2.6.12
# the Dockerfile prepares the source code of openvpn2.6.12, as well as the /etc/openvpn directory which stores configuration material
docker build -t openvpn2.6.12 .

# then create a container with the image openvpn2.6.12
# map the fuzzcode directory to a directory inside container
# note the priviledge and network options in the command
# e.g. user alice downloads the current directory in /home/alice
docker run --privileged -it -v /home/alice/openvpn2.6.12-docker/fuzzcode:/fuzzcode  --cap-add=NET_ADMIN --device=/dev/net/tun --name fuzzvpn openvpn2.6.12

# in the terminal of the container fuzzvpn
# we run usesan.sh to build openvpn with ASan, UBSan, we disable ASLR as a fix of ASan bug
cd /fuzzcode
./usesan.sh
# now we have the built openvpn

# for each of TCP and UDP mode, there are mainly two python files for the packet fuzzing functionalities, and the configs directory serves for malformed configuration part
# fuzz-udp-proxy.py and fuzz-tcp-proxy.py  serve for 1p1f, reorder, replace, drop strategies
# udp-proxy-manualtest.py and tcp-proxy-manualtest.py serve for replay, restrict strategies
# we use pip to install some packages before running the python file
pip install twisted
pip install scapy

# run_fuzzing.sh is the script organizing experiments using fuzz-udp-proxy.py 
# replay.sh is the script to test replay part
# restrict-controlv1.sh is the script to test when restricting the number of control_v1 packets sent
# we have corresponding scripts for TCP mode in the tcp-scripts directory

# below, we explain how to use the UDP mode program as an example
cd udp-scripts
# before runing the script, the user should ensure the IP addresses in fuzz-udp-proxy.py and udp-proxy-manualtest.py are correct
# in our experiment setting, the IP address in those two python files are
# client_ip = "172.17.0.3"
# server_ip = "172.17.0.3"
# the user should change them to suit their experiment environment when testing
# the IP address can be found with ifconfig command, net-tools package should provide the command 

# also, in the client configuration file, the IP address of server should be updated
# for now, in /etc/openvpn, the client1-raw-fuzz.ovpn has "remote 172.17.0.3 50000"
# the user should change "172.17.0.3" to be the correct IP address in his/her testing environment


# before running the script, the user should prepare a directory to store logs generated in the script
# for now, the log directory in run_fuzzing.sh is /new901run
# and the log directory in  replay.sh and restrict-controlv1.sh is /902runlogs
# the user can replace it in the script with his/her own directory
# then the user can run the script and store running log with the command below 
./run_fuzzing.sh | tee /new901run/run_fuzzing.out

# after the script finishes running, the user can run other scripts, too
# the user can change parameters of replay and restrict part, details in the script
./replay.sh | tee /902runlogs/replay.out
# after the script finishes running
./restrict-controlv1.sh | tee /902runlogs/restrict-controlv1.out

# we provide a script to help analyse logs
# the user have to update the directory_name there, for now in the script directory_name="/new901run"
./analyse_logs.sh 

# in the configs directory, malformed configuration files are generated
# fuzzconfig.py generates the malformed configuration files for both client and server
# the user should prepare a directory to store them, for now in fuzzconfig.py, output_dir = '/fuzzedconfigs/'
cd configs
./fuzzconfig.py
# after the python program finishes running, the user can find all the malformed configuration files generated in /fuzzedconfigs
# testconfig.sh run the malformed configuration file one by one, and the output logs of each run can be found as .log files in /fuzzedconfigs
./testconfig.sh



