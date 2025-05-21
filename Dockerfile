# this dockerfile will only include openvpn src, and we will build it in certain container, so that we add ASan and UBSan
FROM ubuntu:22.04

RUN apt update && \
    apt install -y \
    build-essential \
    libssl-dev \
    liblzo2-dev \
    libpam0g-dev \
    wget \
    tar \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libcap-ng-dev \
    libcap-ng0 \
    libnl-genl-3-200 \
    libnl-genl-3-dev \
    libnl-3-dev \
    libnl-3-200 \
    liblz4-dev \
    vim \
    tcpdump \
    python3 \
    pip \
    netcat \
    iperf3 \
    socat \
    net-tools

RUN pip install twisted scapy

RUN mkdir -p /usr/local/sbin
RUN mkdir -p /etc/openvpn

# copy the directory where the executable openvpn lies: not enough, since some shared libraries are needed
# we should add the whole source repo and compile
COPY openvpn-2.6.12 /openvpn
WORKDIR /openvpn
# RUN ./configure && make && make install

# the directory where all the configuration files lie 
# ensure that we put source file in the directory where the Dockerfile lies
# it has to be relative path instead of absolute 
COPY copied-etc-openvpn/ /etc/openvpn/

ENV PATH="/usr/local/sbin:${PATH}"

# claim that we will use the port, when running we need to add -p xx:xx to ensure we map the ports
EXPOSE 1194/udp
EXPOSE 50000/udp

CMD ["/bin/bash"]

