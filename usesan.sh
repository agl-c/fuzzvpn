#!/bin/bash
#./configure &&  make && make install
#export CFLAGS="-fsanitize=address -fsanitize=undefined -g"
#export CXXFLAGS="-fsanitize=address -fsanitize=undefined -g"
#export LDFLAGS="-fsanitize=address -fsanitize=undefined"
#make && make install
./configure
make  CFLAGS="-Wall -Wno-stringop-truncation -g -O2 -std=c99 -I/usr/include/libnl3 -fsanitize=address -fsanitize=undefined" CXXFLAGS="-fsanitize=address -fsanitize=undefined -g" LDFLAGS="-fsanitize=address -fsanitize=undefined"

make  CFLAGS="-Wall -Wno-stringop-truncation -g -O2 -std=c99 -I/usr/include/libnl3 -fsanitize=address -fsanitize=undefined" CXXFLAGS="-fsanitize=address -fsanitize=undefined -g" LDFLAGS="-fsanitize=address -fsanitize=undefined" install

#disable ASLR to fix ASan bug with os
echo 0 > /proc/sys/kernel/randomize_va_space
