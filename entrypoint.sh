#!/bin/sh
#disable ASLR to fix ASan bug with os
echo 0 > /proc/sys/kernel/randomize_va_space
echo "Entering shell..."
exec /bin/bash