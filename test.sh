#!/bin/bash
SMALL=false

# DEFINE THESE VARS FROM YOUR IFCONFIG
SRC=1.1.1.1
MAC=00:00:00:00:00:00
SND=e

make all source-ip=$SRC #2>&1 >/dev/null

small_test () {
    <lists/services_list_small pv -L 1 -l --quiet |
    sudo ./lzr --handshakes http -sendSYNs -sourceIP $SRC -gatewayMac $MAC -sendInterface $SND
}

random_test () {
    <lists/services_list_random pv -L 100 -l --quiet |
    sudo ./lzr --handshakes http -sendSYNs -sourceIP $SRC -gatewayMac $MAC -sendInterface $SND
}

if [ $SMALL = true ] ; then
    echo "Running small test..."
    small_test
else
    # Eric's runtime tests
    echo "Running tests with random IPs..."
    for i in {1..10}; do
        random_test 2>&1 | grep "Runtime:" | awk '{print $2}' >> results.txt
    done
fi

stty sane