#!/bin/bash

set -x

TARGET_PROCESS=dig
TARGET_QUERY=google.com
DELAY=1s
JITTER=0ms
TARGET_SERVER_IP=127.0.0.1

# Check if sudo
if [ $(id -u) -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

while getopts p:q:d:j:i:h opt; do
    case $opt in
        p) TARGET_PROCESS=$OPTARG ;;
        q) TARGET_QUERY=$OPTARG ;;
        d) DELAY=$OPTARG ;;
        j) JITTER=$OPTARG ;;
        i) TARGET_SERVER_IP=$OPTARG ;;
        h|*) echo "Usage: $0 [-p process_name] [-q query] [-d delay] [-j jitter] [-i dns_server_ip]" >&2
           exit 1 ;;
    esac
done

# Root qdisc
tc qdisc add dev lo handle 1: root htb default 12

# Parent class
tc class add dev lo parent 1: classid 1:1 htb rate 1000mbit
# Child class to be used for default traffic
tc class add dev lo parent 1:1 classid 1:11 htb rate 1000mbit
# Child class to be used for filtered traffic
tc class add dev lo parent 1:1 classid 1:12 htb rate 1000mbit

# NetEm qdisc for delaying traffic
tc qdisc add dev lo parent 1:11 handle 11: netem delay $DELAY $JITTER

# Filter based on mark and redirect to 1:11
tc filter add dev lo protocol all parent 1: u32 match mark 1 0xffffffff flowid 1:11

cd $(git rev-parse --show-toplevel)

cat /sys/kernel/debug/tracing/trace_pipe &
TRACE_PID=$!

function cleanup {
    echo "Cleaning up..."
    kill $TRACE_PID
    tc qdisc del dev lo root
}
trap cleanup EXIT

./build/dns_delay_injector -p $TARGET_PROCESS -q $TARGET_QUERY -t $TARGET_SERVER_IP
