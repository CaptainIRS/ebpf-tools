#!/bin/bash

DEBUG=0
TRACE_DURATION_MS=1000
TRACE_FILE=bpf.pftrace

# Check if sudo
if [ $(id -u) -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

while getopts t:dh opt; do
    case $opt in
        t) TRACE_DURATION_MS=$OPTARG ;;
        f) TRACE_FILE=$OPTARG ;;
        d) DEBUG=1 ;;
        h|*) echo "Usage: $0 [-t trace_duration_ms] [-f trace_file] [-d] [-h]" >&2
           exit 1 ;;
    esac
done

cd $(git rev-parse --show-toplevel)

cat /sys/kernel/debug/tracing/trace_pipe &
TRACE_PID=$!

ARGS="-t $TRACE_DURATION_MS -f $TRACE_FILE"
if [ $DEBUG -eq 1 ]; then
    ARGS="$ARGS -d"
fi

function cleanup {
    echo "Cleaning up..."
    kill $TRACE_PID
}
trap cleanup EXIT

./build/thread_visualizer $ARGS
