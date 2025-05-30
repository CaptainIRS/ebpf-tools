#!/bin/bash

USER_ID=""
NS_INUM=""
SYSCALLS=""
CONTAINER_NAME=""
DEBUG=0

# Check if sudo
if [ $(id -u) -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

while getopts u:n:c:s:dlh opt; do
    case $opt in
        u) USER_ID=$OPTARG ;;
        n) NS_INUM=$OPTARG ;;
        c) CONTAINER_NAME=$OPTARG ;;
        s) SYSCALLS=$OPTARG ;;
        d) DEBUG=1 ;;
        h|*) echo "Usage: $0 [-u uid] [-n ns_inum] [-c container_name] [-s syscall1,syscall2,...] [-h]" >&2
           exit 1 ;;
    esac
done

if [ -n "$CONTAINER_NAME" ]; then
    if ! command -v lsns &> /dev/null; then
        echo "lsns is not available. Please install util-linux package"
        exit 1
    fi
    CONTAINER_ID=$(docker container ps -f name=$CONTAINER_NAME --format '{{.ID}}')
    echo "Container ID: $CONTAINER_ID"
    CONTAINER_EXEC_PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER_ID)
    echo "Container exec PID: $CONTAINER_EXEC_PID"
    NS_INUM=$(sudo lsns -t mnt -p $CONTAINER_EXEC_PID -n -o NS)
    echo "Container NS inum: $NS_INUM"
fi

if [ -z "$USER_ID" ] || [ -z "$NS_INUM" ] || [ -z "$SYSCALLS" ]; then
    echo "Usage: $0 [-u uid] [-n ns_inum] [-c container_name] [-s syscall1,syscall2,...] [-h]" >&2
    exit 1
fi

cd $(git rev-parse --show-toplevel)

cat /sys/kernel/debug/tracing/trace_pipe &
TRACE_PID=$!

ARGS="-u $USER_ID -n $NS_INUM -s $SYSCALLS"
if [ $DEBUG -eq 1 ]; then
    ARGS="$ARGS -d"
fi

function cleanup {
    echo "Cleaning up..."
    kill $TRACE_PID
}
trap cleanup EXIT

./build/syscall_blocker $ARGS
