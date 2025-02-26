#!/bin/bash
WS_URL=${1:-"ws://127.0.0.1:8080"}
CONNS=${2:-100}
TIMEOUT=30

declare -a PIDS
trap 'kill ${PIDS[@]} 2>/dev/null' EXIT

for i in $(seq 1 $CONNS); do
    account=$(polkadot key generate | grep "SS58 Address:" | cut -d':' -f2- | tr -d ' ')
    echo "{\"version\":\"1.0\",\"type\":\"SubscribeAccountState\",\"payload\":{\"network\":\"paseo\",\"account\":\"$account\"}}" | \
        timeout $TIMEOUT websocat --text "$WS_URL" --no-close 2>&1 &
    PIDS+=($!)
    sleep 0.1
done

START_TIME=$(date +%s)
while [ $(( $(date +%s) - START_TIME )) -lt 60 ]; do
    active=0
    for pid in "${PIDS[@]}"; do
        kill -0 $pid 2>/dev/null && ((active++))
    done
    echo "Active: $active / $CONNS"
    sleep 5
done
