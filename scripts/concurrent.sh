#!/bin/bash
CONNECTIONS=100
WS_URL=${1:-"ws://0.0.0.0:8080"}

echo "Generating $CONNECTIONS new addresses and querying concurrently..."

generate_and_query_address() {
    local conn_id=$1
    addr_info=$(subkey generate --output-type json --scheme ed25519 | jq -c '{accountId: .accountId, ss58Address: .ss58Address}')
    ss58_address=$(echo "$addr_info" | jq -r '.ss58Address')
    echo "[Conn $conn_id] Generated: $addr_info"
    query_payload=$(echo "{\"version\": \"1.0\", \"type\": \"SubscribeAccountState\", \"payload\": {\"network\": \"paseo\", \"account\": \"$ss58_address\"}}" | jq -c .)
    echo "[Conn $conn_id] Querying: $query_payload"
    echo "$query_payload" | websocat --text "$WS_URL" 2>&1 | sed "s/^/[Conn $conn_id] /"
}

for i in $(seq 1 $CONNECTIONS); do
    generate_and_query_address $i &
    sleep 0.1
    # Adjust sleep if needed to avoid overwhelming system
done

wait
echo "Finished generating and querying $CONNECTIONS addresses."
