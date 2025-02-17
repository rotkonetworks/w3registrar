#!/bin/sh

# Default endpoint with override from first argument
WS_URL=${1:-"wss://api.w3reg.org"}

echo "Using WebSocket endpoint: $WS_URL"

echo "Creating SubscribeAccountState payload..."
SUBSCRIBE_MSG=$(cat << EOF | jq -c .
{
  "version": "1.0",
  "type": "SubscribeAccountState",
  "payload": {
    "network": "paseo",
    "account": "1Qrotkokp6taAeLThuwgzR7Mu3YQonZohwrzixwGnrD1QDT"
  }
}
EOF
)

echo "Subscribe payload:"
echo "$SUBSCRIBE_MSG" | jq .
echo

echo "Starting WebSocket connection and keeping it open..."
echo "$SUBSCRIBE_MSG" | websocat --text "$WS_URL" --no-close
