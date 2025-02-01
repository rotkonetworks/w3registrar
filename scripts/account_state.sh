#!/bin/bash

echo "Creating SubscribeAccountState payload..."

# Create Subscribe JSON message
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

test_websocket() {
    local message=$1
    local max_attempts=3
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        echo "Attempt $attempt to connect..."
        # Use websocket client mode with explicit text framing
        response=$(echo "$message" | websocat --text ws://127.0.0.1:8080)
        if [ $? -eq 0 ]; then
            echo "Connection successful!"

            # Process with jq if it's valid JSON
            if echo "$response" | jq . >/dev/null 2>&1; then
                echo "$response" | jq .
            else
                echo "Response is not valid JSON: $response"
            fi

            return 0
        else
            echo "Connection failed, waiting before retry..."
            sleep 2
        fi
        attempt=$((attempt + 1))
    done

    echo "Failed to connect after $max_attempts attempts"
    return 1
}

echo "Subscribe payload:"
echo $SUBSCRIBE_MSG | jq .
echo
echo "Testing subscription..."
test_websocket "$SUBSCRIBE_MSG"
