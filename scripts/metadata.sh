#!/bin/bash
METADATA_DIR="$(cd "$(dirname "$0")"/../metadata && pwd)"
subxt metadata -f bytes --url wss://people-kusama.dotters.network > "$METADATA_DIR/people_kusama.scale" && subxt metadata -f bytes --url wss://people-paseo.dotters.network > "$METADATA_DIR/people_paseo.scale" && subxt metadata -f bytes --url wss://people-polkadot.dotters.network > "$METADATA_DIR/people_polkadot.scale"
