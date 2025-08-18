#!/bin/bash
METADATA_DIR="$(dirname "$0")/../metadata"
mkdir -p "$METADATA_DIR"
METADATA_DIR="$(cd "$METADATA_DIR" && pwd)"
subxt metadata -f bytes --url wss://people-kusama.dotters.network > "$METADATA_DIR/people_kusama.scale" && subxt metadata -f bytes --url wss://people-paseo.dotters.network > "$METADATA_DIR/people_paseo.scale" && subxt metadata -f bytes --url wss://people-polkadot.dotters.network > "$METADATA_DIR/people_polkadot.scale"
