#!/bin/sh

./build.sh

echo ">> Deploying contract"

NEAR_ENV=localnet near deploy  --wasmFile ./target/wasm32-unknown-unknown/release/contract.wasm --account_id shard0