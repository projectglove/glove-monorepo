#!/bin/bash

cargo build -p service --release
cargo build -p enclave --release
docker build -t glove-enclave -f enclave/Dockerfile .
nitro-cli build-enclave --docker-uri glove-enclave --output-file target/release/glove.eif
