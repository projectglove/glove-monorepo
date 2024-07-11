#!/bin/bash

set -Eeuxo pipefail

glove_build_env() {
  docker exec -t glove-build-env "$@"
}

rm -rf target
mkdir -p target/release
docker create --name glove-build-env -v /var/run/docker.sock:/var/run/docker.sock -w /glove ghcr.io/projectglove/glove-monorepo/glove-build-env@sha256:5211549088162917d286b1412d51d9d71dfb7f6cd5a0a85d7ce117eb61459f5e
docker cp . glove-build-env:/glove
docker start glove-build-env > /dev/null
glove_build_env git config --global --add safe.directory /glove
glove_build_env cargo test
glove_build_env cargo build --bins -p enclave --target x86_64-unknown-linux-musl -r
glove_build_env cargo build --bins --workspace --exclude enclave -r
glove_build_env touch --date='@0' target/x86_64-unknown-linux-musl/release/enclave
glove_build_env docker build --no-cache -t glove-enclave -f enclave/Dockerfile .
glove_build_env nitro-cli build-enclave --docker-uri glove-enclave --output-file target/release/glove.eif
glove_build_env nitro-cli describe-eif --eif-path target/release/glove.eif | jq -r '.Measurements.PCR0' > target/release/enclave_measurement.txt
docker cp glove-build-env:/glove/target .
docker image rm glove-enclave > /dev/null
docker rm -f glove-build-env > /dev/null
