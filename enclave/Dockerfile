# For reproducible builds, pin the linux distro to an exact digest, here representing v3.20.1
FROM --platform=linux/amd64 alpine@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0
COPY ../target/x86_64-unknown-linux-musl/release/enclave .
CMD ["./enclave"]
