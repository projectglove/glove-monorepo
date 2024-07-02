# For reproducible builds, pin the linux distro to an exact digest, here representing v3.20.1
FROM --platform=linux/amd64 alpine@sha256:dabf91b69c191a1a0a1628fd6bdd029c0c4018041c7f052870bb13c5a222ae76
COPY ../target/x86_64-unknown-linux-musl/release/enclave .
CMD ["./enclave"]
