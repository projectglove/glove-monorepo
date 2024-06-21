# TODO Use alpine instead, which will reduce the size of the image and potentially only require 512MB of enclave memory.
#  However, this requires building the enclave with musl, which has been a bit tricky to get working on Amazon Linux 2023.
FROM debian:stable-20240612-slim
COPY ../target/release/enclave .
CMD ["./enclave"]
