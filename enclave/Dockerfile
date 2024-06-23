# TODO Use alpine instead, which will reduce the size of the image and potentially only require 512MB of enclave memory.
#  However, this requires building the enclave with musl, which has been a bit tricky to get working on Amazon Linux 2023.
FROM debian:stable-20240612-slim
# TODO If we can't get alphine working then manually install libssl3 from a specific version to keep the build reproducible.
RUN apt-get update && apt-get install libssl3 -y
COPY ../target/release/enclave .
CMD ["./enclave"]
