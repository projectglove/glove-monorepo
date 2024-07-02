FROM --platform=linux/amd64 amazonlinux:2023

ENV PATH="/root/.cargo/bin:$PATH"
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-amazon-linux-gcc

RUN yum update -y
RUN dnf install aws-nitro-enclaves-cli -y
RUN dnf install aws-nitro-enclaves-cli-devel -y
RUN yum groupinstall "Development Tools" -y
RUN yum install openssl-devel -y
RUN dnf install perl -y
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN rustup target install x86_64-unknown-linux-musl

CMD ["sleep", "infinity"]
