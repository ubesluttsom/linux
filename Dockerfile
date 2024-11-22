FROM ubuntu:latest

RUN apt update && \
    apt install -y \
        build-essential \
        clang \
        llvm \
        lld \
        libncurses-dev \
        bison \
        flex \
        libssl-dev \
        libelf-dev \
        bc

WORKDIR /usr/src/linux
