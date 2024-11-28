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
        bc \
        kmod

RUN echo "This is a container to build the Linux kernel with LGCC. \n\
\n\
Instructions: \n\
\n\
1. Configure the kernel. For example using \`make nconfig\`. If making an \n\
   image for a virtualization guest, perhaps use \`make virt.config\`. See \n\
   \`make help\` for options. \n\
\n\
2. Merge in the LGCC configuration using \n\
   \`./scripts/kconfig/merge_config.sh .config lgcc_config\`. \n\
\n\
2. Compile the kernel using \`make LLVM=1 CC=clang\`. \n\
\n\
3. Take a coffee break while you wait ... \n" > /etc/motd
RUN echo "cat /etc/motd" >> /root/.bashrc

WORKDIR /usr/src/linux
