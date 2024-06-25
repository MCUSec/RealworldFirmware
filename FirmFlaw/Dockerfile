FROM ubuntu:22.04
LABEL maintainer="dingisoul"

# fix error 
RUN chmod 1777 /tmp

RUN apt-get update && \
    apt-get install -y openjdk-17-jdk python3-pip unzip 
    
WORKDIR /FirmFlaw

# COPY scripts
ADD . .

# download ghidra
ADD https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1_build/ghidra_11.1_PUBLIC_20240607.zip .

# unzip and configure the environment
RUN unzip ghidra_11.1_PUBLIC_20240607.zip && \
    rm ghidra_11.1_PUBLIC_20240607.zip && \
    pip3 install pyhidra && \
    mkdir logs res db fidb ghidra_projects

# set the environment for pyhidra
# fix the FirmFlaw when WORKDIR changes
ENV GHIDRA_INSTALL_DIR /FirmFlaw/ghidra_11.1_PUBLIC 
   
