FROM ubuntu:20.04  

RUN chmod 1777 /tmp

# Install OpenJDK-11
RUN apt-get update && \
    apt-get install -y openjdk-11-jdk && \
    apt-get install -y openjdk-17-jdk && \
    apt-get install -y ant && \
    apt-get clean;

# Fix certificate issues
RUN apt-get update && \
    apt-get install ca-certificates-java && \
    apt-get clean && \
    update-ca-certificates -f;

# Setup JAVA_HOME -- useful for docker commandline
ENV JAVA_HOME /usr/lib/jvm/java-11-openjdk-amd64/
RUN export JAVA_HOME

# Installing all dependencies
RUN  apt-get -y update && \
     apt-get install python3-pip -y && \ 
     apt-get install -qy curl && \
     apt-get install -y z3 && \
     apt-get install -y unzip && \
     apt-get install -y rsync

RUN  pip3 install --upgrade pip
RUN  pip3 install scrapy

RUN curl -fsSL -O https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
RUN curl -fsSL -O https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar
RUN mv apktool_2.9.3.jar /usr/local/bin/apktool.jar 
RUN mv apktool /usr/local/bin/
RUN chmod +x /usr/local/bin/apktool
RUN chmod +x /usr/local/bin/apktool.jar

RUN  curl -fsSL https://ollama.com/install.sh | sh

# Creating folder structure
RUN  mkdir /home/otacap-complete
RUN  mkdir /home/otacap-complete/apk-dataset
RUN  mkdir /home/otacap-complete/apk-dataset-extracted
RUN  mkdir /home/otacap-complete/binwalk
RUN  mkdir /home/otacap-complete/bin-unpack
RUN  mkdir /home/otacap-complete/crawler
RUN  mkdir /home/otacap-complete/crawler/intermediate-results
RUN  mkdir /home/otacap-complete/FirmProcessing
RUN  mkdir /home/otacap-complete/FirmProcessing/originals
RUN  mkdir /home/otacap-complete/FirmXRay
RUN  mkdir /home/otacap-complete/otacap
RUN  mkdir /home/otacap-complete/FirmFlaw
RUN  mkdir /home/otacap-complete/FirmFlaw/firmwares
RUN  mkdir /home/otacap-complete/Android

# Creating folder structure
COPY apk-dataset/ /home/otacap-complete/apk-dataset/
COPY binwalk/ /home/otacap-complete/binwalk/ 
COPY bin-unpack/ /home/otacap-complete/bin-unpack
COPY crawler/ /home/otacap-complete/crawler/ 
COPY FirmProcessing/ /home/otacap-complete/FirmProcessing/ 
COPY FirmXRay/ /home/otacap-complete/FirmXRay/ 
COPY otacap/ /home/otacap-complete/otacap/ 
COPY FirmFlaw/ /home/otacap-complete/FirmFlaw/
COPY Android/ /home/otacap-complete/Android/

RUN mkdir /home/otacap-complete/crawler/httpftp/results
RUN mkdir /home/otacap-complete/crawler/httpftp/results/jsons


# Setting up FirmFlaw
WORKDIR /home/otacap-complete/FirmFlaw
RUN  curl -L -O https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1_build/ghidra_11.1_PUBLIC_20240607.zip
RUN  unzip ghidra_11.1_PUBLIC_20240607.zip && \
    rm ghidra_11.1_PUBLIC_20240607.zip && \
    pip3 install pyhidra && \
    mkdir logs res db fidb ghidra_projects

ENV GHIDRA_INSTALL_DIR /home/otacap-complete/FirmFlaw/ghidra_11.1_PUBLIC

# Setting up OTACap
WORKDIR /home/otacap-complete/otacap/VSA
RUN  ./gradlew build -Dorg.gradle.java.home=/usr/lib/jvm/java-11-openjdk-amd64/
RUN  mv /home/otacap-complete/otacap/VSA/build/dependencies/libz3java.so /usr/lib/x86_64-linux-gnu/jni/
RUN  mv /home/otacap-complete/otacap/VSA/build/dependencies/libz3.so /usr/lib/x86_64-linux-gnu/jni/
RUN  mv /home/otacap-complete/otacap/VSA/build/dependencies/javasmt-solver-z3-4.12.4-com.microsoft.z3.jar /usr/lib/x86_64-linux-gnu/jni/

# Setting up binwalk
WORKDIR /home/otacap-complete/binwalk/ 
RUN  pip3 install -r requirements.txt
RUN  python3 setup.py install

# Setting up FirmXRay
WORKDIR /home/otacap-complete/FirmXRay/ 
RUN  make

WORKDIR /home/otacap-complete/
