FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y --quiet
RUN apt-get install -y -qq \
    build-essential \
    byacc \
    cmake \
    flex \
    gengetopt \
    libgmp3-dev \
    libjson-c-dev \
    libpcap-dev \
    libunistring-dev \
    pkg-config \
    python3
