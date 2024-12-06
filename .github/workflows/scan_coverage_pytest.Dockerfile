FROM arm64v8/ubuntu:latest

RUN apt-get update
RUN apt-get install -y build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config \
    libunistring-dev libjudy-dev cmake  make python3 python3-pytest python3-timeout-decorator python3-bitarray curl
RUN apt-get clean



WORKDIR /zmap
COPY . .
RUN rm -f CMakeCache.txt # if building locally, this file can be present and cause build failure
RUN cmake -DENABLE_DEVELOPMENT=$ENABLE_DEVELOPMENT -DENABLE_LOG_TRACE=$ENABLE_LOG_TRACE -DWITH_AES_HW=$WITH_AES_HW . \
    && make -j4

WORKDIR /zmap/test/integration-tests
# need to get the gateway mac
RUN curl zmap.io \
    # launch the test
    && python3 test_full_ipv4_multi_port_scan.py
