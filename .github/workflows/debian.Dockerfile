FROM debian:latest

RUN apt-get update \
    && apt-get install -y build-essential cmake libgmp3-dev gengetopt libpcap-dev flex \
    byacc libjson-c-dev pkg-config libunistring-dev libjudy-dev cmake  make python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /zmap

COPY . .

RUN cmake -DENABLE_DEVELOPMENT=$ENABLE_DEVELOPMENT -DENABLE_LOG_TRACE=$ENABLE_LOG_TRACE . \
    && make
RUN python3 ./scripts/check_manfile.py