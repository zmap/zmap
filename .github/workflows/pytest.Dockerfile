FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y build-essential cmake libgmp3-dev gengetopt libpcap-dev flex \
    byacc libjson-c-dev pkg-config libunistring-dev libjudy-dev cmake  make python3 python3-pytest python3-timeout-decorator curl
RUN apt-get clean


WORKDIR /zmap
COPY . .

RUN cmake -DENABLE_DEVELOPMENT=$ENABLE_DEVELOPMENT -DENABLE_LOG_TRACE=$ENABLE_LOG_TRACE . \
    && make

WORKDIR /zmap/test/integration-tests
# need to get the gateway mac
RUN curl zmap.io \
    && pytest -vv --durations=0

