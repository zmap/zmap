FROM ubuntu:16.04
# Set non-interactive mode so that apt-get does not prompt for input
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y build-essential cmake libgmp3-dev gengetopt libpcap-dev flex \
    byacc libjson-c-dev pkg-config libunistring-dev libjudy-dev cmake  make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /zmap
COPY . .

RUN cmake -DENABLE_DEVELOPMENT=$ENABLE_DEVELOPMENT -DENABLE_LOG_TRACE=$ENABLE_LOG_TRACE . \
    && make