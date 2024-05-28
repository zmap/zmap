FROM ubuntu:24.04
# Set non-interactive mode so that apt-get does not prompt for input
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y build-essential cmake libgmp3-dev gengetopt libpcap-dev flex \
    byacc libjson-c-dev pkg-config libunistring-dev  cmake  make
RUN apt-get install -y libjudy-dev
RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /zmap
COPY . .
RUN rm CMakeCache.txt

#RUN cmake -DENABLE_DEVELOPMENT=$ENABLE_DEVELOPMENT -DENABLE_LOG_TRACE=$ENABLE_LOG_TRACE . \
#    && make
