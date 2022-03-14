####
# A Docker container for running zmap
#
# To build, beware of caching and:
#
#   * If you wish to build current main
#
#        docker build -t zmap .
#
#   * If you wish to build a specific commit, git checkout to that specific commit before building
#
# To run CI pre-built images, use:
#
#     docker run -it --rm --net=host ghcr.io/zmap/zmap <zmap args>
####

FROM ubuntu:20.04 as builder

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update \
    && apt-get install -y \
    build-essential \
    cmake \
    libgmp3-dev \
    gengetopt \
    libpcap-dev \
    flex \
    byacc \
    libjson-c-dev \
    pkg-config \
    libunistring-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/src

COPY . .

RUN cd /usr/local/src \
    && mkdir -p /opt/zmap \
    && cmake . -DRESPECT_INSTALL_PREFIX_CONFIG=ON  \
    && cmake --build . --parallel "$(nproc)" \
    && cmake --install . --prefix "/opt/zmap" 

FROM ubuntu:20.04

LABEL org.opencontainers.image.source="https://github.com/zmap/zmap"

RUN apt-get update \
    && apt-get install -y \
    libpcap0.8 \
    libjson-c4 \
    libhiredis0.14 \
    libgmp10 \
    dumb-init \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/zmap /opt/zmap

ENV PATH="/opt/zmap/sbin:${PATH}"

# dumb-init allows us to more easily send signals to zmap,
# for example by allowing ctrl-c of a running container and zmap will stop.
ENTRYPOINT ["dumb-init", "/opt/zmap/sbin/zmap"]