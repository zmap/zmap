FROM fedora:latest

RUN dnf update -y \
    && dnf install -y gcc cmake gmp-devel gengetopt libpcap-devel flex byacc json-c-devel libunistring-devel Judy-devel python3 \
    && dnf clean all

WORKDIR /zmap

COPY . .

RUN cmake -DENABLE_DEVELOPMENT=$ENABLE_DEVELOPMENT -DENABLE_LOG_TRACE=$ENABLE_LOG_TRACE . \
    && make
RUN python3 ./scripts/check_manfile.py