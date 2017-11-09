FROM ubuntu:16.04

RUN apt-get update && apt-get -y upgrade
# install zmap build dependencies
RUN apt-get -qqy install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev wget unzip
# install zmap+Docker specific things
RUN apt-get -qqy install python-dev python-pip
RUN pip install dumb-init
RUN wget -q https://github.com/zmap/zmap/archive/abc41b78ef97f90d951b7cb87329491a610ea7e8.zip && unzip -q abc41b78ef97f90d951b7cb87329491a610ea7e8.zip && cd zmap-abc41b78ef97f90d951b7cb87329491a610ea7e8 && (cmake . && make -j4 && make install) 2>&1

ENTRYPOINT ["dumb-init", "/usr/local/sbin/zmap"]
