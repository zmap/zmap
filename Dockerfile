####
# A Docker container for running zmap
#
# To build, beware of caching and:
#
#   * If you wish to build current master
#
#        docker build -t zmap_ubuntu -f Dockerfile .
#
#   * If you wish to build a specific commit, use the ZMAP_COMMIT build argument.
#
#        docker build -t zmap_ubuntu -f Dockerfile --build-arg ZMAP_COMMIT=<your commit> .
#
# To run:
#
#     docker run  -it --rm --net=host zmap_ubuntu <zmap args>
####

FROM ubuntu:16.04

ARG ZMAP_COMMIT=master
ENV ZMAP_COMMIT ${ZMAP_COMMIT}

RUN apt-get -qq update && apt-get -qqy upgrade
# install zmap build dependencies
RUN apt-get -qqy install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev wget unzip
# install zmap+Docker specific things, currently just dumb-init, which allows
# us to more easily send signals to zmap, for example by allowing ctrl-c of
# a running container and zmap will stop.
RUN apt-get -qqy install python-dev python-pip
RUN pip install dumb-init
RUN wget -q https://github.com/zmap/zmap/archive/${ZMAP_COMMIT}.zip && unzip -q ${ZMAP_COMMIT}.zip && cd zmap-${ZMAP_COMMIT} && (cmake . && make -j4 && make install) 2>&1 > /dev/null

ENTRYPOINT ["dumb-init", "/usr/local/sbin/zmap"]
