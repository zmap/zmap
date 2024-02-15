FROM gentoo/stage3:latest

RUN emaint -a sync
#RUN emerge --sync
RUN emerge sys-devel/binutils dev-libs/gmp dev-util/gengetopt net-libs/libpcap sys-devel/flex dev-util/byacc dev-libs/json-c \
      dev-util/pkgconf dev-libs/libunistring dev-libs/judy

WORKDIR /zmap

COPY . .

RUN cmake -DENABLE_DEVELOPMENT=$ENABLE_DEVELOPMENT -DENABLE_LOG_TRACE=$ENABLE_LOG_TRACE . \
    && make
RUN python3 ./scripts/check_manfile.py