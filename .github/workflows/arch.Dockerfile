FROM archlinux:latest

RUN pacman-key --init
RUN pacman -Syu --noconfirm
RUN pacman -S --noconfirm base-devel cmake gmp gengetopt libpcap flex byacc json-c pkg-config libunistring judy python
RUN pacman -Scc --noconfirm

WORKDIR /zmap

COPY . .

RUN ls
RUN cmake -DENABLE_DEVELOPMENT=$ENABLE_DEVELOPMENT -DENABLE_LOG_TRACE=$ENABLE_LOG_TRACE .
RUN make
RUN cd ..
RUN python ./scripts/check_manfile.py
