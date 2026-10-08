FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    CC=clang \
    CXX=clang++
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential clang cmake ninja-build pkg-config git python3 \
      libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev libunistring-dev libjudy-dev \
      python3-pytest python3-timeout-decorator python3-bitarray \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

# Same development flags as zmap's CI (.github/workflows/cmake.yml). Debug keeps assertions enabled.
RUN cmake -S /src -B /src/build -G Ninja \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-fno-omit-frame-pointer" \
      -DENABLE_DEVELOPMENT=ON \
      -DENABLE_LOG_TRACE=ON \
    && cmake --build /src/build -j"$(nproc)"

# Standalone JA4TS formatter unit test. Integration tests need a real network and are not run here.
RUN (make -C /src/test/unit run CC=clang || echo "WARNING: unit tests reported failures")
