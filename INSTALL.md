# SYSTEM REQUIREMENTS

ZMap is designed to run on GNU/Linux systems and can be built with most recent versions of gcc. Currently, running it requires at least 600MB of free memory.

#### INSTALLING PREBUILT PACKAGE FROM PACKAGE MANAGER

If you want to install zmap on Fedora 19+ or EPEL 6+, just type:
  ```sh
  yum install zmap
  ```

If you want to install zmap on Debian 8+, just type:
  ```sh
  sudo apt-get install zmap
  ```

If you want to install zmap on Archlinux, just type:
  ```sh
  pacman -S zmap
  ```

#### BUILDING FROM SOURCE

You can also build ZMap from sources, following fundamentals required:

  - [CMake](http://www.cmake.org/) - Cross-platform, open-source build system
  - [GMP](http://gmplib.org/) - Free library for arbitrary precision arithmetic
  - [gengetopt](http://www.gnu.org/software/gengetopt/gengetopt.html) - Command line option parsing for C programs
  - [libpcap](http://www.tcpdump.org/) - Famous user-level packet capture library
  - [flex](http://flex.sourceforge.net/) and [byacc](http://invisible-island.net/byacc/) - Output filter lexer and parser generator.
  - [json-c](https://github.com/json-c/json-c/) - JSON implementation in C
  - [libunistring](https://www.gnu.org/software/libunistring/) - Unicode string library for C

In addition, you can get following packages to get further functionalities:
  - [hiredis](https://github.com/redis/hiredis) - RedisDB support in C
  - [mongo-c-driver](https://github.com/mongodb/mongo-c-driver/) - MongoDB support in C

---
*On Mac, ZMap uses [libdnet](https://github.com/dugsong/libdnet) for gateway and route detection.*

---
**You can compile fundamental dependencies on your own, but using package manager is strongly recommended:**

* On Debian-based systems by running:
   ```sh
   sudo apt-get install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev
   ```

* On RHEL- and Fedora-based systems by running:
   ```sh
   sudo yum install cmake gmp-devel gengetopt libpcap-devel flex byacc json-c-devel libunistring-devel
   ```

* On Mac OS systems [Homebrew](http://brew.sh/):
  ```sh
  brew install pkg-config cmake gmp gengetopt json-c byacc libdnet libunistring
  ```

Once these prerequisites have been installed, ZMap can be compiled
by running:
  ```sh
  cmake .
  make -j4
  ```

and installed by running:
  ```sh
  sudo make install
  ```

# Miscellaneous notes:
- **Enabling development turns on debug symbols, and turns off optimizations.
Release builds should be built with `-DENABLE_DEVELOPMENT=OFF`.**

- **Enabling log_trace can have a major performance impact and should not be used
except during early development. Release builds shoudl be built with `-DENABLE_LOG_TRACE=OFF`.**

- Redis support is not enabled by default. If you want to use ZMap with Redis, you will first need to install hiredis. Then run cmake with `-DWITH_REDIS=ON`. Debian has packaged it as `libhiredis-dev`, Fedora and RHEL have packaged it as `hiredis-devel`.

- MongoDB support is not enabled by default. If you want to use ZMap with MongoDB, you will first need to install mongo-c-driver. Then run cmake with `-DWITH_MONGO=ON`.

- Building packages for some systems like Fedora and RHEL requires a user-definable directory(buildroot) to put files, the conducive way to respect prefix is to run cmake with `-DRESPECT_INSTALL_PREFIX_CONFIG=ON`.

