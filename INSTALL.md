# Installing and Building ZMap

## Installing via Package Manager

ZMap operates on GNU/Linux, macOS, and BSD. The latest stable version (v2.1.1)
can be installed using most OS package managers:

| OS                                        |                         |
| ----------------------------------------- | ----------------------- |
| Fedora 19+ or EPEL 6+                     | `sudo yum install zmap` |
| Debian 8+ or Ubuntu 14.04+                | `sudo apt install zmap` |
| Gentoo                                    | `sudo emerge zmap`      |
| macOS (using [Homebrew](https://brew.sh)) | `brew install zmap`     |
| Arch Linux                                | `sudo pacman -S zmap`   |

## Building from Source

### Installing ZMap Dependencies

ZMap has the following dependencies:

  - [CMake](http://www.cmake.org/) - Cross-platform, open-source build system
  - [GMP](http://gmplib.org/) - Free library for arbitrary precision arithmetic
  - [gengetopt](http://www.gnu.org/software/gengetopt/gengetopt.html) - Command line option parsing for C programs
  - [libpcap](http://www.tcpdump.org/) - Famous user-level packet capture library
  - [flex](http://flex.sourceforge.net/) and [byacc](http://invisible-island.net/byacc/) - Output filter lexer and parser generator
  - [json-c](https://github.com/json-c/json-c/) - JSON implementation in C
  - [libunistring](https://www.gnu.org/software/libunistring/) - Unicode string library for C
  - [libdnet](https://github.com/dugsong/libdnet) - (macOS Only) Gateway and route detection

In addition, the following optional packages enable optional ZMap functionality:

  - [hiredis](https://github.com/redis/hiredis) - RedisDB support in C

Install the required dependencies with the following commands.

* On Debian-based systems (including Ubuntu):
   ```sh
   sudo apt-get install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev
   ```

* On RHEL- and Fedora-based systems (including CentOS):
   ```sh
   sudo yum install cmake gmp-devel gengetopt libpcap-devel flex byacc json-c-devel libunistring-devel
   ```

* On macOS systems (using [Homebrew](http://brew.sh/)):
  ```sh
  brew install pkg-config cmake gmp gengetopt json-c byacc libdnet libunistring
  ```

### Building and Installing ZMap

Once these prerequisites are installed, ZMap can be compiled by running:
  ```sh
  cmake .
  make -j4
  ```

and then installed via `sudo make install`.

### Development Notes

- Enabling development turns on debug symbols, and turns off optimizations.
Release builds should be built with `-DENABLE_DEVELOPMENT=OFF`.

- Enabling `log_trace` can have a major performance impact and should not be used
except during early development. Release builds should be built with `-DENABLE_LOG_TRACE=OFF`.

- Redis support is not enabled by default. If you want to use ZMap with Redis,
you will first need to install hiredis. Then run cmake with `-DWITH_REDIS=ON`.
Debian/Ubuntu has packaged hiredis as `libhiredis-dev`; Fedora and RHEL/CentOS
have packaged it as `hiredis-devel`.

- Building packages for some systems like Fedora and RHEL requires a user-definable
directory (buildroot) to put files. The way to respect this prefix is to run cmake
with `-DRESPECT_INSTALL_PREFIX_CONFIG=ON`.

- Manpages (and their HTML representations) are generated from the `.ronn` source
files in the repository, using the [ronn](https://github.com/rtomayko/ronn) tool.
This does not happen automatically as part of the build process; to regenerate the
man pages you'll need to run `make manpages`. This target assumes that `ronn` is
in your PATH.

- Building with some versions of CMake may fail with `unable to find parser.h`.
If this happens, try updating CMake. If it still fails, don't clone ZMap into a
path that contains the string `.com`, and try again.

- ZMap may be installed to an alternative directory, with the `CMAKE_INSTALL_PREFIX`
option. For example, to install it in `$HOME/opt` run
    ```sh
    cmake -DCMAKE_INSTALL_PREFIX=$HOME/opt .
    make -j4
    make install
    ```
