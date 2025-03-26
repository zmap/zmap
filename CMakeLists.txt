cmake_minimum_required(VERSION 3.5.0 FATAL_ERROR)
project(ZMAP C)
set(ZMAP_VERSION DEVELOPMENT) # Change DEVELOPMENT to version number for release

option(ENABLE_DEVELOPMENT "Enable development specific compiler and linker flags" OFF)
option(ENABLE_LOG_TRACE "Enable log trace messages" OFF)
option(RESPECT_INSTALL_PREFIX_CONFIG "Respect CMAKE_INSTALL_PREFIX for /etc" OFF)
option(WITH_WERROR "Build with -Werror" OFF)
option(WITH_PFRING "Build with PF_RING ZC for send (10 GigE)" OFF)
option(WITH_NETMAP "Build with netmap(4) for send/recv (10+ GigE)" OFF)
option(WITH_AES_HW "Build with AES hardware acceleration (x86_64 and arm64)" OFF)
option(FORCE_CONF_INSTALL "Overwrites existing configuration files at install" OFF)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(USING_CLANG "YES")
else()
    set(USING_GCC "YES")
endif()

if("${CMAKE_SYSTEM_NAME}" MATCHES "FreeBSD" OR "${CMAKE_SYSTEM_NAME}" MATCHES "NetBSD" OR "${CMAKE_SYSTEM_NAME}" MATCHES "DragonFly" OR "${CMAKE_SYSTEM_NAME}" MATCHES "MidnightBSD")
    set(BSD "YES")
endif()

if("${CMAKE_SYSTEM_NAME}" MATCHES "NetBSD")
    set(NetBSD "YES")
endif()

# Hardening and warnings for building with gcc
# Maybe add -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
set(GCCWARNINGS
    "-Wall -Wformat=2 -Wno-format-nonliteral"
    "-pedantic -fno-strict-aliasing"
    "-Wextra"
    "-Wfloat-equal -Wundef -Wwrite-strings -Wredundant-decls"
    "-Wnested-externs -Wbad-function-cast -Winit-self"
    "-Wmissing-noreturn"
    "-Wstack-protector"
)

# Fix line breaks
string(REPLACE ";" " "  GCCWARNINGS "${GCCWARNINGS}")

if(WITH_WERROR)
    set(GCCWARNINGS "${GCCWARNINGS} -Werror")
endif()

# Check for dependencies
find_library(FOUND_JUDY HINTS /usr/include/ NAMES Judy libjudy-dev judy dev-libs/judy judy-devel)
if (NOT FOUND_JUDY)
    message(FATAL_ERROR "Missing dependency: did not find Judy library, please install Judy or equivalent. More details in INSTALL.md")
endif()

find_library(FOUND_GMP HINTS /usr/include/ NAMES libgmp3-dev gmp dev-libs/gmp gmp-devel)
if (NOT FOUND_GMP)
    message(FATAL_ERROR "Missing dependency: did not find gmp library, please install gmp or equivalent. More details in INSTALL.md")
endif()

find_library(FOUND_PCAP HINTS /usr/include/ NAMES pcap libpcap-dev libpcap net-libs/libpcap libpcap-devel)
if (NOT FOUND_PCAP)
    message(FATAL_ERROR "Missing dependency: did not find libpcap library, please install libpcap or equivalent. More details in INSTALL.md")
endif()

find_program(FOUND_FLEX HINTS /usr/include/ /usr/bin/ NAMES flex sys-devel/flex)
if (NOT FOUND_FLEX)
    message(FATAL_ERROR "Missing dependency: did not find flex, please install flex or equivalent. More details in INSTALL.md")
endif()
find_program(FOUND_BYACC HINTS /usr/include/ NAMES byacc dev-util/byacc)
if (NOT FOUND_BYACC)
    message(FATAL_ERROR "Missing dependency: did not find byacc, please install byacc or equivalent. More details in INSTALL.md")
endif()
find_library(FOUND_JSON HINTS /usr/include/ NAMES json libjson-c-dev json-c-devel json-c dev-libs/json-c)
if (NOT FOUND_JSON)
    message(FATAL_ERROR "Missing dependency: did not find libjson-c, please install libjson-c or equivalent. More details in INSTALL.md")
endif()
find_program(FOUND_GENGETOPT HINTS /usr/include/ NAMES gengetopt dev-util/gengetopt)
if (NOT FOUND_GENGETOPT)
    message(FATAL_ERROR "Missing dependency: did not find gengetopt, please install gengetopt or equivalent. More details in INSTALL.md")
endif()

find_path(FOUND_LIBUNISTRING # UniString is neither a library or a program, but install several header files in the include path
        NAMES unistr.h
        PATH_SUFFIXES include
)
if (NOT FOUND_LIBUNISTRING)
    message(FATAL_ERROR "Missing dependency: did not find libunistring, please install libunistring or equivalent. More details in INSTALL.md")
endif()

find_program(FOUND_PKGCONFIG HINTS /usr/include/ NAMES pkg-config dev-util/pkgconf)
if (NOT FOUND_PKGCONFIG)
    message(FATAL_ERROR "Missing dependency: did not find pkg-config, please install pkg-config or equivalent. More details in INSTALL.md")
endif()


if(ENABLE_DEVELOPMENT)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -g")
else()
    # Hardening and optimizations for building with gcc
    set(GCCHARDENING "-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIC --param ssp-buffer-size=1")
    if(NOT APPLE AND NOT BSD)
        set(LDHARDENING "-z relro -z now")
    else()
        set(LDHARDENING "")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCCHARDENING} -O2")
    set(CMAKE_EXE_LINKER_FLAGS "${LDHARDENING} ${CMAKE_EXE_LINKER_FLAGS}")
endif()

if(ENABLE_LOG_TRACE)
    add_definitions("-DDEBUG")
endif()


set(CMAKE_C_FLAGS "${GCCWARNINGS} ${CMAKE_C_FLAGS}")


include(FindPkgConfig)
pkg_check_modules(JSON json-c)
if(JSON_FOUND)
    include_directories(${JSON_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "Did not find libjson")
endif()
string(REPLACE ";" " " JSON_CFLAGS "${JSON_CFLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${JSON_CFLAGS}")

if(WITH_PFRING)
    add_definitions("-DPFRING")
    set(PFRING_LIBRARIES pfring rt numa)
endif()

if(WITH_NETMAP)
    add_definitions("-DNETMAP")
endif()

if(WITH_AES_HW)
    add_definitions("-DAES_HW")
endif()

set(JUDY_LIBRARIES "Judy")

# Standard FLAGS
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")
if(NOT APPLE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")
endif()

# Set up OS-specific include directories
if(APPLE)
    if(EXISTS /opt/local/include)
        include_directories(/opt/local/include)
    endif()
    if(EXISTS /opt/local/lib)
        link_directories(/opt/local/lib)
    endif()
    if(EXISTS /usr/local/include)
        include_directories(/usr/local/include)
    endif()
    if(EXISTS /usr/local/lib)
        link_directories(/usr/local/lib)
    endif()
    if(EXISTS /opt/homebrew)
        include_directories(/opt/homebrew/include)
        link_directories(/opt/homebrew/lib)
    endif()
endif()

if(BSD)
    include_directories(/usr/local/include)
    link_directories(/usr/local/lib)
endif()

if(NetBSD)
    include_directories(/usr/pkg/include)
    link_directories(/usr/pkg/lib)
endif()

add_subdirectory(lib)
add_subdirectory(src)

# Install conf files
if(RESPECT_INSTALL_PREFIX_CONFIG)
    set(CONFIG_DESTINATION "etc/zmap")
else()
    set(CONFIG_DESTINATION "/etc/zmap")
endif()

FILE(GLOB CONF_FILES "${PROJECT_SOURCE_DIR}/conf/*")

# Upgrade path for old conf files - this is necessary for users upgrading from a version where we called the blocklist file blacklist.conf
# Must occur before the install command
if(EXISTS "${CONFIG_DESTINATION}/blacklist.conf")
    message(STATUS "Old configuration file detected at ${CONFIG_DESTINATION}/blacklist.conf, creating a symlink to ${CONFIG_DESTINATION}/blocklist.conf to match the new flag conventions")
    execute_process(
            COMMAND ${CMAKE_COMMAND} -E create_symlink "${CONFIG_DESTINATION}/blacklist.conf" "${CONFIG_DESTINATION}/blocklist.conf"
    )
    message(STATUS "blocklist.conf has been successfully symlinked to blacklist.conf.")
endif()

# If the zmap.conf file exists and contains the old blacklist-file option, replace it with the new blocklist-file option
if(EXISTS "${CONFIG_DESTINATION}/zmap.conf")
    file(READ "${CONFIG_DESTINATION}/zmap.conf" FILE_CONTENTS)

    if(FILE_CONTENTS MATCHES "blacklist-file \"${CONFIG_DESTINATION}/blacklist.conf\"")
        string(REPLACE "blacklist-file \"${CONFIG_DESTINATION}/blacklist.conf\""
                "blocklist-file \"${CONFIG_DESTINATION}/blocklist.conf\""
                FILE_CONTENTS
                "${FILE_CONTENTS}")
        file(WRITE "${CONFIG_DESTINATION}/zmap.conf" "${FILE_CONTENTS}")

        message(STATUS "Blacklist to blocklist file path successfully updated in ${CONFIG_DESTINATION}/zmap.conf.")
    else()
        message(STATUS "blacklist-file option does not exist in ${CONFIG_DESTINATION}/zmap.conf. No changes necessary to upgrade ZMap configuration file.")
    endif()
else()
    message(STATUS "No ZMap configuration file detected at ${CONFIG_DESTINATION}/zmap.conf. No changes necessary to upgrade ZMap configuration file.")
endif()

message(STATUS "Default ZMap configuration file location is /etc/zmap")
foreach(EACH_CONF ${CONF_FILES})
    get_filename_component(CONF_BASENAME ${EACH_CONF} NAME)
    message(STATUS "Checking if ${CONF_BASENAME} exists there...")
    if(NOT EXISTS "${CONFIG_DESTINATION}/${CONF_BASENAME}")
        install(FILES ${EACH_CONF} DESTINATION ${CONFIG_DESTINATION})
    elseif(FORCE_CONF_INSTALL)
        message(WARNING "FORCE_CONF_INSTALL will overwrite any existing configuration files")
        install(FILES ${EACH_CONF} DESTINATION ${CONFIG_DESTINATION})
    else()
        message(WARNING "Existing configuration file detected at /etc/zmap/${CONF_BASENAME}, ${CONF_BASENAME} from sources will NOT be installed. Please check and install manually!")
    endif()
endforeach()

# Allow Debian Packaging
include(InstallRequiredSystemLibraries)

set(CPACK_SET_DESTDIR "on")
set(CPACK_PACKAGING_INSTALL_PREFIX "/tmp")
set(CPACK_GENERATOR "DEB")

set(CPACK_DEBIAN_PACKAGE_VERSION ${ZMAP_VERSION})
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_SECTION "network")
set(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.1.3), libgmp10, libpcap0.8, libjson-c-dev")

set(CPACK_PACKAGE_DESCRIPTION "Internet-scale network scanner")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ZMap is an open source network scanner that enables researchers to easily perform Internet-wide network studies. With a single machine and a well provisioned network uplink, ZMap is capable of performing a complete scan of the IPv4 address space in under five minutes, approaching the theoretical limit of gigabit Ethernet. ZMap can be used to study protocol adoption over time, monitor service availability, and help us better understand large systems distributed across the Internet.")
set(CPACK_PACKAGE_CONTACT "Zakir Durumeric <zakird@gmail.com>")
set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${VERSION}_${CPACK_DEBIAN_ARCHITECTURE}")

set(CPACK_COMPONENTS_ALL Libraries ApplicationData)

include(CPack)
