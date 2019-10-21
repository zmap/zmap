cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)
project(ZMAP C)
set(ZMAP_VERSION DEVELOPMENT) # Change DEVELOPMENT to version number for release

option(WITH_REDIS "Build with support for Redis DB" OFF)
option(WITH_MONGO "Build with support for MongoDB" OFF)
option(ENABLE_DEVELOPMENT "Enable development specific compiler and linker flags" OFF)
option(ENABLE_LOG_TRACE "Enable log trace messages" OFF)
option(RESPECT_INSTALL_PREFIX_CONFIG "Respect CMAKE_INSTALL_PREFIX for /etc" OFF)
option(WITH_WERROR "Build with -Werror" OFF)
option(WITH_PFRING "Build with PF_RING ZC for send (10 GigE)" OFF)
option(FORCE_CONF_INSTALL "Overwrites existing configuration files at install" OFF)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(USING_CLANG "YES")
else()
    set(USING_GCC "YES")
endif()

if("${CMAKE_SYSTEM_NAME}" MATCHES "FreeBSD" OR "${CMAKE_SYSTEM_NAME}" MATCHES "NetBSD" OR "${CMAKE_SYSTEM_NAME}" MATCHES "DragonFly")
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
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${JSON_CFLAGS}")

if(WITH_REDIS)
    set(REDIS_LIBS hiredis)
    add_definitions("-DREDIS")
endif()

if(WITH_MONGO)
    include(FindPkgConfig)
    pkg_check_modules(MONGO libmongoc-1.0)
    if(MONGO_FOUND)
        include_directories(${MONGO_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "Did not find libmongoc-1.0")
    endif()
    add_definitions("-DMONGODB")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MONGO_CFLAGS_OTHER}")
endif()

if(WITH_PFRING)
    add_definitions("-DPFRING")
    set(PFRING_LIBRARIES pfring rt numa)
endif()

# Standard FLAGS
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
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

message(STATUS "Default ZMap configuration file location is /etc/zmap")
foreach(EACH_CONF ${CONF_FILES})
    get_filename_component(CONF_BASENAME ${EACH_CONF} NAME)
    message(STATUS "Checking if ${CONF_BASENAME} exists there...")
    if(NOT EXISTS "/etc/zmap/${CONF_BASENAME}")
        install(FILES ${EACH_CONF} DESTINATION ${CONFIG_DESTINATION})
    elseif(FORCE_CONF_INSTALL)
        message(WARNING "FORCE_CONF_INSTALL will overwrite any exsiting configuration files")
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

set(${VERSION} CPACK_DEBIAN_PACKAGE_VERSION)
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
