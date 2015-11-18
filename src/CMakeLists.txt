include_directories(
    "${CMAKE_CURRENT_BINARY_DIR}"
    ${PROJECT_SOURCE_DIR}/lib
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/output_modules
    ${PROJECT_SOURCE_DIR}/src/tests
)

# ADD YOUR PROBE MODULE HERE
set(EXTRA_PROBE_MODULES
)

# ADD YOUR OUTPUT MODULE HERE
set(EXTRA_OUTPUT_MODULES
)

set(OUTPUT_MODULE_SOURCES
    output_modules/module_csv.c
    output_modules/output_modules.c
)

# Handle optional output modules
if(WITH_JSON)
    set(OUTPUT_MODULE_SOURCES ${OUTPUT_MODULE_SOURCES} output_modules/module_json.c)
endif()

if(WITH_REDIS)
    set(OUTPUT_MODULE_SOURCES ${OUTPUT_MODULE_SOURCES} output_modules/module_redis_packed.c output_modules/module_redis_csv.c)
endif()

if(WITH_MONGO)
    set(OUTPUT_MODULE_SOURCES ${OUTPUT_MODULE_SOURCES} output_modules/module_mongodb.c)
endif()

set(PROBE_MODULE_SOURCES
    probe_modules/module_icmp_echo.c
    probe_modules/module_icmp_echo_time.c
    probe_modules/module_tcp_synscan.c
    probe_modules/module_tcp_cisco_backdoor.c
    probe_modules/module_udp.c
    probe_modules/packet.c
    probe_modules/probe_modules.c
    probe_modules/module_ntp.c
    probe_modules/module_upnp.c
    probe_modules/module_dns.c
    probe_modules/module_bacnet.c
)

set(SOURCES
    aesrand.c
    cyclic.c
    expression.c
    fieldset.c
    filter.c
    get_gateway.c
    iterator.c
    monitor.c
    recv.c
    send.c
    shard.c
    socket.c
    state.c
    summary.c
    validate.c
    zmap.c
    zopt_compat.c
    "${CMAKE_CURRENT_BINARY_DIR}/zopt.h"
    "${CMAKE_CURRENT_BINARY_DIR}/lexer.c"
    "${CMAKE_CURRENT_BINARY_DIR}/parser.c"
    ${EXTRA_PROBE_MODULES}
    ${EXTRA_OUTPUT_MODULES}
    ${PROBE_MODULE_SOURCES}
    ${OUTPUT_MODULE_SOURCES}
)

set(ZTESTSOURCES
    aesrand.c
    cyclic.c
    expression.c
    fieldset.c
    filter.c
    get_gateway.c
    iterator.c
    monitor.c
    recv.c
    send.c
    shard.c
    socket.c
    state.c
    summary.c
    validate.c
    zopt_compat.c
    ${PROBE_MODULE_SOURCES}
    ${OUTPUT_MODULE_SOURCES}
    tests/test_harness.c
    "${CMAKE_CURRENT_BINARY_DIR}/zopt.h"
    "${CMAKE_CURRENT_BINARY_DIR}/lexer.c"
    "${CMAKE_CURRENT_BINARY_DIR}/parser.c"
    ${EXTRA_PROBE_MODULES}
    ${EXTRA_OUTPUT_MODULES}
)

set(ZBLSOURCES
    zblacklist.c
    zbopt_compat.c
    "${CMAKE_CURRENT_BINARY_DIR}/zbopt.h"
)

set(ZTEESOURCES
    ztee.c
    topt_compat.c
    "${CMAKE_CURRENT_BINARY_DIR}/topt.h"
)

# Handle various versions of socket
if(WITH_PFRING)
    set(SOURCES ${SOURCES} socket-pfring.c)
    set(ZTESTSOURCES ${ZTESTSOURCES} socket-pfring.c)
elseif (APPLE OR BSD)
    set(SOURCES ${SOURCES} socket-bsd.c)
    set(ZTESTSOURCES ${ZTESTSOURCES} socket-bsd.c)
else()
    set(SOURCES ${SOURCES} socket-linux.c)
    set(ZTESTSOURCES ${ZTESTSOURCES} socket-linux.c)
endif()

# Handle various versions of recv
if(WITH_PFRING)
    set(SOURCES ${SOURCES} recv-pfring.c)
    set(ZTESTSOURCES ${ZTESTSOURCES} recv-pfring.c)
else()
    set(SOURCES ${SOURCES} recv-pcap.c)
    set(ZTESTSOURCES ${ZTESTSOURCES} recv-pcap.c)
endif()

configure_file(topt.ggo.in ${CMAKE_BINARY_DIR}/src/topt.ggo @ONLY)
configure_file(zbopt.ggo.in ${CMAKE_BINARY_DIR}/src/zbopt.ggo @ONLY)
configure_file(zopt.ggo.in ${CMAKE_BINARY_DIR}/src/zopt.ggo @ONLY)

add_custom_command(OUTPUT zopt.h
    COMMAND gengetopt -C --no-help --no-version --unamed-opts=SUBNETS -i "${CMAKE_CURRENT_SOURCE_DIR}/zopt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/zopt"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/zopt.ggo"
)

add_custom_command(OUTPUT topt.h
    COMMAND gengetopt -S --no-help --no-version --unamed-opts=FILE -i "${CMAKE_CURRENT_SOURCE_DIR}/topt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/topt"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/topt.ggo"
)

add_custom_command(OUTPUT zbopt.h
    COMMAND gengetopt -C --no-help --no-version -i "${CMAKE_CURRENT_SOURCE_DIR}/zbopt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/zbopt"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/zbopt.ggo"
)

add_custom_command(OUTPUT lexer.c
    COMMAND flex -o "${CMAKE_CURRENT_BINARY_DIR}/lexer.c" --header-file="${CMAKE_CURRENT_BINARY_DIR}/lexer.h" "${CMAKE_CURRENT_SOURCE_DIR}/lexer.l"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/lexer.l"
)

add_custom_command(OUTPUT parser.c
    COMMAND byacc -d -o "${CMAKE_CURRENT_BINARY_DIR}/parser.c" "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
)

add_executable(zmap ${SOURCES})
add_executable(zblacklist ${ZBLSOURCES})
add_executable(ztee ${ZTEESOURCES})
add_executable(ztests ${ZTESTSOURCES})

if(APPLE OR BSD)
    set(DNET_LIBRARIES "dnet")
else()
    set(DNET_LIBRARIES "")
endif()

target_link_libraries(
    zmap
    zmaplib
    ${PFRING_LIBRARIES}
    pcap gmp m unistring
    ${DNET_LIBRARIES}
    ${REDIS_LIBS}
    ${JSON_LIBRARIES}
    ${MONGO_LIBRARIES}
)

target_link_libraries(
    zblacklist
    zmaplib
    m
)

target_link_libraries(
    ztee
    zmaplib
    m
)

target_link_libraries(
    ztests
    zmaplib
    ${PFRING_LIBRARIES}
    pcap gmp m unistring
    ${DNET_LIBRARIES}
    ${REDIS_LIBS}
    ${JSON_LIBRARIES}
    ${MONGO_LIBRARIES}
)

# Install binary
install(
    TARGETS
    zmap
    zblacklist
    ztee
    RUNTIME DESTINATION sbin
)

# Install Manpages
install(
    FILES
    zmap.1
    zblacklist.1
    ztee.1
    DESTINATION share/man/man1
)
