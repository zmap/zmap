include_directories(
    "${CMAKE_CURRENT_BINARY_DIR}"
    ${PROJECT_SOURCE_DIR}/lib
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/output_modules
)

# ADD YOUR PROBE MODULE HERE
SET(EXTRA_PROBE_MODULES
)

# ADD YOUR OUTPUT MODULE HERE
SET(EXTRA_OUTPUT_MODULES
)

SET(OUTPUT_MODULE_SOURCES
    output_modules/module_csv.c
    output_modules/output_modules.c
)

# Handle optional output modules
if (WITH_JSON)
    SET(OUTPUT_MODULE_SOURCES ${OUTPUT_MODULE_SOURCES} output_modules/module_json.c)
endif()

if (WITH_REDIS)
    SET(OUTPUT_MODULE_SOURCES ${OUTPUT_MODULE_SOURCES} output_modules/module_redis_packed.c output_modules/module_redis_csv.c)
endif()

if (WITH_MONGO)
    SET(OUTPUT_MODULE_SOURCES ${OUTPUT_MODULE_SOURCES} output_modules/module_mongodb.c)
endif()

SET(PROBE_MODULE_SOURCES
    probe_modules/module_icmp_echo.c
    probe_modules/module_icmp_echo_time.c
    probe_modules/module_tcp_synscan.c
    probe_modules/module_udp.c
    probe_modules/packet.c
    probe_modules/probe_modules.c
    probe_modules/module_ntp.c
    probe_modules/module_upnp.c
)

SET(SOURCES
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

SET(ZBLSOURCES
    zblacklist.c
    zbopt_compat.c
    "${CMAKE_CURRENT_BINARY_DIR}/zbopt.h"
)

SET(ZTEESOURCES
    ztee.c
    topt_compat.c
    "${CMAKE_CURRENT_BINARY_DIR}/topt.h"
)

# Handle various versions of socket
if(WITH_PFRING)
    SET(SOURCES ${SOURCES} socket-pfring.c)
elseif (APPLE OR BSD)
    SET(SOURCES ${SOURCES} socket-bsd.c)
else()
    SET(SOURCES ${SOURCES} socket-linux.c)
endif()

# Handle various versions of recv
if(WITH_PFRING)
    SET(SOURCES ${SOURCES} recv-pfring.c)
else()
    SET(SOURCES ${SOURCES} recv-pcap.c)
endif()

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

if (APPLE OR BSD)
    set(DNET_LIBRARIES "dnet")
else()
    set(DNET_LIBRARIES "")
endif()

target_link_libraries(
    zmap
    zmaplib
    ${PFRING_LIBRARIES}
    pcap gmp m
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
