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
    output_modules/module_json.c
    output_modules/output_modules.c
)

set(PROBE_MODULE_SOURCES
    probe_modules/module_icmp_echo.c
    probe_modules/module_icmp_echo_time.c
    probe_modules/module_tcp_synscan.c
    probe_modules/module_tcp_synackscan.c
	#probe_modules/module_tcp_cisco_backdoor.c
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
    utility.c
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
    ztopt_compat.c
    ${PROBE_MODULE_SOURCES}
    ${OUTPUT_MODULE_SOURCES}
    tests/test_harness.c
    "${CMAKE_CURRENT_BINARY_DIR}/ztopt.h"
    "${CMAKE_CURRENT_BINARY_DIR}/lexer.c"
    "${CMAKE_CURRENT_BINARY_DIR}/parser.c"
    ${EXTRA_PROBE_MODULES}
    ${EXTRA_OUTPUT_MODULES}
)

set(ZBLSOURCES
    zblocklist.c
    zbopt_compat.c
    "${CMAKE_CURRENT_BINARY_DIR}/zbopt.h"
)

set(ZITSOURCES
    aesrand.c
    cyclic.c
    iterator.c
    shard.c
    state.c
    validate.c
    zitopt_compat.c
    ziterate.c
    "${CMAKE_CURRENT_BINARY_DIR}/zitopt.h"
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

# Set configure time zmap version
configure_file(topt.ggo.in ${CMAKE_BINARY_DIR}/src/topt.ggo @ONLY)
configure_file(zbopt.ggo.in ${CMAKE_BINARY_DIR}/src/zbopt.ggo @ONLY)
configure_file(zitopt.ggo.in ${CMAKE_BINARY_DIR}/src/zitopt.ggo @ONLY)
configure_file(zopt.ggo.in ${CMAKE_BINARY_DIR}/src/zopt.ggo @ONLY)
configure_file(ztopt.ggo.in ${CMAKE_BINARY_DIR}/src/ztopt.ggo @ONLY)
# Additional ggo.in's should be added here and CMakeVersion.txt

# This sets a *build* time dependency that checks git
if("${ZMAP_VERSION}" STREQUAL "DEVELOPMENT")
    add_custom_target(git_versioning ALL
        COMMAND ${CMAKE_COMMAND} -D ORIG_SRC_DIR:STRING="${CMAKE_SOURCE_DIR}" -P "${CMAKE_SOURCE_DIR}/src/CMakeVersion.txt"
        )
endif()

add_custom_command(OUTPUT zopt.h
    COMMAND gengetopt -C --no-help --no-version --unamed-opts=SUBNETS -i "${CMAKE_CURRENT_BINARY_DIR}/zopt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/zopt"
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/zopt.ggo"
)

add_custom_command(OUTPUT topt.h
    COMMAND gengetopt -S --no-help --no-version --unamed-opts=FILE -i "${CMAKE_CURRENT_BINARY_DIR}/topt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/topt"
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/topt.ggo"
)

add_custom_command(OUTPUT zbopt.h
    COMMAND gengetopt -C --no-help --no-version -i "${CMAKE_CURRENT_BINARY_DIR}/zbopt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/zbopt"
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/zbopt.ggo"
)

add_custom_command(OUTPUT zitopt.h
	COMMAND gengetopt -C --no-help --no-version --unamed-opts=SUBNETS -i "${CMAKE_CURRENT_BINARY_DIR}/zitopt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/zitopt"
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/zitopt.ggo"
)

add_custom_command(OUTPUT ztopt.h
	COMMAND gengetopt -C --no-help --no-version -i "${CMAKE_CURRENT_BINARY_DIR}/ztopt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/ztopt"
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/ztopt.ggo"
)

add_custom_command(OUTPUT lexer.c
    COMMAND flex -o "${CMAKE_CURRENT_BINARY_DIR}/lexer.c" --header-file="${CMAKE_CURRENT_BINARY_DIR}/lexer.h" "${CMAKE_CURRENT_SOURCE_DIR}/lexer.l"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/lexer.l"
)

if(NetBSD)
add_custom_command(OUTPUT parser.c
    COMMAND yacc -d -o "${CMAKE_CURRENT_BINARY_DIR}/parser.c" "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
)
else()
add_custom_command(OUTPUT parser.c
    COMMAND byacc -d -o "${CMAKE_CURRENT_BINARY_DIR}/parser.c" "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/parser.y"
)
endif()

add_custom_target(manpages ronn "${CMAKE_CURRENT_SOURCE_DIR}/zmap.1.ronn" --organization="ZMap" --manual="zmap"
    COMMAND ronn "${CMAKE_CURRENT_SOURCE_DIR}/zblocklist.1.ronn" --organization="ZMap" --manual="zblocklist"
    COMMAND ronn "${CMAKE_CURRENT_SOURCE_DIR}/ziterate.1.ronn" --organization="ZMap" --manual="ziterate"
    COMMAND ronn "${CMAKE_CURRENT_SOURCE_DIR}/ztee.1.ronn" --organization="ZMap" --manual="ztee"
    SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zblocklist.1.ronn" "${CMAKE_CURRENT_SOURCE_DIR}/ziterate.1.ronn" "${CMAKE_CURRENT_SOURCE_DIR}/zmap.1.ronn" "${CMAKE_CURRENT_SOURCE_DIR}/ztee.1.ronn"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

add_executable(zmap ${SOURCES})
add_executable(zblocklist ${ZBLSOURCES})
add_executable(ziterate ${ZITSOURCES})
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
    ${JSON_LIBRARIES}
)

target_link_libraries(
    zblocklist
    zmaplib
    m
)

target_link_libraries(
    ziterate
    zmaplib
    gmp
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
    ${JSON_LIBRARIES}
)

# Install binary
install(
    TARGETS
    zmap
    zblocklist
    ziterate
    ztee
    RUNTIME DESTINATION sbin
)

# Install Manpages
install(
    FILES
    zmap.1
    zblocklist.1
    ziterate.1
    ztee.1
    DESTINATION share/man/man1
)
