include_directories(
	"${CMAKE_CURRENT_BINARY_DIR}"
	${PROJECT_SOURCE_DIR}/lib
	${PROJECT_SOURCE_DIR}/src
	${PROJECT_SOURCE_DIR}/src/output_modules
	)

SET(LIB_SOURCES
	${PROJECT_SOURCE_DIR}/lib/blacklist.c
	${PROJECT_SOURCE_DIR}/lib/constraint.c
	${PROJECT_SOURCE_DIR}/lib/logger.c
	${PROJECT_SOURCE_DIR}/lib/pbm.c
	${PROJECT_SOURCE_DIR}/lib/random.c
	${PROJECT_SOURCE_DIR}/lib/rijndael-alg-fst.c
	${PROJECT_SOURCE_DIR}/lib/stack.c
	${PROJECT_SOURCE_DIR}/lib/xalloc.c
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

SET(PROBE_MODULE_SOURCES
	probe_modules/module_icmp_echo.c
	probe_modules/module_tcp_synscan.c
	probe_modules/module_udp.c
	probe_modules/packet.c
	probe_modules/probe_modules.c
	)

SET(SOURCES
	aesrand.c
	cyclic.c
	expression.c
	fieldset.c
	filter.c
	get_gateway.c
	monitor.c
	recv.c
	send.c
	state.c
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
	${LIB_SOURCES}
	)

if (WITH_JSON)
	SET(SOURCES ${SOURCES} output_modules/module_json.c)
endif()

if (WITH_REDIS)
	SET(SOURCES ${SOURCES} ${PROJECT_SOURCE_DIR}/lib/redis.c output_modules/module_redis.c output_modules/module_csvredis.c)
endif()

add_custom_command(OUTPUT zopt.h
	COMMAND gengetopt -C --no-help --no-version --unamed-opts=SUBNETS -i "${CMAKE_CURRENT_SOURCE_DIR}/zopt.ggo" -F "${CMAKE_CURRENT_BINARY_DIR}/zopt"
	)

add_custom_command(OUTPUT lexer.c
	COMMAND flex -o "${CMAKE_CURRENT_BINARY_DIR}/lexer.c" --header-file="${CMAKE_CURRENT_BINARY_DIR}/lexer.h" lexer.l
	)

add_custom_command(OUTPUT parser.c
	COMMAND byacc -d -o parser.c parser.y
	)

add_executable(zmap ${SOURCES})

target_link_libraries(
	zmap 
	pcap gmp m
	${REDIS_LIBS}
	${JSON_LIBRARIES}
	)

# Install binary
install(
	TARGETS
	zmap
	RUNTIME DESTINATION sbin
)

# Install Manpages
install(
	FILES
	zmap.1
	DESTINATION share/man/man1
	)
