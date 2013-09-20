cmake_minimum_required (VERSION 2.6)
project (ZMAP C)

option(WITH_REDIS "Build with support for Redis DB" OFF)
option(WITH_JSON "Build with support for JSON" OFF)
option(ENABLE_DEVELOPMENT "Enable development specific compiler and linker flags" OFF)
option(ENABLE_HARDENING "Add hardening specific compiler and linker flags" OFF)

if(ENABLE_DEVELOPMENT)
	# Hardening and warnings for building with gcc
	# Maybe add -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
	set(GCCWARNINGS 
		"-Wall -Wformat=2 -Wno-format-nonliteral"
		"-pedantic -fno-strict-aliasing"
		"-Wextra"
		"-Wfloat-equal -Wundef -Wwrite-strings -Wredundant-decls"
		"-Wnested-externs -Wbad-function-cast -Winit-self"
		"-Wmissing-noreturn -Wnormalized=id"
		"-Wstack-protector"
		"-Werror"
		)

	# Fix line breaks
	string(REPLACE ";" " "  GCCWARNINGS "${GCCWARNINGS}")

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCCWARNINGS} -g")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -g")
endif()

if(ENABLE_HARDENING)
	set(GCCHARDENING "-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIC --param ssp-buffer-size=1")
	set(LDHARDENING "-z relro -z now")

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCCHARDENING}")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LDHARDENING}")
endif()

if(WITH_REDIS)
	set(REDIS_LIBS hiredis)
	add_definitions("-DREDIS")
endif()

if(WITH_JSON)
	include(FindPkgConfig)
	pkg_check_modules(JSON json-c)
	if(NOT JSON_FOUND)
		set(JSON_CFLAGS "")
		set(JSON_LIBS "-ljson-c")
		include_directories("/usr/local/include/json-c/")
	endif()

	add_definitions("-DJSON")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${JSON_CFLAGS}")
endif()

# Standard FLAGS
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

# Extra target FLAGS
set(CMAKE_C_FLAGS_DEBUG "-O2 -g")
set(CMAKE_C_FLAGS_RELEASE "-O2")

add_subdirectory(src)

# Install conf files
FILE(GLOB CONF_FILES "conf/*")
install(
	FILES
	${CONF_FILES}
	DESTINATION "/etc/zmap/"
	)
