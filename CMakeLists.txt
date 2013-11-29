cmake_minimum_required (VERSION 2.6)
project (ZMAP C)

option(WITH_REDIS "Build with support for Redis DB" OFF)
option(WITH_JSON "Build with support for JSON" OFF)
option(ENABLE_DEVELOPMENT "Enable development specific compiler and linker flags" OFF)
#option(ENABLE_HARDENING "Add hardening specific compiler and linker flags" ON)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
	set(USING_CLANG "YES")
else()
	set(USING_GCC "YES")
endif()

if(ENABLE_DEVELOPMENT)
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
		"-Werror"
		)

	# Fix line breaks
	string(REPLACE ";" " "  GCCWARNINGS "${GCCWARNINGS}")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCCWARNINGS} -g")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -g")
endif()

if(ENABLE_DEVELOPMENT)
	set(GCCWARNINGS "${GCCWARNINGS} -Werror")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -g")
else()
	# Hardening and optimizations for building with gcc
	set(GCCHARDENING "-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIC --param ssp-buffer-size=1")
	if (NOT APPLE)
		set(LDHARDENING "-z relro -z now")
	else()
		set(LDHARDENING "")
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCCHARDENING} -O2")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LDHARDENING}")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCCWARNINGS}")

if(ENABLE_HARDENING)

endif()

if(WITH_REDIS)
	set(REDIS_LIBS hiredis)
	add_definitions("-DREDIS")
endif()

if(WITH_JSON)
	include(FindPkgConfig)
	pkg_check_modules(JSON json)
	if(JSON_FOUND)
		include_directories(JSON_INCLUDE_DIRS)
	else()
		message(FATAL_ERROR "Did not find libjson")
	endif()

	add_definitions("-DJSON")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${JSON_CFLAGS}")
endif()



# Standard FLAGS
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
if (NOT APPLE)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")
endif()

add_subdirectory(src)

# Install conf files
FILE(GLOB CONF_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/conf" "conf/*")
message(STATUS "${CONF_FILES}")
configure_file(zmap_conf_install.cmake.in zmap_conf_install.cmake)
install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/zmap_conf_install.cmake")
