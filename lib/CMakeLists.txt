SET(LIB_SOURCES
    blocklist.c
    cachehash.c
    constraint.c
    logger.c
    pbm.c
    random.c
    rijndael-alg-fst.c
    xalloc.c
    lockfd.c
    util.c
    queue.c
    csv.c
    aes128.c
)

add_library(zmaplib STATIC ${LIB_SOURCES})

if(WITH_AES_HW)
    add_definitions("-DAES_HW")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+crypto")
    endif()
endif()

target_link_libraries(
    zmaplib
    ${JUDY_LIBRARIES}
)

target_include_directories (zmaplib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
