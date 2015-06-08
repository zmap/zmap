SET(LIB_SOURCES
    blacklist.c
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
)

if (WITH_REDIS)
    SET(LIB_SOURCES ${LIB_SOURCES} redis.c)
endif()

add_library(zmaplib STATIC ${LIB_SOURCES})

target_include_directories (zmaplib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
