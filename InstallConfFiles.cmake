if(NOT EXISTS "/etc/zmap/blacklist.conf")
   file(COPY "${PROJECT_SOURCE_DIR}/conf/blacklist.conf" DESTINATION "/etc/zmap/blacklist.conf")
endif()

if(NOT EXISTS "/etc/zmap/zmap.conf")
   file(COPY "${PROJECT_SOURCE_DIR}/conf/zmap.conf" DESTINATION "/etc/zmap/zmap.conf")
endif()
