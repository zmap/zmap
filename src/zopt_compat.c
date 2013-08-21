#if __GNUC__ < 4
#error "gcc version >= 4 is required"
#elif __GNUC_MINOR__ >= 6
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

const char* zmap_version(void);
#define CMDLINE_PARSER_VERSION zmap_version()

#include "zopt.c"
