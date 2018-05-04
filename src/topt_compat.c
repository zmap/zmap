#if __GNUC__ < 4
#error "gcc version >= 4 is required"
#elif __GNUC__ == 4 && __GNUC_MINOR__ >= 6
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#elif __GNUC_MINOR__ >= 4
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

#include "topt.c"
