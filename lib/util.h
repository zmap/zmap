#ifndef ZMAP_UTIL_H
#define ZMAP_UTIL_H

#include <stdio.h>
#include <stdint.h>

int max_int(int a, int b);

// Splits comma delimited string into char*[]. Does not handle
// escaping or complicated setups - designed to process a set
// of fields that the user wants output
void split_string(char *in, int *len, char ***results);

// Print a string using w length long lines, attempting to break on
// spaces
void fprintw(FILE *f, char *s, size_t w);

// If running as root, drops priviledges to that of user "nobody".
// Otherwise, does nothing.
int drop_privs();

// Set CPU affinity to a single core
int set_cpu(uint32_t core);




#endif /* ZMAP_UTIL_H */
