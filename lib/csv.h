#ifndef ZMAP_CSV_H
#define ZMAP_CSV_H

#include <string.h>

int csv_find_index(char *header, const char **names, size_t names_len);
char *csv_get_index(char *row, size_t idx);

#endif
