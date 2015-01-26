#include "csv.h"

int csv_find_index(char *header, const char **names, size_t names_len)
{
	char *split = header;
	for (int idx = 0; split != NULL; ++idx) {
		char *front = (idx == 0) ? split : split + 1;
		for (size_t i = 0; i < names_len; ++i) {
			if (strncmp(front, names[i], strlen(names[i])) == 0) {
				return idx;
			}
		}
		split = strchr(front, ',');
	}
	return -1;

}

char* csv_get_index(char *row, size_t idx)
{
	char *split = row;
	for (size_t i = 0; i < idx; ++i) {
		split = strchr(split + 1, ',');
		if (split == NULL) {
			return NULL;
		}
	}
	char *entry;
	char *start = (idx == 0) ? split : split + 1;
	char *end = strchr(start, ',');
	if (end != NULL) {
		entry = strndup(start, end - start);
	} else {
		entry = strdup(start);
	}
	return entry;
}
