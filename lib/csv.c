/*
 * Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

char *csv_get_index(char *row, size_t idx)
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
