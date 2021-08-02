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

#ifndef ZMAP_UTIL_H
#define ZMAP_UTIL_H

#include <stdio.h>
#include <stdint.h>

#include "types.h"

int max_int(int a, int b);

uint32_t parse_max_hosts(char *max_targets);
void enforce_range(const char *name, int v, int min, int max);

// Splits comma delimited string into char*[]. Does not handle
// escaping or complicated setups - designed to process a set
// of fields that the user wants output
void split_string(const char *in, int *len, const char ***results);

// Print a string using w length long lines, attempting to break on
// spaces
void fprintw(FILE *f, const char *s, size_t w);

// pretty print elapsed (or estimated) number of seconds
void time_string(uint32_t time, int est, char *buf, size_t len);

// pretty print quantities
void number_string(uint32_t n, char *buf, size_t len);

// Convert a string representation of a MAC address to a byte array
int parse_mac(macaddr_t *out, char *in);

int check_range(int v, int min, int max);

int file_exists(char *name);

// If running as root, drops privileges to that of user "nobody".
// Otherwise, does nothing.
int drop_privs();

// Set CPU affinity to a single core
int set_cpu(uint32_t core);

#endif /* ZMAP_UTIL_H */
