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

#ifndef UTILITY_H
#define UTILITY_H

#include <netinet/in.h>

void parse_source_ip_addresses(char given_string[]);
in_addr_t string_to_ip_address(char *t);

#if defined(__linux__) // BSD has an implementation of strlcpy, but linux doesn't by default
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif // linux

#endif // UTILITY_H
