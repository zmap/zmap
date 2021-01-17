/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef IPV6_TARGET_FILE_H
#define IPV6_TARGET_FILE_H

int ipv6_target_file_init(char *file);
int ipv6_target_file_get_ipv6(struct in6_addr *dst);
int ipv6_target_file_deinit();

#endif
