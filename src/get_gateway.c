/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include <pcap/pcap.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/xalloc.h"

#include <sys/ioctl.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||       \
    defined(__DragonFly__)
#include "get_gateway-bsd.h"
#else // (linux)
#include "get_gateway-linux.h"
#endif
