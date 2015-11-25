/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_MODULE_BACNET_H
#define ZMAP_MODULE_BACNET_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "probe_modules.h"

extern probe_module_t module_bacnet;

struct __attribute__((__packed__)) bacnet_vlc {
        uint8_t type;
        uint8_t function;
        uint16_t length;
};
typedef struct bacnet_vlc bacnet_vlc_t;

struct __attribute__((__packed__)) bacnet_npdu {
        uint8_t version;
        uint8_t control;
};
typedef struct bacnet_npdu bacnet_npdu_t;

struct __attribute__((__packed__)) bacnet_apdu {
        uint8_t type_flags;
        uint8_t max_segments_apdu;
        uint8_t invoke_id;
        uint8_t server_choice;
};
typedef struct bacnet_apdu bacnet_apdu_t;

struct __attribute__((__packed__)) bacnet_probe {
        struct bacnet_vlc vlc;
        struct bacnet_npdu npdu;
        struct bacnet_apdu apdu;
};
typedef struct bacnet_probe bacnet_probe_t;

typedef struct bacnet_oid bacnet_oid_t;

#define ZMAP_BACNET_TYPE_IP 0x81
#define ZMAP_BACNET_FUNCTION_UNICAST_NPDU 0x0a
#define ZMAP_BACNET_NPDU_VERSION_ASHRAE_135_1995 0x01
#define ZMAP_BACNET_SERVER_CHOICE_READ_PROPERTY 0x0c

#endif /* ZMAP_MODULE_BACNET_H */
