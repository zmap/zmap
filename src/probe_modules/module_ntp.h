/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "../fieldset.h"
#include "../state.h"

#ifndef MODULE_NTP_H
#define MODULE_NTP_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct __attribute__((__packed__)) ntphdr { // typedef
	uint8_t LI_VN_MODE;
	uint8_t stratum;
	uint8_t poll;
	uint8_t precision;
	uint32_t root_delay;
	uint32_t root_dispersion;
	uint32_t ref_ID;
	uint64_t reference_timestamp;
	uint64_t origin_timestamp;
	uint64_t receive_timestamp;
	uint64_t transmit_timestamp;
	// uint32_t key_ID;
	// uint64_t dgst_1;
	// uint64_t dgst_2;
};

#endif
