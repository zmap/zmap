/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN scans

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifndef JA4TS_UNIT_TEST
#include <unistd.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#endif /* !JA4TS_UNIT_TEST */

#define SMALLEST_PROBES_OS_OPTIONS 0x00
#define LINUX_OS_OPTIONS 0x01
#define BSD_OS_OPTIONS 0x02
#define WINDOWS_OS_OPTIONS 0x03

#ifndef JA4TS_UNIT_TEST
void synscan_print_packet(FILE *fp, void *packet);
#endif /* !JA4TS_UNIT_TEST */

/* Format a JA4TS string for a SYN-ACK.
 *
 *   opts:        pointer to TCP options bytes (i.e. (uint8_t*)tcp + 20)
 *   opts_len:    length of the options region in bytes (data_offset*4 - 20)
 *   window:      TCP receive window, host byte order
 *   out:         caller-provided buffer
 *   out_len:     size of out in bytes (>= 256 recommended)
 *
 * Always writes a NUL-terminated string. Stops parsing on the first
 * malformed option and emits whatever was collected up to that point.
 * "00" is emitted for MSS / wscale when the corresponding option is
 * absent; "0" is emitted when the option is present with value 0.
 */
void compute_ja4ts(const uint8_t *opts, size_t opts_len, uint16_t window,
		   char *out, size_t out_len);
