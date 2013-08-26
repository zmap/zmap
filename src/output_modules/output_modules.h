/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OUTPUT_MODULES_H
#define OUTPUT_MODULES_H

#include "../state.h"

// called at scanner initialization
typedef int (*output_init_cb)(struct state_conf *);

// called on packet receipt
typedef int (*output_packet_cb)(ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				const char* response_type,
				int is_repeat, int in_cooldown,
				const u_char* packetbuf, size_t buflen);

// called periodically during the scan
typedef int (*output_update_cb)(struct state_conf*, struct state_send*, struct state_recv*);


typedef struct output_module {
	const char *name;
	unsigned update_interval;

	output_init_cb init;
	output_update_cb start;
	output_update_cb update;
	output_update_cb close;
	output_packet_cb success_ip;
	output_packet_cb other_ip;

} output_module_t;


output_module_t* get_output_module_by_name(const char*);
void print_output_modules(void);

#endif // HEADER_OUTPUT_MODULES_H
