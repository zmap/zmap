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

#include "../state.h"
#include "../fieldset.h"

#ifndef PROBE_MODULES_H
#define PROBE_MODULES_H

#define OUTPUT_TYPE_STATIC 1
#define OUTPUT_TYPE_DYNAMIC 2

typedef struct probe_response_type {
	const uint8_t is_success;
	const char *name;
} response_type_t;

typedef int (*probe_global_init_cb)(struct state_conf *);
typedef int (*probe_thread_init_cb)(void *packetbuf, macaddr_t *src_mac,
				    macaddr_t *gw_mac, port_n_t src_port,
				    void **arg_ptr);

// The make_packet callback is passed a buffer pointing at an ethernet header.
// The buffer is MAX_PACKET_SIZE bytes. The callback must update the value
// pointed at by buf_len with the actual length of the packet. The contents of
// the buffer will match the previous packet sent. Every invocation of
// make_packet contains a unique (src_ip, probe_num) tuple.
//
// The probe module is responsible for populating the IP header. The src_ip,
// dst_ip, and ttl are provided by the framework and must be set on the IP
// header.
//
// The uin32_t validation parameter is a pointer to four 4-byte words of
// validation data.  The data is deterministic based on the the validation
// state, and is constant across a src_ip. To get the src_port, use the
// get_src_port function which takes probe_num and validation as parameters.
typedef int (*probe_make_packet_cb)(void *packetbuf, size_t *buf_len,
				    ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
				    uint32_t *validation, int probe_num,
				    void *arg);

typedef void (*probe_print_packet_cb)(FILE *, void *packetbuf);
typedef int (*probe_close_cb)(struct state_conf *, struct state_send *,
			      struct state_recv *);
typedef int (*probe_validate_packet_cb)(const struct ip *ip_hdr, uint32_t len,
					uint32_t *src_ip, uint32_t *validation);

typedef void (*probe_classify_packet_cb)(const u_char *packetbuf, uint32_t len,
					 fieldset_t *, uint32_t *validation, const struct timespec ts);

typedef struct probe_module {
	const char *name;

	// TODO(dadrian): Completely get rid of this. We can do bandwidth rate
	// limiting by actually counting how much data is sent over the wire. We
	// know the lengths of packets from the make_packet API.
	size_t max_packet_length;

	const char *pcap_filter;
	size_t pcap_snaplen;

	// Should ZMap complain if the user hasn't specified valid
	// source and target port numbers?
	uint8_t port_args;

	probe_global_init_cb global_initialize;
	probe_thread_init_cb thread_initialize;
	probe_make_packet_cb make_packet;
	probe_print_packet_cb print_packet;
	probe_validate_packet_cb validate_packet;
	probe_classify_packet_cb process_packet;
	probe_close_cb close;
	int output_type;
	fielddef_t *fields;
	int numfields;
	const char *helptext;

} probe_module_t;

probe_module_t *get_probe_module_by_name(const char *);

void fs_add_ip_fields(fieldset_t *fs, struct ip *ip);
void fs_add_system_fields(fieldset_t *fs, int is_repeat, int in_cooldown);
void print_probe_modules(void);

extern int ip_fields_len;
extern int sys_fields_len;
extern fielddef_t ip_fields[];
extern fielddef_t sys_fields[];

#endif // HEADER_PROBE_MODULES_H
