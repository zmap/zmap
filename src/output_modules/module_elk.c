/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <json.h>
#include <curl/curl.h>

#include "../../lib/logger.h"

#include "output_modules.h"
#include "module_json.h"
#include "../probe_modules/probe_modules.h"

#define UNUSED __attribute__((unused))
#define MAX_BULK_BUFFER  (1024 * 150)
#define BULK_INDEX "{\"index\":{}}\n"

char *_g_res_bulk = NULL;
unsigned int _g_res_bulk_fill = 0;

char _g_scan_res_uri[512];
char _g_scan_res_uri_bulk[512];
char _g_scan_info_uri[] = "http://localhost:9200/zmap/scaninfo/";

CURL *_g_curl;
time_t _g_start_time;

int elk_insert(char *data, char*uri)
{
	CURLcode res;
    
	curl_easy_setopt(_g_curl, CURLOPT_POST, 1);
	curl_easy_setopt(_g_curl, CURLOPT_URL, uri);
	curl_easy_setopt(_g_curl, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(_g_curl, CURLOPT_POSTFIELDSIZE, strlen(data));
	res = curl_easy_perform(_g_curl);
	return res;
}

int elk_insert_bulk(char *data, char*uri, int force)
{
	CURLcode res;
	unsigned int data_len = 0;
    
	if (!force){
		data_len = strlen(data);
		if ((sizeof(BULK_INDEX) + data_len + _g_res_bulk_fill) < (MAX_BULK_BUFFER - 1))
		{
			strcat(_g_res_bulk, BULK_INDEX);
			strcat(_g_res_bulk, data);
			strcat(_g_res_bulk, "\n");
			
			_g_res_bulk_fill += (sizeof(BULK_INDEX)) + data_len;
			return 0;
		}
		else
		{
			char *insert_buff = malloc(data_len + sizeof(BULK_INDEX) + sizeof(char));
			if (insert_buff == NULL) log_fatal("elk", "Can't allocated insert buffer!");
			
			memset(insert_buff, 0, data_len + sizeof(BULK_INDEX) + sizeof(char));
			strcat(insert_buff, BULK_INDEX);
			strcat(insert_buff, data);
			strcat(insert_buff, "\n");
			
			res = elk_insert(insert_buff, uri);
			free(insert_buff);
		}
	}
	
	res = elk_insert(_g_res_bulk, uri);
	memset(_g_res_bulk, 0, MAX_BULK_BUFFER * sizeof(char));
	_g_res_bulk_fill = 0;

	return res;
}

int insert_scan_info(struct state_conf *conf)
{
	int res;
	
	json_object *record = json_object_new_object();
	json_object_object_add(record, "tport", json_object_new_int(conf->target_port));
	json_object_object_add(record, "bandwidth", json_object_new_int64(conf->bandwidth));
	json_object_object_add(record, "scan_start", json_object_new_int64(_g_start_time));
	
	res = elk_insert((char*)json_object_to_json_string(record), _g_scan_info_uri);
	json_object_put(record);
	
	return res;
}

int elk_module_init(struct state_conf *conf, UNUSED char **fields, UNUSED int fieldlens)
{
	if (conf->output_args) {
		strncpy(_g_scan_res_uri, conf->output_args, 511);
		snprintf(_g_scan_res_uri_bulk, 511, "%s_bulk", conf->output_args);
	}
	else {
		strcpy(_g_scan_res_uri, "http://localhost:9200/zmap/scan/");
		strcpy(_g_scan_res_uri_bulk, "http://localhost:9200/zmap/scan/_bulk");
	}
	
	_g_curl = curl_easy_init();
	if(_g_curl) 
	{
		FILE* devnull = fopen("nul", "w"); 
		curl_easy_setopt(_g_curl, CURLOPT_WRITEDATA, devnull);
		curl_easy_setopt(_g_curl, CURLOPT_VERBOSE, 0); 
	} 
	else 
	{		
		log_fatal("elk", "Can't ininilize curl!");
	}
	
	_g_start_time = time(NULL);
	if (insert_scan_info(conf)) log_fatal("elk", "Can't insert scan info into elk!");
	
	_g_res_bulk = malloc(MAX_BULK_BUFFER * sizeof(char));
	if (_g_res_bulk == NULL)
	{
		log_fatal("elk", "Can't allocated bulk insert buffer!");
	}
	else 
	{
		memset(_g_res_bulk, 0, MAX_BULK_BUFFER * sizeof(char));
		_g_res_bulk_fill = 0;
	}
	
	return EXIT_SUCCESS;
}

int elk_module_process(fieldset_t *fs)
{	
	int res;
	
	json_object *record = fs_to_jsonobj(fs);
	json_object_object_add(record, "scan_start", json_object_new_int64(_g_start_time));
	res = elk_insert_bulk((char*)json_object_to_json_string(record), _g_scan_res_uri_bulk, 0);
	json_object_put(record);
	
	if (res)
		log_debug("elk", "Can't insert scan resutl into elk!");
	
	check_and_log_file_error(stdout, "elk");
	return EXIT_SUCCESS;
}

int elk_module_close(UNUSED struct state_conf* c, UNUSED struct state_send* s, UNUSED struct state_recv* r)
{
	elk_insert_bulk(NULL, _g_scan_res_uri_bulk, 1);
	curl_easy_cleanup(_g_curl);
	free(_g_res_bulk);
	return EXIT_SUCCESS;
}

output_module_t module_elk = {
	.name = "elk",
	.init = &elk_module_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
    .supports_dynamic_output = DYNAMIC_SUPPORT,
	.close = &elk_module_close,
	.process_ip = &elk_module_process,
	.helptext = "Write output to Elasticsearch. Defaults to http://localhost:9200/zmap/scan/. Specify a custom connection URI in output module args."
};
