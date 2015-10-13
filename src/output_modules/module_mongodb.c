/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* NOTE: This output module is currently marked as only supporting statically
 * structured data. Clearly, MongoDB can handle dynamic documents longterm.
 * However, this will need to be implemented and is not currently.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../../lib/logger.h"
#include "../../lib/xalloc.h"

#include "mongoc.h"
#include "bson.h"

#include "output_modules.h"

#define UNUSED __attribute__((unused))

#define BUFFER_SIZE 50

static int buffer_fill = 0;
static mongoc_client_t *client         = NULL;
static mongoc_collection_t *collection = NULL;
static mongoc_bulk_operation_t *bulk   = NULL;

void mongodb_module_log(mongoc_log_level_t log_level, const char *log_domain, 
        const char *msg, UNUSED void *user_data)
{
	if (log_level == MONGOC_LOG_LEVEL_ERROR) {
		log_fatal("mongodb-module", "%s: %s", log_domain, msg);
	}
	else if (log_level ==  MONGOC_LOG_LEVEL_CRITICAL){
		log_error("mongodb-module", "%s: %s", log_domain, msg);
	}
	else if (log_level ==  MONGOC_LOG_LEVEL_WARNING){
		log_warn("mongodb-module", "%s: %s", log_domain, msg);
	}
	else if (log_level ==  MONGOC_LOG_LEVEL_INFO || log_level ==  MONGOC_LOG_LEVEL_MESSAGE){
		log_info("mongodb-module", "%s: %s", log_domain, msg);
	}
	else if (log_level ==  MONGOC_LOG_LEVEL_DEBUG){
		log_debug("mongodb-module", "%s: %s", log_domain, msg);
	}
	else {
		log_debug("mongodb-module", "%s: %s", log_domain, msg);
	}
}

int mongodb_module_init(struct state_conf *conf, UNUSED char **fields, UNUSED int fieldlens)
{
	char *uri_str = NULL;
	buffer_fill = 0;
	const char *db;

	if (conf->output_args) {
		uri_str = conf->output_args;
	}

	mongoc_init();
	mongoc_log_set_handler(mongodb_module_log, NULL);
	mongoc_uri_t *uri = mongoc_uri_new(uri_str);

	if (uri == NULL) {
		log_fatal("mongodb-module", "URI %s not valid!", uri_str);
	}

	client = mongoc_client_new_from_uri(uri);

	db = mongoc_uri_get_database(uri);
	collection = mongoc_client_get_collection(client, db ? db : strdup("zmap_output"), 
            conf->output_filename ? conf->output_filename : strdup("zmap_output"));
	bulk = mongoc_collection_create_bulk_operation(collection,false,NULL);

	return EXIT_SUCCESS;
}

static int mongodb_module_flush(void)
{
	int ret;
	uint32_t bulk_ret;
	bson_error_t error;
	bson_t reply;
	mongoc_bulk_operation_t *old_bulk;

	if (buffer_fill == 0){
		mongoc_bulk_operation_destroy(bulk);
		return EXIT_SUCCESS;
	}

	bulk_ret = mongoc_bulk_operation_execute(bulk, &reply, &error);
	old_bulk = bulk;

	if (bulk_ret == 0) {
		mongoc_log(MONGOC_LOG_LEVEL_ERROR, "zmap", 
                "Error executing bulk insert: %s", error.message);
		ret = EXIT_FAILURE;
	} else {
		bulk = mongoc_collection_create_bulk_operation(collection,false,NULL);
		ret = EXIT_SUCCESS;
	}

	bson_destroy(&reply);
	mongoc_bulk_operation_destroy(old_bulk);
	return ret;
}

int mongodb_module_process(fieldset_t *fs)
{
	bson_t *doc;

	if (!bulk) {
		return EXIT_FAILURE;
	}

	if (buffer_fill == BUFFER_SIZE) {
		if (mongodb_module_flush()) {
			return EXIT_FAILURE;
		}
	}

	doc = bson_new();
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		if (f->type == FS_STRING) {
			BSON_APPEND_UTF8(doc,f->name,f->value.ptr);
		} else if (f->type == FS_UINT64) {
			BSON_APPEND_INT64(doc,f->name,(uint64_t) f->value.num);
		} else if (f->type == FS_BINARY) {
			BSON_APPEND_BINARY(doc,f->name, BSON_SUBTYPE_BINARY,f->value.ptr, f->len);
		} else if (f->type == FS_NULL) {
			// do nothing
		} else {
			log_fatal("mongodb", "received unknown output type");
		}
	}
	mongoc_bulk_operation_insert(bulk,doc);
	buffer_fill++;
	return EXIT_SUCCESS;
}

int mongodb_module_close(UNUSED struct state_conf* c,
		UNUSED struct state_send* s,
		UNUSED struct state_recv* r)
{
	if (mongodb_module_flush()) {
		return EXIT_FAILURE;
	}
	mongoc_collection_destroy(collection);
	mongoc_client_destroy(client);
	mongoc_cleanup();
	return EXIT_SUCCESS;
}

output_module_t module_mongodb = {
	.name = "mongodb",
	.init = &mongodb_module_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
    .supports_dynamic_output = NO_DYNAMIC_SUPPORT,
	.close = &mongodb_module_close,
	.process_ip = &mongodb_module_process,
	.helptext = "Write output to MongoDB. Defaults to mongodb://localhost:27017/zmap_output. Specify a custom connection URI in output module args."
};
