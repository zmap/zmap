#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../../lib/logger.h"
#include "../../lib/xalloc.h"

#include "mongoc.h"
#include "bson.h"

#include "output_modules.h"
#include "module_mongodb.h"

#define UNUSED __attribute__((unused))

#define BUFFER_SIZE 50

static int buffer_fill = 0;
static mongoc_client_t *client = NULL;
static mongoc_collection_t *collection = NULL;
static mongoc_bulk_operation_t *bulk = NULL;

static void mongodb_module_log(mongoc_log_level_t log_level,
			       const char *log_domain, const char *msg,
			       UNUSED void *user_data)
{
	if (log_level == MONGOC_LOG_LEVEL_ERROR) {
		log_fatal("mongodb-module", "%s: %s", log_domain, msg);
	} else if (log_level == MONGOC_LOG_LEVEL_CRITICAL) {
		log_error("mongodb-module", "%s: %s", log_domain, msg);
	} else if (log_level == MONGOC_LOG_LEVEL_WARNING) {
		log_warn("mongodb-module", "%s: %s", log_domain, msg);
	} else if (log_level == MONGOC_LOG_LEVEL_INFO ||
		   log_level == MONGOC_LOG_LEVEL_MESSAGE) {
		log_info("mongodb-module", "%s: %s", log_domain, msg);
	} else {
		log_debug("mongodb-module", "%s: %s", log_domain, msg);
	}
}

static int mongodb_module_flush(void)
{
	int ret;
	uint32_t bulk_ret;
	bson_error_t error;
	bson_t reply;
	mongoc_bulk_operation_t *old_bulk;

	if (buffer_fill == 0) {
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
		bulk = mongoc_collection_create_bulk_operation_with_opts(
		    collection, NULL);
		ret = EXIT_SUCCESS;
	}

	bson_destroy(&reply);
	mongoc_bulk_operation_destroy(old_bulk);
	return ret;
}

static void append_to_bson(bson_t *doc, field_t *field, const char *name);

static void append_fs_to_bson(bson_t *doc, const char *name, fieldset_t *fs)
{
	bson_t inner;
	if (fs->len > 0) {
		bson_append_document_begin(doc, name, (int)strlen(name),
					   &inner);
		for (int i = 1; i < fs->len; i++) {
			field_t *field = &(fs->fields[i]);
			append_to_bson(&inner, field, NULL);
		}
		bson_append_document_end(doc, &inner);
	}
}

static void append_repeated_to_bson(bson_t *doc, const char *name,
				    fieldset_t *fs)
{
	bson_t inner;
	char str[3];
	if (fs->len > 0) {
		const char *key;
		bson_append_array_begin(doc, name, strlen(name), &inner);
		for (int i = 0; i < fs->len; i++) {
			field_t *field = &(fs->fields[i]);
			bson_uint32_to_string(i, &key, str, sizeof str);
			append_to_bson(&inner, field, key);
		}
		bson_append_array_end(doc, &inner);
	}
}

void append_to_bson(bson_t *doc, field_t *field, const char *name)
{
	if (name == NULL) {
		name = field->name;
	}
	if (field->type == FS_STRING) {
		BSON_APPEND_UTF8(doc, name, field->value.ptr);
	} else if (field->type == FS_UINT64) {
		BSON_APPEND_INT64(doc, name, (uint64_t)field->value.num);
	} else if (field->type == FS_BOOL) {
		BSON_APPEND_BOOL(doc, name, field->value.num);
	} else if (field->type == FS_BINARY) {
		BSON_APPEND_BINARY(doc, name, BSON_SUBTYPE_BINARY,
				   field->value.ptr, field->len);
	} else if (field->type == FS_NULL) {
		// do nothing
	} else if (field->type == FS_FIELDSET) {
		append_fs_to_bson(doc, name, field->value.ptr);
	} else if (field->type == FS_REPEATED) {
		append_repeated_to_bson(doc, name, field->value.ptr);
	} else {
		log_fatal("mongodb", "received unknown output type");
	}
}

int mongodb_module_init(struct state_conf *conf, UNUSED char **fields,
			UNUSED int fieldlens)
{
	char *uri_str = NULL;
	buffer_fill = 0;
	const char *db;

	if (conf->output_args) {
		log_debug("mongdb", "output args %s", conf->output_args);
		uri_str = conf->output_args;
	}

	mongoc_init();
	mongoc_log_set_handler(mongodb_module_log, NULL);
	mongoc_uri_t *uri = mongoc_uri_new(uri_str);

	if (uri == NULL) {
		log_fatal("mongodb", "URI %s not valid!", uri_str);
	}

	client = mongoc_client_new_from_uri(uri);

	db = mongoc_uri_get_database(uri);
	collection = mongoc_client_get_collection(
	    client, db ? db : strdup("zmap_output"),
	    conf->output_filename ? conf->output_filename
				  : strdup("zmap_output"));
	bulk =
	    mongoc_collection_create_bulk_operation_with_opts(collection, NULL);

	return EXIT_SUCCESS;
}

int mongodb_module_process(fieldset_t *fs)
{
	bson_t *doc;

	if (!bulk) {
		return EXIT_FAILURE;
	}

	doc = bson_new();
	for (int i = 0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		append_to_bson(doc, f, f->name);
	}
	mongoc_bulk_operation_insert(bulk, doc);
	bson_destroy(doc);

	if (++buffer_fill == BUFFER_SIZE) {
		if (mongodb_module_flush()) {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int mongodb_module_close(UNUSED struct state_conf *c,
			 UNUSED struct state_send *s,
			 UNUSED struct state_recv *r)
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
    .supports_dynamic_output = DYNAMIC_SUPPORT,
    .close = &mongodb_module_close,
    .process_ip = &mongodb_module_process,
    .helptext =
	"Write output to MongoDB. Defaults to mongodb://localhost:27017/zmap_output. Specify a custom connection URI in output module args."};
