#include "fieldset.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "../lib/logger.h"

// maximum number of records that can be stored in a fieldset
#define MAX_FIELDS 128

// types of data that can be stored in a field
#define FS_STRING 0
#define FS_UINT64 1
#define FS_BINARY 2

// definition of a field that's provided by a probe module
// these are used so that users can ask at the command-line
// what fields are available for consumption
typedef struct field_def {
	const char *name;
	const char *type;
	const char *desc;
} field_def_t;

// the internal field type used by fieldset
typedef struct field {
	const char *name;
	int type;
	int free_;
	size_t len;
	void *value;
} field_t;

// data structure that is populated by the probe module
// and translated into the data structure that's passed
// to the output module
typedef struct fieldset {
	int len;
	field_t fields[MAX_FIELDS];
} fieldset_t;

// we pass a different fieldset to an output module than 
// the probe module generates for us because a user may
// only want certain fields and will expect them in a certain
// order. We generate a translated fieldset that contains
// only the fields we want to export to the output module.
// a translation specifies how to efficiently convert the fs
// povided by the probe module to the fs for the output module.
typedef struct translation {
	int len;
	int translation[MAX_FIELDS];
} translation_t;

int fs_split_string(int *len, char**results)
{
	
}

fieldset_t *fs_new_fieldset(void)
{
	fieldset_t *f = malloc(sizeof(fieldset_t));
	if (!f) {
		log_fatal("fieldset", "unable to allocate new fieldset");
	}
	memset(f, 0, sizeof(fieldset_t));
	return f;	
}

static inline void fs_add_word(fieldset_t *fs, const char *name, int type,
		int free_, size_t len, void *value)
{
	if (fs->len + 1 >= MAX_FIELDS) {
		log_fatal("fieldset", "out of room in fieldset");
	}
	field_t *f = &(fs->fields[fs->len]);
	fs->len++;
	f->type = type;
	f->name = name;
	f->len = len;
	f->value = value;
	f->free_ = free_;
}

void fs_add_string(fieldset_t *fs, const char *name, char *value, int free_)
{
	fs_add_word(fs, name, FS_STRING, free_, strlen(value), (void*) value);
}

void fs_add_uint64(fieldset_t *fs, const char *name, uint64_t value)
{
	fs_add_word(fs, name, FS_STRING, 0, sizeof(uint64_t), (void*) value);
}

void fs_add_binary(fieldset_t *fs, const char *name, size_t len,
		void *value, int free_)
{
	fs_add_word(fs, name, FS_BINARY, free_, len, value);
}

void fs_free(fieldset_t *fs)
{
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		if (f->free_) {
			free(f->value);
		}
	}
	free(fs);
}

translation_t *fs_generate_fieldset_translation()
{

}

fieldset_t *translate_fieldset(fieldset_t *fs, translation_t *t)
{
	fieldset_t *retv = fs_new_fieldset();
	if (!retv) {
		log_fatal("fieldset", "unable to allocate space for translated field set");
	}
	for (int i=0; i < t->len; i++) {
		int o = t->translation[i];
		memcpy(&(retv->fields[i]), &(fs->fields[o]), sizeof(field_t));
	}
	retv->len = t->len;
}
