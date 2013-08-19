#include "fieldset.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "../lib/logger.h"


int fs_split_string(int *len, char**results)
{
	(void)len;
	(void)results;
	return 0;
}

void combine_definitions()
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
	return NULL;
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
	return retv;
}

