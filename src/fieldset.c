/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "fieldset.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "../lib/logger.h"

void gen_fielddef_set(fielddefset_t *fds, fielddef_t fs[], int len)
{
	if (fds->len + len > MAX_FIELDS) {
		log_fatal("fieldset", "out of room in field def set");
	}
	fielddef_t *open = &(fds->fielddefs[fds->len]);
	memcpy(open, fs, len*sizeof(fielddef_t)); 
	fds->len += len;
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
		int free_, size_t len, field_val_t value)
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

static void fs_modify_word(fieldset_t *fs, const char *name, int type,
		int free_, size_t len, field_val_t value)
{
	for (int i=0; i<fs->len; i++) {
		if (!strcmp(fs->fields[i].name, name)) {
			if (fs->fields[i].free_) {
				free(fs->fields[i].value.ptr);
				fs->fields[i].value.ptr = NULL;
			}
			fs->fields[i].type = type;
			fs->fields[i].free_ = free_;
			fs->fields[i].len = len;
			fs->fields[i].value = value;
			return;
		}
	}
	fs_add_word(fs, name, type, free_, len, value);
}

void fs_add_null(fieldset_t *fs, const char *name)
{
	field_val_t val = { .ptr = NULL };
	fs_add_word(fs, name, FS_NULL, 0, 0, val);
}

void fs_add_string(fieldset_t *fs, const char *name, char *value, int free_)
{
	field_val_t val = { .ptr = value };
	fs_add_word(fs, name, FS_STRING, free_, strlen(value), val);
}

void fs_add_uint64(fieldset_t *fs, const char *name, uint64_t value)
{
	field_val_t val = { .num = value };
	fs_add_word(fs, name, FS_UINT64, 0, sizeof(uint64_t), val);
}

void fs_add_binary(fieldset_t *fs, const char *name, size_t len,
		void *value, int free_)
{
	field_val_t val = { .ptr = value };
	fs_add_word(fs, name, FS_BINARY, free_, len, val);
}

// Modify
void fs_modify_null(fieldset_t *fs, const char *name)
{
	field_val_t val = { .ptr = NULL };
	fs_modify_word(fs, name, FS_NULL, 0, 0, val);
}

void fs_modify_string(fieldset_t *fs, const char *name, char *value, int free_)
{
	field_val_t val = { .ptr = value };
	fs_modify_word(fs, name, FS_STRING, free_, strlen(value), val);
}

void fs_modify_uint64(fieldset_t *fs, const char *name, uint64_t value)
{
	field_val_t val = { .num = value };
	fs_modify_word(fs, name, FS_UINT64, 0, sizeof(uint64_t), val);
}

void fs_modify_binary(fieldset_t *fs, const char *name, size_t len,
		void *value, int free_)
{
	field_val_t val = { .ptr = value };
	fs_modify_word(fs, name, FS_BINARY, free_, len, val);
}

uint64_t fs_get_uint64_by_index(fieldset_t *fs, int index)
{
	return (uint64_t) fs->fields[index].value.num;
}

char* fs_get_string_by_index(fieldset_t *fs, int index)
{
	return (char*) fs->fields[index].value.ptr;
}

int fds_get_index_by_name(fielddefset_t *fds, char *name)
{
	for (int i=0; i < fds->len; i++) {
		if (!strcmp(fds->fielddefs[i].name, name)) {
			return i;
		}
	}
	return -1;
}

void fs_free(fieldset_t *fs)
{
	if (!fs) {
		return;
	}
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		if (f->free_) {
			free(f->value.ptr);
		}
	}
	free(fs);
}

void fs_generate_fieldset_translation(translation_t *t, 
		fielddefset_t *avail, char** req, int reqlen)
{
	memset(t, 0, sizeof(translation_t));
	if (!t) {
		log_fatal("fieldset", "unable to allocate memory for translation");
	}
	for (int i=0; i < reqlen; i++) {
		int l = fds_get_index_by_name(avail, req[i]);
		if (l < 0) {
			log_fatal("fieldset", "specified field (%s) not "
					      "available in selected "
					      "probe module.", req[i]);
		}
		t->translation[t->len++] = l;
	}
}

void fs_generate_full_fieldset_translation(translation_t *t, fielddefset_t *avail)
{
	memset(t, 0, sizeof(translation_t));
	if (!t) {
		log_fatal("fieldset", "unable to allocate memory for translation");
	}
	t->len = avail->len;
	for (int i=0; i < avail->len; i++) {
		t->translation[i] = i;
	}
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

