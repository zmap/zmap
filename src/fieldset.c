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
#include <unistr.h>

#include "../lib/logger.h"
#include "../lib/xalloc.h"

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
	fieldset_t *f = xcalloc(1, sizeof(fieldset_t));
	f->len = 0;
	f->type = FS_FIELDSET;
	return f;
}

fieldset_t *fs_new_repeated_field(int type, int free_)
{
	fieldset_t *f = xcalloc(1, sizeof(fieldset_t));
	f->len = 0;
	f->type = FS_REPEATED;
	f->inner_type = type;
	f->free_ = free_;
	return f;
}

fieldset_t *fs_new_repeated_uint64(void)
{
	return fs_new_repeated_field(FS_UINT64, 0);
}


fieldset_t *fs_new_repeated_bool(void)
{
	return fs_new_repeated_field(FS_BOOL, 0);
}

fieldset_t *fs_new_repeated_string(int free_)
{
	return fs_new_repeated_field(FS_STRING, free_);
}

fieldset_t *fs_new_repeated_binary(int free_)
{
	return fs_new_repeated_field(FS_BINARY, free_);
}

fieldset_t *fs_new_repeated_fieldset(void)
{
	return fs_new_repeated_field(FS_FIELDSET, 0);
}


static inline void fs_add_word(fieldset_t *fs, const char *name, int type,
		int free_, size_t len, field_val_t value)
{
	if (fs->len + 1 >= MAX_FIELDS) {
		log_fatal("fieldset", "out of room in fieldset");
	}
	if (fs->type == FS_REPEATED && fs->inner_type != type) {
		log_fatal("fieldset", "object added to repeated field does not match type of repeated field.");
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

static char *sanitize_utf8(const char *buf)
{
	const char *ptr = buf;

	// Count how many errors we encounter
	uint32_t i = 0;
	// Upper bounds to ensure termination even if u8_check is unsafe
	while (i < strlen(buf) && ptr < buf + strlen(buf)) {
		ptr = (char*)u8_check((uint8_t*)ptr, strlen(ptr));
		if (ptr == NULL) {
			break;
		}

		assert(ptr >= buf);
		assert(ptr < buf + strlen(buf));

		ptr++;
		i++;
	}

	// i is the total number of errors. We need 2 extra bytes for each rune
	char *safe_buf = xmalloc(strlen(buf) + i*2 + 1);
	char *safe_ptr = NULL;
	memcpy(safe_buf, buf, strlen(buf));

	// Fix exactly i errors
	for (uint32_t j = 0; j < i; j++) {
		// Always operate on the working buffer
		safe_ptr = (char*)u8_check((uint8_t*)safe_buf, strlen(safe_buf));

		// This implies we had less errors than we should.
		// This is temporary debug code.
		if (safe_ptr == NULL) {
			log_warn("fieldset", "UTF8 Sanitization issue. %u errors, fell through iter %u. Orig: %s new: %s",
					i, j, buf, safe_buf);
			i = j;
			break;
		}

		// XXX Uncomment when we remove above log_warn.
		//assert(safe_ptr != NULL);
		assert(safe_ptr >= safe_buf);
		assert(safe_ptr < safe_buf + strlen(safe_buf));

		// Shift the rest of the string by 2 bytes
		if (strlen(safe_ptr) > 1) {
			memcpy(safe_ptr + 3, safe_ptr + 1, strlen(safe_ptr + 1));
		}

		// UTF8 replacement rune
		safe_ptr[0] = (char)0xef;
		safe_ptr[1] = (char)0xbf;
		safe_ptr[2] = (char)0xbd;
	}

	// We now have a valid utf8 string
	assert(u8_check((uint8_t*)safe_buf, strlen(safe_buf)) == NULL);
	// We should be null terminated
	assert(safe_buf[strlen(buf) + i*2] == '\0');
	// We should be the right length
	assert(strlen(safe_buf) == (strlen(buf) + i*2));

	return safe_buf;
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

void fs_add_unsafe_string(fieldset_t *fs, const char *name, char *value, int free_)
{
	if (u8_check((uint8_t*)value, strlen(value)) == NULL) {
		field_val_t val = { .ptr = value };
		fs_add_word(fs, name, FS_STRING, free_, strlen(value), val);
	} else {
		char* safe_value = sanitize_utf8(value);

		if (free_) {
			free(value);
		}

		field_val_t val = { .ptr = safe_value };
		fs_add_word(fs, name, FS_STRING, 1, strlen(safe_value), val);
	}
}

void fs_chkadd_string(fieldset_t *fs, const char *name, char *value, int free_)
{
	if (value) {
		fs_add_string(fs, name, value, free_);
	} else {
		fs_add_null(fs, name);
	}
}

void fs_chkadd_unsafe_string(fieldset_t *fs, const char *name, char *value, int free_)
{
	if (value) {
		fs_add_unsafe_string(fs, name, value, free_);
	} else {
		fs_add_null(fs, name);
	}
}


void fs_add_constchar(fieldset_t *fs, const char *name, const char *value)
{
	field_val_t val = { .ptr = (char*) value };
	fs_add_word(fs, name, FS_STRING, 0, strlen(value), val);
}

void fs_add_uint64(fieldset_t *fs, const char *name, uint64_t value)
{
	field_val_t val = { .num = value };
	fs_add_word(fs, name, FS_UINT64, 0, sizeof(uint64_t), val);
}

void fs_add_bool(fieldset_t *fs, const char *name, int value)
{
	field_val_t val = { .num = value };
	fs_add_word(fs, name, FS_BOOL, 0, sizeof(int), val);
}

void fs_add_binary(fieldset_t *fs, const char *name, size_t len,
		void *value, int free_)
{
	field_val_t val = { .ptr = value };
	fs_add_word(fs, name, FS_BINARY, free_, len, val);
}

void fs_add_fieldset(fieldset_t *fs, const char *name, fieldset_t *child)
{
	field_val_t val = { .ptr = child };
	fs_add_word(fs, name, FS_FIELDSET, 1, sizeof(void*), val);
}

void fs_add_repeated(fieldset_t *fs, const char *name, fieldset_t *child)
{
	field_val_t val = { .ptr = child };
	fs_add_word(fs, name, FS_REPEATED, 1, sizeof(void*), val);
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

void fs_modify_bool(fieldset_t *fs, const char *name, int value)
{
	field_val_t val = { .num = value };
	fs_modify_word(fs, name, FS_BOOL, 0, sizeof(int), val);
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

void field_free(field_t *f)
{
	if (f->type == FS_FIELDSET || f->type == FS_REPEATED) {
		fs_free((fieldset_t *) f->value.ptr);
	} else if (f->free_) {
		free(f->value.ptr);
	}
}

void fs_free(fieldset_t *fs)
{
	if (!fs) {
		return;
	}
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		field_free(f);
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

