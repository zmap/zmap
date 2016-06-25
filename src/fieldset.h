/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdint.h>
#include "types.h"

#ifndef FIELDSET_H
#define FIELDSET_H

// maximum number of records that can be stored in a fieldset
#define MAX_FIELDS 128
#define MAX_LIST_LENGTH 255

// types of data that can be stored in a field
#define FS_RESERVED 0
#define FS_STRING 1
#define FS_UINT64 2
#define FS_BINARY 3
#define FS_NULL 4
#define FS_BOOL 7
// recursive support
#define FS_FIELDSET 5
#define FS_REPEATED 6

// definition of a field that's provided by a probe module
// these are used so that users can ask at the command-line
// what fields are available for consumption
typedef struct field_def {
	const char *name;
	const char *type;
	const char *desc;
} fielddef_t;

typedef struct fielddef_set {
	fielddef_t fielddefs[MAX_FIELDS];
	int len;
} fielddefset_t;

typedef union field_val {
	void	  *ptr;
	uint64_t   num;
} field_val_t;

// the internal field type used by fieldset
typedef struct field {
	const char *name;
	int type;
	int free_;
	size_t len;
	field_val_t value;
} field_t;

// data structure that is populated by the probe module
// and translated into the data structure that's passed
// to the output module
typedef struct fieldset {
	int len;
	field_t fields[MAX_FIELDS];
    // only used for repeated.
    int inner_type; // type of repeated element. e.g., FS_STRING
    int type; // REPEATED or FIELDSET
    int free_; // should elements be freed
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

fieldset_t *fs_new_fieldset(void);

fieldset_t *fs_new_repeated_field(int type, int free_);
fieldset_t *fs_new_repeated_uint64(void);
fieldset_t *fs_new_repeated_bool(void);
fieldset_t *fs_new_repeated_string(int free_);
fieldset_t *fs_new_repeated_binary(int free_);
fieldset_t *fs_new_repeated_fieldset();

char* fs_get_string_by_index(fieldset_t *fs, int index);

int fds_get_index_by_name(fielddefset_t *fds, char *name);

void gen_fielddef_set(fielddefset_t *fds, fielddef_t fs[], int len);

void fs_add_null(fieldset_t *fs, const char *name);

void fs_add_uint64(fieldset_t *fs, const char *name, uint64_t value);

void fs_add_bool(fieldset_t *fs, const char *name, int value);

void fs_add_string(fieldset_t *fs, const char *name, char *value, int free_);

void fs_add_unsafe_string(fieldset_t *fs, const char *name, char *value, int free_);

void fs_chkadd_string(fieldset_t *fs, const char *name, char *value, int free_);

void fs_chkadd_unsafe_string(fieldset_t *fs, const char *name, char *value, int free_);

void fs_add_constchar(fieldset_t *fs, const char *name, const char *value);

void fs_add_binary(fieldset_t *fs, const char *name, size_t len,
		void *value, int free_);

void fs_add_fieldset(fieldset_t *fs, const char *name, fieldset_t *child);
void fs_add_repeated(fieldset_t *fs, const char *name, fieldset_t *child);

// Modify
void fs_modify_null(fieldset_t *fs, const char *name);

void fs_modify_uint64(fieldset_t *fs, const char *name, uint64_t value);

void fs_modify_bool(fieldset_t *fs, const char *name, int value);

void fs_modify_string(fieldset_t *fs, const char *name, char *value, int free_);

void fs_modify_binary(fieldset_t *fs, const char *name, size_t len,
		void *value, int free_);

uint64_t fs_get_uint64_by_index(fieldset_t *fs, int index);

void fs_free(fieldset_t *fs);

void fs_generate_fieldset_translation(translation_t *t,
		fielddefset_t *avail, char** req, int reqlen);

fieldset_t *translate_fieldset(fieldset_t *fs, translation_t *t);

void fs_generate_full_fieldset_translation(translation_t *t, fielddefset_t *avail);

#endif // FIELDSET_H

