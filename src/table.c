#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "config.h"

char *load_file(const char*path)
{
	FILE *f = fopen(path, "r");
	char *ptr, *new_ptr;
	off_t sz;
	size_t actual;
	
	if (!f)
		return NULL;
	
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	
	ptr = malloc(sz + 1);
	if (!ptr) {
		fclose(f);
		return NULL;
	}
	
	actual = fread(ptr, 1, sz, f);
	fclose(f);
	
	ptr[actual] = 0;
	new_ptr = realloc(ptr, actual + 1);
	
	if(new_ptr)
		return new_ptr;
	else
		return ptr;
}

static uint64_t fnv_1a(const char *str)
{
	uint64_t x = 0xcbf29ce484222325ULL;
	for (; *str; str++) {
		x ^= *str;
		x *= 0x100000001b3ULL;
	}
	return x;
}

#include "table.h"

struct table_entry {
	uint64_t key_hash;
	char *key;
	char *value;
};

struct table {
	const char *strings;
	struct table_entry *entries;
	size_t num_entries, load;
};

static int add_row(struct table *table, char *key, char *value);

struct table *load_table(const char *path)
{
	char *raw, *left, *right;
	struct table *table;
	int comment, white, line, more;
	
	raw = load_file(path);
	if (raw == NULL)
		return NULL;
	
	table = malloc(sizeof(*table));
	if (!table) {
		free(raw);
		return NULL;
	}
	
	table->strings = raw;
	table->num_entries = 0;
	table->load = 0;
	table->entries = NULL;
	
	comment = 0;
	white = 1;
	line = 1;
	more = 1;
	
	left = NULL;
	right = NULL;
	
	while (more) {
		switch (*raw) {
		case '\0':
			more = 0;
		case '\n':
			*raw = 0;
			
			if (!left)
				goto LINE_DONE;
			
			if (!right)
				goto ERROR;
			
			if (add_row(table, left, right))
				goto ERROR;
			
LINE_DONE:
			left = NULL;
			right = NULL;
			comment = 0;
			white = 1;
			line++;
			
			break;
			
		case '\t':
		case ' ':
			*raw = 0;
			white = 1;
			break;
			
		case '#':
			comment = 1;
			break;
			
		default:
			if (comment)
				break;
			
			if (white && left == NULL)
				left = raw;
			else if (white && right == NULL)
				right = raw;
			else if (white)
				goto ERROR;
			
			white = 0;
			break;
		}
		
		raw++;
	}
	
	return table;
ERROR:
	free_table(table);
	return NULL;
}

static int probe_insert(struct table_entry *table, size_t size, struct table_entry *entry);

static int expand_table(struct table *table)
{
	size_t new_size, i;
	struct table_entry *new_table;
	
	table->load++;
	if (table->num_entries * LOAD_FACTOR >= table->load)
		return 0;
	
	new_size = table->num_entries;
	if (new_size == 0)
		new_size = DEFAULT_TABLE_SIZE;
	else
		new_size *= EXPAND_FACTOR;
	
	new_table = malloc(new_size * sizeof(*new_table));
	if (!new_table)
		return 1;
	
	memset(new_table, 0, new_size * sizeof(*new_table));
	
	for (i = 0; i < table->num_entries; i++)
		if (table->entries[i].key != NULL)
			probe_insert(new_table, new_size, &table->entries[i]);
	
	free(table->entries);
	
	table->num_entries = new_size;
	table->entries = new_table;
	
	return 0;
}

static int add_row(struct table *table, char *key, char *value)
{
	struct table_entry entry = {fnv_1a(key), key, value};
	
	if (expand_table(table))
		return 1;
	
	return probe_insert(table->entries, table->num_entries, &entry);
}

static int probe_insert(struct table_entry *table, size_t size, struct table_entry *entry)
{
	size_t i = entry->key_hash % size;
	
	while (1) {
		if (table[i].key == NULL) {
			table[i] = *entry;
			break;
		}
		
		if (strcmp(table[i].key, entry->key) == 0)
			return 1;
		
		i++;
		if (i >= size)
			i -= size;
	}
	
	return 0;
}

const char *table_lookup(struct table *table, const char *name)
{
	uint64_t hash = fnv_1a(name) % table->num_entries;
	
	while (1) {
		if (table->entries[hash].key == NULL)
			return NULL;
		
		if (strcmp(table->entries[hash].key, name) == 0)
			return table->entries[hash].value;
		
		hash++;
		if (hash >= table->num_entries)
			hash -= table->num_entries;
	}
}

void free_table(struct table *table)
{
	if (table == NULL)
		return;
	
	free((void*)table->strings);
	free(table->entries);
	
	free(table);
}
