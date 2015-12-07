#ifndef TABLE_H
#define TABLE_H

struct table;

struct table *load_table(const char *path);
const char *table_lookup(struct table *table, const char *name);
void free_table(struct table *table);

#endif
