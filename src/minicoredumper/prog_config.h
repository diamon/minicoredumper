/*
 * Copyright (c) 2012-2018 Linutronix GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

struct interesting_prog {
	char *comm;
	char *exe;
	char *recept;

	struct interesting_prog *next;
};

struct interesting_buffer {
	char *symname;
	size_t data_len;
	bool follow_ptr;
	char *ident;

	struct interesting_buffer *next;
};

struct stack_config {
	bool dump_stacks;
	bool first_thread_only;
	size_t max_stack_size;
};

struct maps_config {
	char **name_globs;
	size_t nglobs;
};

struct prog_config {
	struct stack_config stack;
	struct maps_config maps;
	struct interesting_buffer *buffers;
	char *core_compressor;
	char *core_compressor_ext;
	bool core_in_tar;
	bool using_posix_format;
	bool core_compressed;
	bool dump_fat_core;
	bool dump_auxv_so_list;
	bool dump_pthread_list;
	bool dump_robust_mutex_list;
	bool write_proc_info;
	bool write_debug_log;
	bool live_dumper;
	unsigned int dump_scope;
};

struct config {
	char *base_dir;
	struct interesting_prog *ilist;
	struct prog_config prog_config;
};

const char *get_prog_recept(struct config *cfg, const char *comm,
			    const char *exe);
struct config *init_config(const char *cfg_file);
int init_prog_config(struct config *cfg, const char *cfg_file);
int simple_match(const char *pattern, const char *string);
void free_config(struct config *cfg);

#endif /* CONFIG_H */
