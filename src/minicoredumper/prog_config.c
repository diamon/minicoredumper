/*
 * Copyright (c) 2012-2015 Ericsson AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include "prog_config.h"
#include "json.h"

void info(const char *fmt, ...);
void fatal(const char *fmt, ...);

static json_value *parse_json_file(const char *file, char *msg, size_t msize)
{
	json_value *v = NULL;
	json_settings js;
	struct stat st;
	char *json;
	int fd;

	memset(&js, 0, sizeof(js));

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		snprintf(msg, msize, "open: %m");
		goto out;
	}

	if (fstat(fd, &st) != 0) {
		snprintf(msg, msize, "lstat: %m");
		goto out;
	}

	if (st.st_size < 1) {
		snprintf(msg, msize, "file empty");
		goto out;
	}

	json = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (json == MAP_FAILED) {
		snprintf(msg, msize, "mmap: %m");
		goto out;
	}

	v = json_parse_ex(&js, json, st.st_size, msg);

	munmap(json, st.st_size);
out:
	if (fd >= 0)
		close(fd);

	return v;
}

static int read_mapname_elems(json_value *v_root, struct maps_config *cfg)
{
	unsigned int i = v_root->u.array.length;

	/* allocate globs */
	cfg->name_globs = calloc(i, sizeof(char *));
	if (!cfg->name_globs)
		return -1;
	cfg->nglobs = i;

	/* add to list elements from json file */
	for (i = 0; i < v_root->u.array.length; i++) {
		json_value *v = v_root->u.array.values[i];
		if (v->type != json_string)
			return -1;

		cfg->name_globs[i] = strdup(v->u.string.ptr);
		if (!cfg->name_globs[i])
			return -1;
	}

	return 0;
}

static int read_prog_map_config(json_value *v_root, struct prog_config *cfg)
{
	unsigned int i;

	if (v_root->type != json_object)
		return -1;

	/* make sure it isn't already configured */
	if (cfg->maps.nglobs > 0)
		return -1;

	for (i = 0; i < v_root->u.object.length; i++) {
		json_value *v = v_root->u.object.values[i].value;
		const char *n = v_root->u.object.values[i].name;

		if (strcmp(n, "dump_by_name") == 0) {
			if (v->type != json_array)
				return -1;

			if (read_mapname_elems(v, &cfg->maps) != 0)
				return -1;

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	return 0;
}

static int read_prog_compression_config(json_value *v_root,
					struct prog_config *cfg)
{
	unsigned int i;

	if (v_root->type != json_object)
		return -1;

	for (i = 0; i < v_root->u.object.length; i++) {
		json_value *v = v_root->u.object.values[i].value;
		const char *n = v_root->u.object.values[i].name;

		if (strcmp(n, "compressor") == 0) {
			if (v->type != json_string)
				return -1;
			if (cfg->core_compressor)
				free(cfg->core_compressor);
			cfg->core_compressor = strdup(v->u.string.ptr);
			if (!cfg->core_compressor)
				return -1;

		} else if (strcmp(n, "extension") == 0) {
			if (v->type != json_string)
				return -1;
			if (cfg->core_compressor_ext)
				free(cfg->core_compressor_ext);
			cfg->core_compressor_ext = strdup(v->u.string.ptr);
			if (!cfg->core_compressor_ext)
				return -1;
	
		} else if (strcmp(n, "in_tar") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->core_in_tar = v->u.boolean;
	
		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	return 0;
}

static int read_buffer_item(json_value *v_root, struct prog_config *cfg)
{
	struct interesting_buffer *tmp;
	unsigned int i;

	tmp = calloc(1, sizeof(*tmp));
	if (!tmp)
		return -1;

	for (i = 0; i < v_root->u.object.length; i++) {
		json_value *v = v_root->u.object.values[i].value;
		const char *n = v_root->u.object.values[i].name;

		if (strcmp(n, "symname") == 0) {
			if (v->type != json_string)
				goto out_err;

			tmp->symname = strdup(v->u.string.ptr);
			if (!tmp->symname)
				goto out_err;

		} else if (strcmp(n, "follow_ptr") == 0) {
			if (v->type != json_boolean)
				goto out_err;
			tmp->follow_ptr = v->u.boolean;

		} else if (strcmp(n, "data_len") == 0) {
			if (v->type != json_integer)
				goto out_err;
			tmp->data_len = v->u.integer;

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	/* push to front of list */
	tmp->next = cfg->buffers;
	cfg->buffers = tmp;

	return 0;
out_err:
	if (tmp->symname)
		free(tmp->symname);
	free(tmp);

	return -1;
}

static int read_prog_buffers_config(json_value *v_root,
				    struct prog_config *cfg)
{
	unsigned int i;

	if (v_root->type != json_array)
		return -1;

	if (cfg->buffers)
		return -1;

	for (i = 0; i < v_root->u.array.length; i++) {
		json_value *v = v_root->u.array.values[i];

		if (v->type != json_object)
			return -1;

		if (read_buffer_item(v, cfg) != 0)
			return -1;
	}

	return 0;
}

static int read_prog_stack_config(json_value *v_root, struct stack_config *cfg)
{
	unsigned int i;

	if (v_root->type != json_object)
		return -1;

	for (i = 0; i < v_root->u.object.length; i++) {
		json_value *v = v_root->u.object.values[i].value;
		const char *n = v_root->u.object.values[i].name;

		if (strcmp(n, "dump_stacks") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->dump_stacks = v->u.boolean;

		} else if (strcmp(n, "first_thread_only") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->first_thread_only = v->u.boolean;

		} else if (strcmp(n, "max_stack_size") == 0) {
			if (v->type != json_integer)
				return -1;
			cfg->max_stack_size = v->u.integer;

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	return 0;
}

static int read_prog_config(json_value *v_root, struct prog_config *cfg)
{
	unsigned int i;

	if (v_root->type != json_object)
		return -1;

	for (i = 0; i < v_root->u.object.length; i++) {
		const char *n = v_root->u.object.values[i].name;
		json_value *v = v_root->u.object.values[i].value;

		if (strcmp(n, "stacks") == 0) {
			if (read_prog_stack_config(v, &cfg->stack) != 0)
				return -1;

		} else if (strcmp(n, "buffers") == 0) {
			if (read_prog_buffers_config(v, cfg) != 0)
				return -1;

		} else if (strcmp(n, "maps") == 0) {
			if (read_prog_map_config(v, cfg) != 0)
				return -1;

		} else if (strcmp(n, "compression") == 0) {
			if (read_prog_compression_config(v, cfg) != 0)
				return -1;

		} else if (strcmp(n, "dump_robust_mutex_list") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->dump_robust_mutex_list = v->u.boolean;

		} else if (strcmp(n, "dump_fat_core") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->dump_fat_core = v->u.boolean;

		} else if (strcmp(n, "dump_auxv_so_list") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->dump_auxv_so_list = v->u.boolean;

		} else if (strcmp(n, "dump_pthread_list") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->dump_pthread_list = v->u.boolean;

		} else if (strcmp(n, "dump_scope") == 0) {
			if (v->type != json_integer)
				return -1;
			cfg->dump_scope = v->u.integer;

		} else if (strcmp(n, "write_debug_log") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->write_debug_log = v->u.boolean;

		} else if (strcmp(n, "write_proc_info") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->write_proc_info = v->u.boolean;

		} else if (strcmp(n, "live_dumper") == 0) {
			if (v->type != json_boolean)
				return -1;
			cfg->live_dumper = v->u.boolean;

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	return 0;
}

/* match '*' to 0 or more characters */
int simple_match(const char *pattern, const char *string)
{
	if (*pattern == 0 && *string == 0) {
		/* reached the end of both strings => match! */
		return 0;
	}

	/* handle wildcard */
	if (*pattern == '*') {
		/* skip consecutive wildcards */
		while (*(pattern + 1) == '*')
			pattern++;

		/* characters after a wildcard must be present in string */
		if (*(pattern + 1) != 0 && *string == 0)
			return -1;

		/* try ignoring wildcard */
		if (simple_match(pattern + 1, string) == 0)
			return 0;

		/* try matching string character with wildcard */
		if (simple_match(pattern, string + 1) == 0)
			return 0;

		return -1;
	}

	/* handle non-wildcard */
	if (*pattern != *string)
		return -1;

	/* continue matching */
	return simple_match(pattern + 1, string + 1);
}

const char *get_prog_recept(struct config *cfg, const char *comm,
			    const char *exe)
{
	struct interesting_prog *tmp;

	for (tmp = cfg->ilist; tmp; tmp = tmp->next) {
		/* both not defined = everything matches */
		if (!tmp->comm && !tmp->exe)
			return tmp->recept;

		/* both defined = both rules must match */
		if (tmp->comm && tmp->exe) {
			if (simple_match(tmp->comm, comm) == 0 &&
			    simple_match(tmp->exe, exe) == 0) {
				return tmp->recept;
			}
			continue;
		}

		/* match only against comm */
		if (tmp->comm) {
			if (simple_match(tmp->comm, comm) == 0)
				return tmp->recept;
			continue;
		}

		/* match only against exe */
		if (tmp->exe) {
			if (simple_match(tmp->exe, exe) == 0)
				return tmp->recept;
			continue;
		}
	}

	/* no match */
	return NULL;
}

static int read_watch_elem(json_value *v_root, struct config *cfg)
{
	struct interesting_prog *tail;
	struct interesting_prog *tmp;
	unsigned int i;

	tmp = calloc(1, sizeof(*tmp));
	if (!tmp)
		return -1;

	for (i = 0; i < v_root->u.object.length; i++) {
		const char *n = v_root->u.object.values[i].name;
		json_value *v = v_root->u.object.values[i].value;

		if (strcmp(n, "exe") == 0) {
			if (v->type != json_string)
				goto out_err;
			tmp->exe = strdup(v->u.string.ptr);

		} else if (strcmp(n, "comm") == 0) {
			if (v->type != json_string)
				goto out_err;
			tmp->comm = strdup(v->u.string.ptr);

		} else if (strcmp(n, "recept") == 0) {
			if (v->type != json_string)
				goto out_err;
			tmp->recept = strdup(v->u.string.ptr);

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	/* no recept = use defaults */
	if (!tmp->recept)
		tmp->recept = strdup("");

	/* new item must be appended because rules are ordered */

	if (!cfg->ilist) {
		/* add new item to head */
		cfg->ilist = tmp;

	} else {
		/* find the end of the list */
		for (tail = cfg->ilist; tail->next; tail = tail->next)
			/* NOP */;

		/* add new item to tail */
		tail->next = tmp;
	}

	return 0;
out_err:
	if (tmp->exe)
		free(tmp->exe);
	if (tmp->comm)
		free(tmp->comm);
	if (tmp->recept)
		free(tmp->recept);
	free(tmp);

	return -1;
}

static int read_base_config(json_value *v_root, struct config *cfg)
{
	unsigned int i;

	cfg->ilist = NULL;

	if (v_root->type != json_object)
		return -1;

	for (i = 0; i < v_root->u.object.length; i++) {
		const char *n = v_root->u.object.values[i].name;
		json_value *v = v_root->u.object.values[i].value;

		if (strcmp(n, "watch") == 0) {
			unsigned int j;

			if (v->type != json_array)
				return -1;

			for (j = 0; j < v->u.array.length; j++) {
				json_value *v2 = v->u.array.values[j];
				if (v2->type != json_object)
					return -1;
				if (read_watch_elem(v2, cfg) != 0)
					return -1;
			}

		} else if (strcmp(n, "base_dir") == 0) {
			if (v->type != json_string)
				return -1;
			cfg->base_dir = strdup(v->u.string.ptr);

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	return 0;
}

struct config *init_config(const char *cfg_file)
{
	struct config *cfg;
	json_value *v;
	char err[json_error_max] = { 0 };

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg)
		return NULL;
	v = parse_json_file(cfg_file, err, sizeof(err));
	if (!v) {
		fatal("unable to parse config file: %s", err);
		free(cfg);
		return NULL;
	}

	if (read_base_config(v, cfg) < 0) {
		fatal("unable to read base config");
		free(cfg);
		cfg = NULL;
	}

	json_value_free(v);
	return cfg;
}

static void set_config_defaults(struct prog_config *cfg)
{
	/* dump stacks */
	cfg->stack.dump_stacks = true;
	cfg->stack.first_thread_only = false;
	cfg->stack.max_stack_size = 0;

	/* dump everything gdb likes */
	cfg->dump_auxv_so_list = true;
	cfg->dump_pthread_list = true;
	cfg->dump_robust_mutex_list = true;

	/* no dbus notification */
	cfg->live_dumper = false;

	/* no debugging data */
	cfg->write_proc_info = false;
	cfg->write_debug_log = false;
	cfg->dump_fat_core = false;

	/* dump everything */
	cfg->dump_scope = -1;

	/* for compression, pack in tarball */
	cfg->core_in_tar = true;
}

int init_prog_config(struct config *cfg, const char *cfg_file)
{
	json_value *v;
	char err[json_error_max] = { 0 };
	int ret;

	set_config_defaults(&cfg->prog_config);

	/* recept "" means use defaults */
	if (cfg_file[0] == 0)
		return 0;

	v = parse_json_file(cfg_file, err, sizeof(err));
	if (!v) {
		fatal("unable to parse recept file: %s", err);
		return -1;
	}

	ret = read_prog_config(v, &cfg->prog_config);

	json_value_free(v);

	return ret;
}
