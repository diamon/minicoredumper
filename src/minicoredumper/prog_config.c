/*
 * Copyright (c) 2012-2018 Linutronix GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <json-c/json.h>

#include "prog_config.h"

void info(const char *fmt, ...);
void fatal(const char *fmt, ...);

static char *alloc_json_string(struct json_object *o)
{
	const char *v;

	if (!json_object_is_type(o, json_type_string))
		return NULL;

	v = json_object_get_string(o);
	if (!v)
		return NULL;

	return strdup(v);
}

static int get_json_int(struct json_object *o, int *i, bool nonneg)
{
	if (!json_object_is_type(o, json_type_int))
		return -1;

	*i = json_object_get_int(o);

	if (*i == INT32_MIN)
		return -1;

	if (*i == INT32_MAX)
		return -1;

	if (nonneg && *i < 0)
		return -1;

	return 0;
}

static int get_json_boolean(struct json_object *o, bool *b)
{
	if (!json_object_is_type(o, json_type_boolean))
		return -1;

	*b = json_object_get_boolean(o);

	return 0;
}

static int read_mapname_elems(struct json_object *root,
			      struct maps_config *cfg)
{
	int len;
	int i;

	if (!json_object_is_type(root, json_type_array))
		return -1;

	len = json_object_array_length(root);
	if (len < 1)
		return -1;

	/* allocate globs */
	cfg->name_globs = calloc(len, sizeof(char *));
	if (!cfg->name_globs)
		return -1;
	cfg->nglobs = len;

	for (i = 0; i < len; i++) {
		struct json_object *v;

		v = json_object_array_get_idx(root, i);
		if (!v)
			return -1;

		cfg->name_globs[i] = alloc_json_string(v);
		if (!cfg->name_globs[i])
			return -1;
	}

	return 0;
}

static int read_prog_map_config(struct json_object *root,
				struct prog_config *cfg)
{
	struct json_object_iterator it_end;
	struct json_object_iterator it;

	/* make sure it isn't already configured */
	if (cfg->maps.nglobs > 0)
		return -1;

	for (it = json_object_iter_begin(root),
	     it_end = json_object_iter_end(root);
	     !json_object_iter_equal(&it, &it_end);
	     json_object_iter_next(&it)) {

		struct json_object *v;
		const char *n;

		n = json_object_iter_peek_name(&it);
		if (!n)
			return -1;

		v = json_object_iter_peek_value(&it);
		if (!v)
			return -1;

		if (strcmp(n, "dump_by_name") == 0) {
			if (read_mapname_elems(v, &cfg->maps) != 0)
				return -1;

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	return 0;
}

static int read_prog_compression_config(struct json_object *root,
					struct prog_config *cfg)
{
	struct json_object_iterator it_end;
	struct json_object_iterator it;

	for (it = json_object_iter_begin(root),
	     it_end = json_object_iter_end(root);
	     !json_object_iter_equal(&it, &it_end);
	     json_object_iter_next(&it)) {

		struct json_object *v;
		const char *n;

		n = json_object_iter_peek_name(&it);
		if (!n)
			return -1;

		v = json_object_iter_peek_value(&it);
		if (!v)
			return -1;

		if (strcmp(n, "compressor") == 0) {
			if (cfg->core_compressor)
				free(cfg->core_compressor);

			cfg->core_compressor = alloc_json_string(v);
			if (!cfg->core_compressor)
				return -1;

		} else if (strcmp(n, "extension") == 0) {
			if (cfg->core_compressor_ext)
				free(cfg->core_compressor_ext);

			cfg->core_compressor_ext = alloc_json_string(v);
			if (!cfg->core_compressor_ext)
				return -1;

		} else if (strcmp(n, "in_tar") == 0) {
			if (get_json_boolean(v, &cfg->core_in_tar) != 0)
				return -1;

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	return 0;
}

static int read_buffer_item(struct json_object *root, struct prog_config *cfg)
{
	struct json_object_iterator it_end;
	struct json_object_iterator it;
	struct interesting_buffer *tmp;

	tmp = calloc(1, sizeof(*tmp));
	if (!tmp)
		return -1;

	for (it = json_object_iter_begin(root),
	     it_end = json_object_iter_end(root);
	     !json_object_iter_equal(&it, &it_end);
	     json_object_iter_next(&it)) {

		struct json_object *v;
		const char *n;

		n = json_object_iter_peek_name(&it);
		if (!n)
			goto out_err;

		v = json_object_iter_peek_value(&it);
		if (!v)
			goto out_err;

		if (strcmp(n, "symname") == 0) {
			tmp->symname = alloc_json_string(v);
			if (!tmp->symname)
				goto out_err;

		} else if (strcmp(n, "follow_ptr") == 0) {
			if (get_json_boolean(v, &tmp->follow_ptr) != 0)
				return -1;

		} else if (strcmp(n, "data_len") == 0) {
			int i;
			if (get_json_int(v, &i, true) != 0)
				return -1;
			tmp->data_len = i;

		} else if (strcmp(n, "ident") == 0) {
			tmp->ident = alloc_json_string(v);
			if (!tmp->ident)
				goto out_err;

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
	if (tmp->ident)
		free(tmp->ident);
	free(tmp);

	return -1;
}

static int read_prog_buffers_config(struct json_object *root,
				    struct prog_config *cfg)
{
	int len;
	int i;

	if (cfg->buffers)
		return -1;

	if (!json_object_is_type(root, json_type_array))
		return -1;

	len = json_object_array_length(root);
	if (len < 1)
		return -1;

	for (i = 0; i < len; i++) {
		struct json_object *v;

		v = json_object_array_get_idx(root, i);
		if (!v)
			return -1;

		if (read_buffer_item(v, cfg) != 0)
			return -1;
	}

	return 0;
}

static int read_prog_stack_config(struct json_object *root,
				  struct stack_config *cfg)
{
	struct json_object_iterator it_end;
	struct json_object_iterator it;

	for (it = json_object_iter_begin(root),
	     it_end = json_object_iter_end(root);
	     !json_object_iter_equal(&it, &it_end);
	     json_object_iter_next(&it)) {

		struct json_object *v;
		const char *n;

		n = json_object_iter_peek_name(&it);
		if (!n)
			return -1;

		v = json_object_iter_peek_value(&it);
		if (!v)
			return -1;

		if (strcmp(n, "dump_stacks") == 0) {
			if (get_json_boolean(v, &cfg->dump_stacks) != 0)
				return -1;

		} else if (strcmp(n, "first_thread_only") == 0) {
			if (get_json_boolean(v, &cfg->first_thread_only) != 0)
				return -1;

		} else if (strcmp(n, "max_stack_size") == 0) {
			int i;
			if (get_json_int(v, &i, true) != 0)
				return -1;
			cfg->max_stack_size = i;

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	return 0;
}

static int read_prog_config(struct json_object *root, struct prog_config *cfg)
{
	struct json_object_iterator it_end;
	struct json_object_iterator it;

	for (it = json_object_iter_begin(root),
	     it_end = json_object_iter_end(root);
	     !json_object_iter_equal(&it, &it_end);
	     json_object_iter_next(&it)) {

		struct json_object *v;
		const char *n;

		n = json_object_iter_peek_name(&it);
		if (!n)
			return -1;

		v = json_object_iter_peek_value(&it);
		if (!v)
			return -1;

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
			if (get_json_boolean(v,
					&cfg->dump_robust_mutex_list) != 0) {
				return -1;
			}

		} else if (strcmp(n, "dump_fat_core") == 0) {
			if (get_json_boolean(v, &cfg->dump_fat_core) != 0)
				return -1;

		} else if (strcmp(n, "dump_auxv_so_list") == 0) {
			if (get_json_boolean(v, &cfg->dump_auxv_so_list) != 0)
				return -1;

		} else if (strcmp(n, "dump_pthread_list") == 0) {
			if (get_json_boolean(v, &cfg->dump_pthread_list) != 0)
				return -1;

		} else if (strcmp(n, "dump_scope") == 0) {
			int i;
			if (get_json_int(v, &i, true) != 0)
				return -1;
			cfg->dump_scope = i;

		} else if (strcmp(n, "write_debug_log") == 0) {
			if (get_json_boolean(v, &cfg->write_debug_log) != 0)
				return -1;

		} else if (strcmp(n, "write_proc_info") == 0) {
			if (get_json_boolean(v, &cfg->write_proc_info) != 0)
				return -1;

		} else if (strcmp(n, "live_dumper") == 0) {
			if (get_json_boolean(v, &cfg->live_dumper) != 0)
				return -1;

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

static int read_watch_elem(struct json_object *root, struct config *cfg)
{
	struct json_object_iterator it_end;
	struct json_object_iterator it;
	struct interesting_prog *tail;
	struct interesting_prog *tmp;

	tmp = calloc(1, sizeof(*tmp));
	if (!tmp)
		return -1;

	for (it = json_object_iter_begin(root),
	     it_end = json_object_iter_end(root);
	     !json_object_iter_equal(&it, &it_end);
	     json_object_iter_next(&it)) {

		struct json_object *v;
		const char *n;

		n = json_object_iter_peek_name(&it);
		if (!n)
			goto out_err;

		v = json_object_iter_peek_value(&it);
		if (!v)
			goto out_err;

		if (strcmp(n, "exe") == 0) {
			tmp->exe = alloc_json_string(v);
			if (!tmp->exe)
				goto out_err;

		} else if (strcmp(n, "comm") == 0) {
			tmp->comm = alloc_json_string(v);
			if (!tmp->comm)
				goto out_err;

		} else if (strcmp(n, "recept") == 0) {
			char *s;

			s = alloc_json_string(v);
			if (!s)
				goto out_err;

			if (s[0] == '/') {
				/* absolute path */
				tmp->recept = s;
			} else {
				/* path relative to MCD_CONF_PATH */
				if (asprintf(&tmp->recept, MCD_CONF_PATH "/%s",
					     s) < 1) {
					tmp->recept = NULL;
				}
				free(s);
				if (!tmp->recept)
					goto out_err;
			}

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

static int read_base_config(struct json_object *root, struct config *cfg)
{
	struct json_object_iterator it_end;
	struct json_object_iterator it;

	cfg->ilist = NULL;

	for (it = json_object_iter_begin(root),
	     it_end = json_object_iter_end(root);
	     !json_object_iter_equal(&it, &it_end);
	     json_object_iter_next(&it)) {

		struct json_object *v;
		const char *n;

		n = json_object_iter_peek_name(&it);
		if (!n)
			return -1;

		v = json_object_iter_peek_value(&it);
		if (!v)
			return -1;

		if (strcmp(n, "watch") == 0) {
			int len;
			int i;

			if (!json_object_is_type(v, json_type_array))
				return -1;

			len = json_object_array_length(v);
			if (len < 1)
				return -1;

			for (i = 0; i < len; i++) {
				struct json_object *v2;

				v2 = json_object_array_get_idx(v, i);
				if (!v2)
					return -1;

				if (read_watch_elem(v2, cfg) != 0)
					return -1;
			}

		} else if (strcmp(n, "base_dir") == 0) {
			cfg->base_dir = alloc_json_string(v);
			if (!cfg->base_dir)
				return -1;

		} else {
			info("WARNING: ignoring unknown config item: %s", n);
		}
	}

	return 0;
}

struct config *init_config(const char *cfg_file)
{
	struct json_object *o;
	struct config *cfg;

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg)
		return NULL;
	o = json_object_from_file(cfg_file);
	if (!o) {
		fatal("unable to parse config file: %s", strerror(errno));
		free(cfg);
		return NULL;
	}

	if (read_base_config(o, cfg) < 0) {
		fatal("unable to read base config");
		free(cfg);
		cfg = NULL;
	}

	json_object_put(o);

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

	/* do not dump non-crashing registered applications */
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
	struct json_object *o;
	int ret;

	set_config_defaults(&cfg->prog_config);

	/* recept "" means use defaults */
	if (cfg_file[0] == 0)
		return 0;

	o = json_object_from_file(cfg_file);
	if (!o) {
		fatal("unable to parse recept file: %s", strerror(errno));
		return -1;
	}

	ret = read_prog_config(o, &cfg->prog_config);

	json_object_put(o);

	return ret;
}

void free_config(struct config *cfg)
{
	struct interesting_buffer *buf;
	struct interesting_prog *prog;
	int i;

	if (cfg->base_dir)
		free(cfg->base_dir);

	while (cfg->ilist) {
		prog = cfg->ilist;
		cfg->ilist = prog->next;
		if (prog->exe)
			free(prog->exe);
		if (prog->comm)
			free(prog->comm);
		if (prog->recept)
			free(prog->recept);
		free(prog);
	}

	for (i = 0; i < cfg->prog_config.maps.nglobs; i++)
		free(cfg->prog_config.maps.name_globs[i]);
	if (cfg->prog_config.maps.name_globs)
		free(cfg->prog_config.maps.name_globs);

	while (cfg->prog_config.buffers) {
		buf = cfg->prog_config.buffers;
		cfg->prog_config.buffers = buf->next;
		if (buf->symname)
			free(buf->symname);
		if (buf->ident)
			free(buf->ident);
		free(buf);
	}

	if (cfg->prog_config.core_compressor)
		free(cfg->prog_config.core_compressor);
	if (cfg->prog_config.core_compressor_ext)
		free(cfg->prog_config.core_compressor_ext);

	free(cfg);
}
