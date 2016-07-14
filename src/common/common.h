/*
 * Copyright (c) 2012-2016 Ericsson AB
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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>

struct dump_data_elem;
struct mcd_dump_data;

struct core_data {
	off64_t start;
	off64_t end;

	off64_t mem_start;
	int mem_fd;

	int blk_id;

	struct core_data *next;
};

struct remote_data_callbacks {
	void *(*setup_data)(struct dump_data_elem *, void *);
	void (*cleanup_data)(void *);
	void *cbdata;
};

extern int dump_data_file_text(struct mcd_dump_data *dd, FILE *file,
			       struct remote_data_callbacks *cb);

extern int copy_file(const char *dest, const char *src);

extern int add_dump_list(int core_fd, size_t *core_size,
			 struct core_data *dump_list, off64_t *dump_offset);

#endif /* __COMMON_H__ */
