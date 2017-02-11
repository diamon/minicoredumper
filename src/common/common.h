/*
 * Copyright (c) 2012-2016 Linutronix GmbH
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
#include <pthread.h>
#include <inttypes.h>

#define MCD_SOCK_PATH "minicoredumper"
#define MCD_SHM_PATH "/minicoredumper.shm"

#define MCD_REGISTER	1
#define MCD_UNREGISTER	2
#define MCD_SHUTDOWN	3

struct mcd_regdata {
	uint32_t req;
	uint32_t data;
};

struct mcd_shm_head {
	uint32_t head_size;
	uint32_t item_size;
	uint32_t count;
	pthread_mutex_t m;
};

struct mcd_shm_item {
	pid_t pid;
	uint32_t data;
};

struct core_data {
	off64_t start;
	off64_t end;

	off64_t mem_start;
	int mem_fd;

	int blk_id;

	struct core_data *next;
};

extern int invalid_ident(const char *ident);

extern int add_dump_list(int core_fd, size_t *core_size,
			 struct core_data *dump_list, off64_t *dump_offset);

#endif /* __COMMON_H__ */
