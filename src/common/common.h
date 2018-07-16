/*
 * Copyright (c) 2012-2018 Linutronix GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
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
