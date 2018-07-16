/*
 * Copyright (c) 2012-2018 Linutronix GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __CORESTRIPPER_H__
#define __CORESTRIPPER_H__

#include <stdio.h>
#include <libelf.h>
#include <gelf.h>

struct core_data;

/* dumpable vmas found in the core file */
struct core_vma {
	unsigned long start;
	unsigned long mem_end;
	unsigned long file_end;
	unsigned long file_off;
	unsigned int flags;

	struct core_vma *next;
};

struct interesting_vma {
	unsigned long start;
	unsigned long end;

	struct interesting_vma *next;
};

struct sym_data {
	unsigned long start;
	Elf *elf;
	GElf_Shdr shdr;
	Elf_Data *data;
	int fd;
	int count;

	struct sym_data *next;
};

struct dump_info {
	struct config *cfg;

	char *dst_dir;
	char *core_path;
	int mem_fd;
	int elf_fd;
	int core_fd;
	int fatcore_fd;

	off64_t core_offset;
	off64_t core_start_offset;
	int elfclass;
	FILE *info_file;

	struct sym_data *sym_data_list;

	/* from core_pattern */
	pid_t pid;
	uid_t uid;
	gid_t gid;
	pid_t first_pid;
	int signum;
	time_t timestamp;
	char *hostname;
	char *comm;

	/* /proc/$PID/exe */
	char *exe;

	pid_t *tsks;
	int ntsks;

	unsigned long vma_start;
	unsigned long vma_end;
	struct core_vma *vma;

	struct core_data *core_file;
	off64_t core_file_size;
};

int add_core_data(struct dump_info *di, off64_t dest_offset, size_t len,
		  int src_fd, off64_t src_offset);

#endif
