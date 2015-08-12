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

#ifndef __CORESTRIPPER_H__
#define __CORESTRIPPER_H__

#include <libelf.h>
#include <gelf.h>

/* dumpable vmas found in the core file */
struct core_vma {
	unsigned long start;
	unsigned long mem_end;
	unsigned long file_end;
	unsigned long file_off;
	unsigned int flags;

	struct core_vma *next;
};

struct core_data {
	off64_t start;
	off64_t end;

	off64_t mem_start;
	int mem_fd;

	int blk_id;

	struct core_data *next;
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
	int core_fd;
	int fatcore_fd;

	off_t core_offset;
	off_t core_start_offset;
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

#endif
