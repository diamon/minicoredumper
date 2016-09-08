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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <syslog.h>
#include <fcntl.h>
#include <printf.h>
#include <stddef.h>
#include <limits.h>
#include <inttypes.h>
#include <link.h>
#include <gelf.h>
#include <thread_db.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <linux/futex.h>
#include <elfutils/version.h>

#include "prog_config.h"
#include "dump_data_private.h"
#include "minicoredumper.h"
#include "common.h"
#include "corestripper.h"

/* /BASEDIR/IMAGE.TIMESTAMP.PID */
#define CORE_DIR_FMT "%s/%s.%s.%i"

#if _ELFUTILS_PREREQ(0, 167)
#define SUPPORT_LIBELF_MODIFY
#endif

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif

extern int start_dbus_gloop(struct dump_info *di, char *app_name);

static struct dump_info *global_di;
static long PAGESZ;

void info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR | LOG_USER, fmt, ap);
	va_end(ap);

	if (global_di->info_file) {
		va_start(ap, fmt);
		vfprintf(global_di->info_file, fmt, ap);
		va_end(ap);
		fprintf(global_di->info_file, "\n");
		fflush(global_di->info_file);
	}
}

void fatal(const char *fmt, ...)
{
	va_list ap;
	char *msg;

	if (asprintf(&msg, "FATAL ERROR: %s", fmt) == -1)
		exit(1);

	va_start(ap, fmt);
	vsyslog(LOG_ERR | LOG_USER, msg, ap);
	va_end(ap);

	if (global_di->info_file) {
		va_start(ap, fmt);
		vfprintf(global_di->info_file, msg, ap);
		va_end(ap);
		fprintf(global_di->info_file, "\n");
		fflush(global_di->info_file);
	}

	exit(1);
}

static ssize_t read_file_fd(int fd, char *dst, int len)
{
	size_t size = 0;
	int r;

	do {
		r = read(fd, dst + size, len);
		if (r == -1) {
			info("Couldn't read file fd=%d; error %s", fd,
			     strerror(errno));
			return r;
		}

		if (r > 0) {
			size += r;
			len -= r;
		}
	} while (len > 0);

	return size;
}

static ssize_t write_file_fd(int fd, char *src, int len)
{
	size_t size = 0;
	int r;

	do {
		r = write(fd, src + size, len);
		if (r == -1) {
			info("Couldn't write file fd=%d error %s", fd,
			     strerror (errno));
			return r;
		}
		if (r > 0) {
			size += r;
			len -= r;
		}
	} while (len > 0);

	return size;
}

static void check_config(struct config *cfg)
{
	if (!cfg->base_dir)
		fatal("no base_dir set in config file");
}

static int get_task_list(struct dump_info *di)
{
	pid_t *pidlist = NULL;
	struct dirent *de;
	int count = 0;
	char buf[64];
	int err = 0;
	int pid;
	DIR *d;
	int i;

	di->tsks = NULL;
	di->ntsks = 0;

	snprintf(buf, sizeof(buf), "/proc/%d/task", di->pid);

	d = opendir(buf);
	if (!d)
		return 1;

	/* count the number of tasks */
	while (1) {
		de = readdir(d);
		if (!de)
			break;

		/* ignore hidden files */
		if (de->d_name[0] == '.')
			continue;

		count++;
	}

	if (count == 0)
		goto out;

	pidlist = calloc(count, sizeof(pid_t));
	if (!pidlist) {
		err = 1;
		goto out;
	}

	rewinddir(d);

	/* read the actual tasks */
	for (i = 0; i < count; ) {
		de = readdir(d);
		if (!de) {
			err = 1;
			goto out;
		}

		/* ignore hidden files */
		if (de->d_name[0] == '.')
			continue;

		if (sscanf(de->d_name, "%d", &pid) != 1) {
			err = 1;
			goto out;
		}

		pidlist[i] = pid;

		i++;
	}

	/* make sure we really have exactly "count" tasks */
	if (readdir(d) != NULL) {
		err = 1;
		goto out;
	}

	di->tsks = pidlist;
	pidlist = NULL;
	di->ntsks = count;
out:
	closedir(d);

	if (pidlist)
		free(pidlist);

	return err;
}

static char *alloc_comm(char *arg, pid_t pid)
{
	char *tmp_path;
	FILE *f;
	char *p;

	if (!arg)
		return NULL;

	if (arg[0] != 0)
		return strdup(arg);

	if (pid == 0)
		return NULL;

	if (asprintf(&tmp_path, "/proc/%i/comm", pid) == -1)
		return NULL;

	f = fopen(tmp_path, "r");
	free(tmp_path);
	if (!f)
		return NULL;

	p = calloc(1, PATH_MAX + 1);
	if (!p) {
		fclose(f);
		return NULL;
	}

	fread(p, PATH_MAX, 1, f);
	if (ferror(f) || p[0] == 0) {
		free(p);
		fclose(f);
		return NULL;
	}

	fclose(f);

	return p;
}

static char *alloc_exe(pid_t pid)
{
	char *tmp_path;
	char *exe;
	int ret;

	if (pid == 0)
		return NULL;

	exe = malloc(PATH_MAX + 1);
	if (!exe)
		return NULL;

	if (asprintf(&tmp_path, "/proc/%i/exe", pid) == -1) {
		free(exe);
		return NULL;
	}

	ret = readlink(tmp_path, exe, PATH_MAX + 1);
	if (ret < 0 || ret > PATH_MAX) {
		info("readlink on \'%s\' failed", tmp_path);
		free(tmp_path);
		free(exe);
		return NULL;
	}
	free(tmp_path);
	/* readlink does not terminate the string */
	exe[ret] = 0;

	return exe;
}

static char *alloc_dst_dir(time_t timestamp, const char *base_dir,
			   const char *comm_base, pid_t pid)
{
	char timestamp_str[sizeof("YYYYMMDD.HHMMSS+0000")];
	char *tmp_path;
	struct tm tm;

	/* compute timestamp string */
	if (localtime_r(&timestamp, &tm) == NULL) {
		time(&timestamp);
		info("failed to interpret timestamp, falling back to now");
		if (localtime_r(&timestamp, &tm) == NULL) {
			info("localtime_r failed");
			return NULL;
		}
	}

	if (strftime(timestamp_str, sizeof(timestamp_str), "%Y%m%d.%H%M%S%z",
		     &tm) == 0) {
		info("strftime failed");
		return NULL;
	}

	if (asprintf(&tmp_path, CORE_DIR_FMT, base_dir, comm_base,
		     timestamp_str, pid) == -1) {
		return NULL;
	}

	if (mkdir(tmp_path, 0700) == -1) {
		info("unable to create directory \'%s\': %s", tmp_path,
		     strerror(errno));
		free(tmp_path);
		return NULL;
	}

	return tmp_path;
}

static int init_di(struct dump_info *di, int argc, char *argv[])
{
	const char *recept;
	char *comm_base;
	char *tmp_path;
	char *p;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		info("elf_version EV_NONE");
		return 1;
	}

	di->mem_fd = -1;
	di->elf_fd = -1;
	di->core_fd = -1;
	di->fatcore_fd = -1;

	di->pid = strtol(argv[1], &p, 10);
	if (*p != 0)
		return 1;

	di->uid = strtol(argv[2], &p, 10);
	if (*p != 0)
		return 1;

	di->gid = strtol(argv[3], &p, 10);
	if (*p != 0)
		return 1;

	di->signum = strtol(argv[4], &p, 10);
	if (*p != 0)
		return 1;

	di->timestamp = strtol(argv[5], &p, 10);
	if (*p != 0)
		return 1;

	di->hostname = argv[6];
	if (!di->hostname)
		return 1;

	di->comm = alloc_comm(argv[7], di->pid);
	if (!di->comm)
		return 1;

	di->exe = alloc_exe(di->pid);
	if (!di->exe)
		return 1;

	if (argc == 8) {
		di->cfg = init_config("/etc/minicoredumper/"
				      "minicoredumper.cfg.json");
	} else if (argc == 9) {
		info("using custom minicoredumper cfg: %s", argv[8]);
		di->cfg = init_config(argv[8]);
	} else {
		fatal("wrong arg count, check /proc/sys/kernel/core_pattern");
	}

	if (!di->cfg)
		fatal("unable to init config");

	check_config(di->cfg);

	info("comm: %s", di->comm);
	info("exe: %s", di->exe);

	recept = get_prog_recept(di->cfg, di->comm, di->exe);
	if (!recept)
		return 2;

	info("recept: %s", recept[0] == 0 ? "(defaults)" : recept);

	if (init_prog_config(di->cfg, recept) != 0)
		return 1;

	/* get basename of command for base_dir */
	comm_base = di->comm;
	while (1) {
		p = strchr(comm_base, '/');
		if (!p)
			break;
		comm_base = p + 1;
	}

	if (get_task_list(di) != 0)
		return 1;

	if (di->signum != 0) {
		if (asprintf(&tmp_path, "/core-%s-%d", comm_base,
			     di->pid) == -1) {
			return 1;
		}

		di->elf_fd = shm_open(tmp_path, O_CREAT|O_EXCL|O_RDWR,
				      S_IRUSR|S_IWUSR);
		if (di->elf_fd < 0) {
			info("unable to create shared object \'%s\': %s", tmp_path,
			     strerror(errno));
			free(tmp_path);
			return 1;
		}
		shm_unlink(tmp_path);
		free(tmp_path);

		if (asprintf(&tmp_path, "%s/core", di->dst_dir) == -1)
			return 1;
		di->core_path = tmp_path;

		di->core_fd = open(di->core_path, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
		if (di->core_fd < 0) {
			info("unable to create core \'%s\': %s", di->core_path,
			     strerror(errno));
			return 1;
		}
	} else {
		/* disable core-related dumping */
		di->cfg->prog_config.dump_fat_core = 0;
		di->cfg->prog_config.dump_auxv_so_list = 0;
		di->cfg->prog_config.dump_pthread_list = 0;
		di->cfg->prog_config.dump_robust_mutex_list = 0;
		di->cfg->prog_config.stack.dump_stacks = 0;
		di->cfg->prog_config.write_debug_log = 0;
	}

	if (di->cfg->prog_config.dump_fat_core) {
		if (asprintf(&tmp_path, "%s/fatcore", di->dst_dir) == -1)
			return 1;

		di->fatcore_fd = open(tmp_path, O_CREAT|O_RDWR,
				      S_IRUSR|S_IWUSR);
		if (di->fatcore_fd < 0) {
			info("unable to create fatcore \'%s\': %s", tmp_path,
			     strerror(errno));
			free(tmp_path);
			return 1;
		}

		free(tmp_path);
	}

	if (asprintf(&tmp_path, "/proc/%i/mem", di->pid) == -1)
		return 1;

	di->mem_fd = open(tmp_path, O_RDONLY);
	if (di->mem_fd < 0) {
		info("unable to open mem \'%s\': %s", tmp_path,
		     strerror(errno));
		free(tmp_path);
		return 1;
	}

	free(tmp_path);

	return 0;
}

static int init_log(struct dump_info *di)
{
	char *tmp_path;

	if (!di->cfg->prog_config.write_debug_log)
		return 0;

	if (asprintf(&tmp_path, "%s/debug.txt", di->dst_dir) == -1)
		return 1;

	di->info_file = fopen(tmp_path, "w+");
	if (di->info_file == NULL) {
		info("unable to create \'%s\': %s", tmp_path, strerror(errno));
		free(tmp_path);
		return 1;
	}

	free(tmp_path);

	fprintf(di->info_file, "Core Dump Log\n");
	fprintf(di->info_file, "-------------\n");
	fprintf(di->info_file, "Program: %s\n", di->exe);
	fprintf(di->info_file, "PID: %i UID: %i GID: %i\n", di->pid,
		di->uid, di->gid);

	return 0;
}

typedef int elf_parse_cb(struct dump_info *di, Elf *elf, GElf_Phdr *phdr);

static int do_elf_ph_parse(struct dump_info *di, GElf_Phdr *type,
			   elf_parse_cb *callback)
{
	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr;
	Elf *elf = NULL;
	int err = -1;
	size_t phnum;
	size_t cnt;

	/* start from beginning of core */
	if (lseek64(di->elf_fd, 0, SEEK_SET) == -1) {
		info("lseek failed: %s", strerror(errno));
		goto out;
	}

	elf = elf_begin(di->elf_fd, ELF_C_READ, NULL);
	if (!elf) {
		info("elf_begin failed: %s", elf_errmsg(elf_errno()));
		goto out;
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		info("invalid elf_kind: %d", elf_kind(elf));
		goto out;
	}

	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr) {
		info("gelf_getehdr failed: %s", elf_errmsg(elf_errno()));
		goto out;
	}

	di->elfclass = gelf_getclass(elf);
	if (di->elfclass == ELFCLASSNONE) {
		info("gelf_getclass failed: %s", elf_errmsg(elf_errno()));
		goto out;
	}

	if (elf_getphdrnum(elf, &phnum) != 0) {
		info("elf_getphdrnum failed: %s", elf_errmsg(elf_errno()));
		goto out;
	}

	if (phnum == 0) {
		info("elf error: no program headers");
		goto out;
	}

	for (cnt = 0; cnt < phnum; cnt++) {
		GElf_Phdr phdr_mem;
		GElf_Phdr *phdr;
		int ret;

		phdr = gelf_getphdr(elf, cnt, &phdr_mem);

		/* abort on error */
		if (!phdr)
			goto out;

		/* type must match */
		if (phdr->p_type != type->p_type)
			continue;

		/* if flags specified, they must match */
		if (type->p_flags) {
			if ((phdr->p_flags & type->p_flags) != type->p_flags)
				continue;
		}

		/* we have a match, call the callback */
		ret = callback(di, elf, phdr);

		/* on callback error, abort */
		if (ret < 0)
			goto out;

		/* >0 is callback success, but stop */
		if (ret > 0) {
			err = 0;
			goto out;
		}

		/* callback success, continue */
	}

	err = 0;
out:
	if (elf)
		elf_end(elf);

	return err;
}

static int add_vma(struct dump_info *di, unsigned long start,
		   unsigned long mem_end, unsigned long file_end,
		   unsigned long file_off, unsigned int flags)
{
	struct core_vma *v;

	/* allocate a new vma entry */
	v = malloc(sizeof(*v));
	if (!v)
		return -1;

	/* fill out the entry data */
	v->start = start;
	v->mem_end = mem_end;
	v->file_end = file_end;
	v->file_off = file_off;
	v->flags = flags;

	/* push the new entry on the vma list */
	v->next = di->vma;
	di->vma = v;

	return 0;
}

static int vma_cb(struct dump_info *di, Elf *elf, GElf_Phdr *phdr)
{
	add_vma(di, phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz,
		phdr->p_vaddr + phdr->p_filesz, phdr->p_offset, phdr->p_flags);

	/* continue */
	return 0;
}

/*
 * Tries to parse the found ELF headers and reads all vmas from it.
 */
static int parse_vma_info(struct dump_info *di)
{
	unsigned long min_off = ULONG_MAX;
	unsigned long max_len = 0;
	struct core_vma *v;
	GElf_Phdr type;

	/* clear all existing vma info */
	di->vma_start = 0;
	di->vma_end = 0;
	while (di->vma) {
		v = di->vma;
		di->vma = v->next;
		free(v);
	}

	/* looking for readable loadable program segments */
	memset(&type, 0, sizeof(type));
	type.p_type = PT_LOAD;
	type.p_flags = PF_R;
	if (do_elf_ph_parse(di, &type, vma_cb) != 0)
		return -1;

	for (v = di->vma; v; v = v->next) {
		unsigned long len;

		/*
		 * keep track of highest vm address
		 * (this will be the max size of the core)
		 */
		len = v->file_off + v->file_end - v->start;
		if (len > max_len)
			max_len = len;

		/*
		 * keep track of lowest core file offset
		 * (all bytes up to this value will be copied from
		 *  the source core to the core)
		 */
		if (v->file_off < min_off)
			min_off = v->file_off;
	}

	/* sanity checks */
	if (max_len == 0 || min_off == ULONG_MAX)
		return -1;

	di->vma_start = min_off;
	di->vma_end = max_len;

	return 0;
}

/*
 * Copy data from a source core to (optionally) multiple destination cores.
 * Assumes all files are already positioned correctly to begin.
 */
static int copy_data(int src, int dest, int dest2, size_t len, char *pagebuf)
{
	size_t chunk;
	int ret;

	if (len < (size_t)PAGESZ)
		chunk = len;
	else
		chunk = PAGESZ;

	while (len) {
		if (len < chunk)
			chunk = len;

		ret = read_file_fd(src, pagebuf, chunk);
		if (ret < 0) {
			info("read core failed at 0x%lx",
			     lseek64(src, 0, SEEK_CUR));
			return -1;
		}

		ret = write_file_fd(dest, pagebuf, chunk);
		if (ret < 0) {
			info("write core failed at 0x%lx",
			     lseek64(dest, 0, SEEK_CUR));
			return -1;
		}

		if (dest2 >= 0) {
			ret = write_file_fd(dest2, pagebuf, chunk);
			if (ret < 0) {
				info("write core2 failed at 0x%lx",
				     lseek64(dest2, 0, SEEK_CUR));
				return -1;
			}
		}

		len -= chunk;
	}

	return 0;
}

struct sparse {
	char offset[12];
	char numbytes[12];
};

struct tar_header {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char numbytes[12];
	char mtime[12];
	char checksum[8];
	char type;
	char linkname[100];
	char magic[6];
	char version[2];
	char username[32];
	char groupname[32];
	char dev_major[8];
	char dev_minor[8];
	char atime[12];
	char ctime[12];
	char multivolume_offset[12];
	char longnames[4];
	char pad0;
	struct sparse sparse_map[4];
	char is_extended;
	char filesize[12];
	char pad1[17];
};

#define BLOCK_SIZE 512

/* group core data items into 512-byte blocks */
static void assign_tar_blocks(struct core_data *core_file)
{
	struct core_data *cur;
	off64_t blk_start;
	off64_t blk_end;
	int blk_id = 0;

	if (!core_file)
		return;

	blk_start = core_file->start & ~(BLOCK_SIZE - 1);
	blk_end = blk_start + BLOCK_SIZE;

	for (cur = core_file; cur; cur = cur->next) {
		blk_start = cur->start & ~(BLOCK_SIZE - 1);

		if (blk_start > blk_end) {
			/* new block */
			blk_id++;
			blk_end = blk_start + BLOCK_SIZE;
		}

		while (cur->end > blk_end)
			blk_end += BLOCK_SIZE;

		cur->blk_id = blk_id;
	}
}

static struct core_data *get_tar_block_map(struct core_data *cur,
					   off64_t *offset, off64_t *numbytes)
{
	/* offset based on first item of block */
	*offset = cur->start & ~(BLOCK_SIZE - 1);

	/* skip to last item of block */
	while (cur->next && cur->next->blk_id == cur->blk_id)
		cur = cur->next;

	/* sized based on last item of block */
	*numbytes = cur->end - *offset;

	/* return first item of next block */
	return cur->next;
}

static unsigned int get_tar_checksum(struct tar_header *header)
{
	char *buf = (char *)header;
	int sum = 0;
	int i;

	for (i = 0; i < BLOCK_SIZE; i++)
		sum += 0xff & buf[i];

	return sum;
}

static off64_t block_roundup(off64_t b)
{
	if ((b & (BLOCK_SIZE - 1))) {
		b += BLOCK_SIZE;
		b &= ~(BLOCK_SIZE - 1);
	}

	return b;
}

static int dump_zero(int fd, off64_t count)
{
	while (count) {
		if (write_file_fd(fd, "", 1) < 0)
			return -1;
		count--;
	}

	return 0;
}

/* fill the rest of the current block with zero */
static int dump_zero_block_rest(int fd, size_t block_bytes_written)
{
	size_t rest;

	rest = BLOCK_SIZE - (block_bytes_written % BLOCK_SIZE);

	/* check if there is a rest */
	if (rest == BLOCK_SIZE)
		return 0;

	return dump_zero(fd, rest);
}

static int open_compressor(struct dump_info *di, const char *core_suffix,
			   char **path)
{
	const char *ext = di->cfg->prog_config.core_compressor_ext;
	const char *cmd = di->cfg->prog_config.core_compressor;
	char *tmp_path;
	int pipefd[2];
	pid_t pid;
	int fd;

	*path = NULL;

	if (asprintf(&tmp_path, "%s/core%s.%s", di->dst_dir, core_suffix,
		     ext ? ext : "compressed") == -1) {
		return -1;
	}

	fd = open(tmp_path, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
	if (fd == -1) {
		info("failed to open compressed core file: %s", tmp_path);
		free(tmp_path);
		return -1;
	}

	info("executing compressor %s to create %s", cmd, tmp_path);

	if (pipe(pipefd) != 0) {
		free(tmp_path);
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		close(pipefd[0]);
		close(pipefd[1]);
		free(tmp_path);
		return -1;
	}

	if (pid != 0) {
		/* parent */
		signal(SIGPIPE, SIG_IGN);
		close(fd);
		close(pipefd[0]);
		*path = tmp_path;
		return pipefd[1];
	}

	/* child */
	close(pipefd[1]);

	dup2(pipefd[0], STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);

	execlp(cmd, cmd, NULL);

	info("failed to execute compressor: %s", cmd);
	exit(1);
}

static void close_compressor(int fd)
{
	close(fd);
	wait(NULL);
	signal(SIGPIPE, SIG_DFL);
}

static int dump_compressed_tar(struct dump_info *di)
{
	struct core_data *extended_data = NULL;
	struct core_data *next_block;
	size_t block_bytes_written;
	struct tar_header hdr;
	struct core_data *cur;
	off64_t total_bytes;
	char *path = NULL;
	off64_t numbytes;
	off64_t offset;
	int err = -1;
	char *buf;
	int fd;
	int i;

	if (!di->cfg->prog_config.core_in_tar)
		return -1;
	if (!di->cfg->prog_config.core_compressor)
		return -1;

	buf = malloc(PAGESZ);
	if (!buf)
		return -1;

	memset(&hdr, 0, sizeof(hdr));

	assign_tar_blocks(di->core_file);

	/* fill header */

	snprintf(hdr.name, sizeof(hdr.name), "core");
	snprintf(hdr.mode, sizeof(hdr.mode), "%07o", 0644);
	snprintf(hdr.uid, sizeof(hdr.uid), "%07o", 0);
	snprintf(hdr.gid, sizeof(hdr.gid), "%07o", 0);
	snprintf(hdr.mtime, sizeof(hdr.mtime), "%011lo", time(NULL));
	memset(hdr.checksum, ' ', sizeof(hdr.checksum));
	hdr.type = 'S';
	memcpy(hdr.magic, "ustar ", 6);
	hdr.version[0] = ' ';
	snprintf(hdr.username, sizeof(hdr.username), "root");
	snprintf(hdr.groupname, sizeof(hdr.groupname), "root");

	total_bytes = 0;
	next_block = di->core_file;
	for (i = 0; next_block; i++) {
		next_block = get_tar_block_map(next_block, &offset, &numbytes);
		/* if this is not the last block, fill the full block */
		if (next_block)
			numbytes = block_roundup(numbytes);
		/* dump sparse header */
		if (i < 4) {
			snprintf(hdr.sparse_map[i].offset,
				 sizeof(hdr.sparse_map[i].offset),
				 "%011" PRIo64, offset);
			snprintf(hdr.sparse_map[i].numbytes,
				 sizeof(hdr.sparse_map[i].numbytes),
				 "%011" PRIo64, numbytes);

			/* save first extended sparse block for later */
			if (i == 3)
				extended_data = next_block;
		}
		total_bytes += numbytes;
	}

	snprintf(hdr.numbytes, sizeof(hdr.numbytes), "%011" PRIo64,
		 total_bytes);

	if (extended_data)
		hdr.is_extended = 1;
	snprintf(hdr.filesize, sizeof(hdr.filesize),
		 "%011" PRIo64, di->core_file_size);

	/* calculate checksum */
	snprintf(hdr.checksum, sizeof(hdr.checksum),
		 "%06o", get_tar_checksum(&hdr));

	fd = open_compressor(di, ".tar", &path);
	if (fd < 0)
		goto out;

	/* write header */
	if (write_file_fd(fd, (char *)&hdr, sizeof(hdr)) < 0)
		goto out;

	/* write extended sparse header */
	while (extended_data) {
		struct sparse s;

		block_bytes_written = 0;
		next_block = extended_data;
		for (i = 0; next_block && i < 21; i++) {
			next_block = get_tar_block_map(next_block, &offset,
						       &numbytes);

			/* if this is not the last block, fill full block */
			if (next_block)
				numbytes = block_roundup(numbytes);

			snprintf(s.offset, sizeof(s.offset), "%011" PRIo64,
				 offset);
			snprintf(s.numbytes, sizeof(s.numbytes),
				 "%011" PRIo64, numbytes);
			if (write_file_fd(fd, (char *)&s, sizeof(s)) < 0)
				goto out;
			block_bytes_written += sizeof(s);
		}
		extended_data = next_block;
		if (extended_data) {
			char c = 1;
			if (write_file_fd(fd, &c, sizeof(c)) < 0)
				goto out;
			block_bytes_written += 1;
		}
		/* fill to end of block */
		if (dump_zero_block_rest(fd, block_bytes_written) < 0)
			goto out;
	}

	/* write data blocks */
	block_bytes_written = 0;
	next_block = get_tar_block_map(di->core_file, &offset, &numbytes);
	for (cur = di->core_file; cur; cur = cur->next) {
		if (cur == next_block) {
			if (block_bytes_written % BLOCK_SIZE != 0) {
				/* fill to end of block */
				if (dump_zero_block_rest(fd,
				    block_bytes_written) < 0) {
					goto out;
				}
			}
			next_block = get_tar_block_map(next_block, &offset,
						       &numbytes);
			block_bytes_written = 0;
		}

		if (lseek64(cur->mem_fd, cur->mem_start, SEEK_SET) == -1) {
			info("lseek di->mem_fd failed at 0x%lx",
			     cur->mem_start);
			goto out;
		}

		if (cur->start != offset) {
			/* fill to beginning of block part */
			if (dump_zero(fd, cur->start - offset) < 0)
				goto out;
			block_bytes_written += cur->start - offset;
		}

		if (copy_data(cur->mem_fd, fd, -1,
		    cur->end - cur->start, buf) < 0) {
			goto out;
		}
		block_bytes_written += cur->end - cur->start;
		offset = cur->end;
	}

	/* fill to end of block */
	if (dump_zero_block_rest(fd, block_bytes_written) < 0)
		goto out;

	/* 2 empty blocks as EOF */
	if (dump_zero(fd, BLOCK_SIZE * 2) < 0)
		goto out;

	err = 0;

	di->cfg->prog_config.core_compressed = true;

	info("compressed core tar path: %s", path);
out:
	if (fd >= 0)
		close_compressor(fd);
	if (path) {
		if (err)
			unlink(path);
		free(path);
	}
	free(buf);

	return err;
}

static int dump_compressed_core(struct dump_info *di)
{
	struct core_data *cur;
	char *path = NULL;
	off64_t pos = 0;
	int err = -1;
	char *buf;
	int fd;

	if (!di->cfg->prog_config.core_compressor)
		return -1;

	buf = malloc(PAGESZ);
	if (!buf)
		return -1;

	fd = open_compressor(di, "", &path);
	if (fd < 0)
		goto out;

	for (cur = di->core_file; cur; cur = cur->next) {
		if (lseek64(cur->mem_fd, cur->mem_start, SEEK_SET) == -1) {
			info("lseek di->mem_fd failed at 0x%lx",
			     cur->mem_start);
			goto out;
		}

		if (cur->start < pos) {
			info("invalid core data ordering");
			goto out;
		}

		dump_zero(fd, cur->start - pos);

		if (copy_data(cur->mem_fd, fd, -1,
			      cur->end - cur->start, buf) < 0) {
			goto out;
		}

		pos = cur->end;
	}

	if (pos < di->core_file_size)
		dump_zero(fd, di->core_file_size - pos);

	err = 0;

	di->cfg->prog_config.core_compressed = true;

	info("compressed core path: %s", path);
out:
	if (fd >= 0)
		close_compressor(fd);
	if (path) {
		if (err)
			unlink(path);
		free(path);
	}
	free(buf);

	return err;
}

static void dump_mini_core(struct dump_info *di)
{
	struct core_data *cur;
	char *buf;

	buf = malloc(PAGESZ);
	if (!buf)
		return;

	/* set core size */
	if (pwrite(di->core_fd, "", 1, di->core_file_size - 1) != 1) {
		info("failed to set core size: %" PRIu64 " bytes",
		     di->core_file_size);
	}

	for (cur = di->core_file; cur; cur = cur->next) {
		if (lseek64(cur->mem_fd, cur->mem_start, SEEK_SET) == -1) {
			info("lseek di->mem_fd failed at 0x%lx",
			     cur->mem_start);
			goto out;
		}

		if (lseek64(di->core_fd, cur->start, SEEK_SET) == -1) {
			info("lseek di->core_fd failed at 0x%lx", cur->start);
			goto out;
		}

		if (copy_data(cur->mem_fd, di->core_fd, -1,
			      cur->end - cur->start, buf) < 0) {
			goto out;
		}
	}

	info("core path: %s", di->core_path);
out:
	free(buf);
}

int add_core_data(struct dump_info *di, off64_t dest_offset, size_t len,
		  int src_fd, off64_t src_offset)
{
	struct core_data *prev = NULL;
	off64_t start = dest_offset;
	struct core_data *cur;
	struct core_data *tmp;
	int done = 0;
	off64_t end;

	end = start + len;

	for (cur = di->core_file; cur && !done; cur = cur->next) {
		if (end < cur->start) {
			/* insert new block */
			tmp = calloc(1, sizeof(*tmp));
			if (!tmp)
				return ENOMEM;

			tmp->start = start;
			tmp->end = end;
			tmp->mem_start = src_offset;
			tmp->mem_fd = src_fd;
			tmp->next = cur;

			if (prev)
				prev->next = tmp;
			else
				di->core_file = tmp;
			done = 1;

		} else if (end == cur->start) {
			if ((src_offset + len) == cur->mem_start &&
			    src_fd == cur->mem_fd) {
				/* adjacent block, expand existing block */
				cur->start = start;
				cur->mem_start = src_offset;
			} else {
				/* non-adjacent block, insert new block */
				tmp = calloc(1, sizeof(*tmp));
				if (!tmp)
					return ENOMEM;

				tmp->start = start;
				tmp->end = end;
				tmp->mem_start = src_offset;
				tmp->mem_fd = src_fd;
				tmp->next = cur;

				if (prev)
					prev->next = tmp;
				else
					di->core_file = tmp;
			}
			done = 1;

		} else if (start < cur->end) {
			/* overlapping block, expand existing block */
			if (start < cur->start) {
				cur->start = start;
				cur->mem_start = src_offset;
			}
			if (end > cur->end)
				cur->end = end;
			done = 1;

		} else if (start == cur->end) {
			if (src_offset == (cur->mem_start + len)) {
				/* adjacent block, expand existing block */
				cur->end = end;
				done = 1;
			}
		}

		while (cur->next) {
			if (cur->next->start < cur->end) {
				/* consolidate overlapping block */
				tmp = cur->next;
				if (tmp->end > cur->end)
					cur->end = tmp->end;
				cur->next = tmp->next;
				free(tmp);
				continue;

			} else if (cur->next->start == cur->end) {
				if (((cur->mem_start + (cur->end - cur->start))
				     == cur->next->mem_start) &&
				    (cur->mem_fd == cur->next->mem_fd)) {
					/* consolidate adjacent block */
					tmp = cur->next;
					cur->end = tmp->end;
					cur->next = tmp->next;
					free(tmp);
					continue;
				}
			}

			break;
		}

		if (done)
			return 0;

		prev = cur;
	}

	tmp = calloc(1, sizeof(*tmp));
	if (!tmp)
		return ENOMEM;

	tmp->start = start;
	tmp->end = end;
	tmp->mem_start = src_offset;
	tmp->mem_fd = src_fd;

	if (prev) {
		tmp->next = prev->next;
		prev->next = tmp;
	} else {
		tmp->next = di->core_file;
		di->core_file = tmp;
	}

	return 0;
}

/*
 * Reads the ELF header from the large core file.
 * This header is dumped to the core.
 */
static int init_src_core(struct dump_info *di, int src)
{
	int tries = 0;
	int ret = -1;
	size_t len;
	char *buf;
	long pos;

	buf = malloc(PAGESZ);
	if (!buf)
		return -1;

	/*
	 * Procedure:
	 * 1. read 2 pages from source core and write to core
	 * 2. try to elf-parse core
	 * 3. if unable to parse, read 2 more pages and try again
	 * 4. try up to 10 times (20 pages)
	 */
again:
	/* copy 2 pages */
	if (copy_data(src, di->elf_fd, di->fatcore_fd, PAGESZ * 2, buf) < 0)
		goto out;

	/* remember our position */
	pos = lseek64(di->elf_fd, 0, SEEK_CUR);
	if (pos == -1)
		goto out;

	/* try to elf-parse the core to read vma info */
	ret = parse_vma_info(di);

	/* restore our position */
	if (lseek64(di->elf_fd, pos, SEEK_SET) == -1)
		goto out;

	if (ret != 0) {
		/* elf-parse failed */

		tries++;

		/* maybe try again */
		if (tries < 10)
			goto again;

		goto out;
	}

	if (di->vma_start > (unsigned long)pos) {
		/* copy the rest of core up to the first vma */
		len = di->vma_start - pos;

		/* position in all cores is already correct, now copy */
		if (copy_data(src, di->elf_fd, di->fatcore_fd, len, buf) < 0)
			goto out;
	}

	add_core_data(di, 0, di->vma_start, di->elf_fd, 0);

	/* make the core big enough to fit all vma areas */
	di->core_file_size = di->vma_end;

	/* add empty core data to mark the size of the core file */
	add_core_data(di, di->core_file_size, 0, di->elf_fd, 0);
out:
	free(buf);
	return ret;
}

/*
 * Log all known vmas for debugging purposes.
 */
static void log_vmas(struct dump_info *di)
{
	struct core_vma *tmp;

	if (!di->info_file)
		return;

	fprintf(di->info_file, "VMA list:\n");

	for (tmp = di->vma; tmp; tmp = tmp->next) {
		fprintf(di->info_file, "start: 0x%lx end: 0x%lx len: 0x%lx "
				       "core offset: 0x%lx\n",
			tmp->start, tmp->file_end, tmp->file_end - tmp->start,
			tmp->file_off);
	}

	fprintf(di->info_file, "\n");
}

static int sym_address(struct dump_info *di, const char *symname,
		       unsigned long *addr)
{
	struct sym_data *sd;
	int i;

	for (sd = di->sym_data_list; sd; sd = sd->next) {
		for (i = 0; i < sd->count; i++) {
			GElf_Sym sym;
			GElf_Sym *s;

			s = gelf_getsym(sd->data, i, &sym);
			if (!s)
				continue;

			if (strcmp(elf_strptr(sd->elf, sd->shdr.sh_link,
					      s->st_name), symname) != 0) {
				continue;
			}

			*addr = sd->start + s->st_value;
			return 0;
		}
	}

	return -1;
}

static struct sym_data *alloc_sym_data(const char *file, unsigned long start)
{
	struct sym_data *sd;
	Elf_Scn *scn = NULL;

	sd = calloc(1, sizeof(*sd));
	if (!sd)
		return NULL;

	sd->start = start;
	sd->fd = open(file, O_RDONLY);
	if (sd->fd < 0) {
		free(sd);
		return NULL;
	}
	sd->elf = elf_begin(sd->fd, ELF_C_READ, NULL);

	while (1) {
		GElf_Shdr *shdr;

	 	scn = elf_nextscn(sd->elf, scn);
		if (!scn) {
			elf_end(sd->elf);
			close(sd->fd);
			free(sd);
			return NULL;
		}

		shdr = gelf_getshdr(scn, &sd->shdr);
		if (shdr && sd->shdr.sh_type == SHT_SYMTAB) {
			/* found symbol table */
			break;
		}
	}

	sd->data = elf_getdata(scn, NULL);
	sd->count = sd->shdr.sh_size / sd->shdr.sh_entsize;

	return sd;
}

static int store_sym_data(struct dump_info *di, const char *lib,
			  unsigned long start)
{
	struct sym_data *cur;
	struct sym_data *sd;

	/* check if we already have this data */
	for (cur = di->sym_data_list; cur; cur = cur->next) {
		if (start == cur->start)
			return 0;
	}

	/* allocate new sym_data node */
	sd = alloc_sym_data(lib, start);
	if (!sd)
		return -1;

	/* add new node to end of list */
	if (!di->sym_data_list) {
		di->sym_data_list = sd;
	} else {
		for (cur = di->sym_data_list; cur->next; cur = cur->next)
			/* NOP */ ;
		cur->next = sd;
	}

	return 0;
}

static void close_sym(struct dump_info *di)
{
	struct sym_data *sd;

	while (di->sym_data_list) {
		sd = di->sym_data_list;
		di->sym_data_list = sd->next;

		elf_end(sd->elf);
		close(sd->fd);
		free(sd);
	}
}

static void cleanup_di(struct dump_info *di)
{
	struct core_data *core_data;
	struct core_vma *vma;

	close_sym(di);

	if (di->core_fd >= 0) {
		close(di->core_fd);
		di->core_fd = -1;
	}
	if (di->fatcore_fd >= 0) {
		close(di->fatcore_fd);
		di->fatcore_fd = -1;
	}
	if (di->elf_fd >= 0) {
		close(di->elf_fd);
		di->elf_fd = -1;
	}
	if (di->mem_fd >= 0) {
		close(di->mem_fd);
		di->mem_fd = -1;
	}
	if (di->info_file) {
		fclose(di->info_file);
		di->info_file = NULL;
	}

	/* delete unused (empty) core if we have compressed */
	if (di->cfg && di->cfg->prog_config.core_compressed)
		unlink(di->core_path);

	if (di->tsks) {
		free(di->tsks);
		di->tsks = NULL;
	}
	if (di->core_path) {
		free(di->core_path);
		di->core_path = NULL;
	}
	if (di->comm) {
		free(di->comm);
		di->comm = NULL;
	}
	if (di->exe) {
		free(di->exe);
		di->exe = NULL;
	}
	while (di->core_file) {
		core_data = di->core_file;
		di->core_file = core_data->next;
		free(core_data);
	}
	while (di->vma) {
		vma = di->vma;
		di->vma = vma->next;
		free(vma);
	}

	if (di->cfg) {
		free_config(di->cfg);
		di->cfg = NULL;
	}
}

static int get_stack_pointer(pid_t pid, unsigned long *addr)
{
#define STAT_LINE_MAXSIZE 4096
	FILE *f = NULL;
	int err = -1;
	char *buf;
	char *p;
	int i;

	/* create a buffer large enough for stat line */
	buf = malloc(STAT_LINE_MAXSIZE);
	if (!buf)
		goto out_err;

	/* open stat file */
	snprintf(buf, STAT_LINE_MAXSIZE, "/proc/%d/stat", pid);
	f = fopen(buf, "r");
	if (!f)
		goto out_err;

	/* read line */
	if (fgets(buf, STAT_LINE_MAXSIZE, f) == NULL)
		goto out_err;

	/* find 29th item: man proc(5) */
	p = buf;
	for (i = 0; i < 28; i++) {
		p = strchr(p, ' ');
		if (!p)
			goto out_err;
		p++;
	}

	/* read stack pointer */
	if (sscanf(p, "%lu ", addr) != 1)
		goto out_err;

	err = 0;
out_err:
	if (f)
		fclose(f);
	if (buf)
		free(buf);

	return err;
#undef STAT_LINE_MAXSIZE
}

static struct core_vma *get_next_vma_range(struct dump_info *di,
					   unsigned long start,
					   unsigned long end,
					   struct core_vma *vma)
{
	/* check for range overlap with vma */
	for ( ; vma; vma = vma->next) {
		if (end > vma->start && start < vma->mem_end)
			break;
	}

	return vma;
}

static struct core_vma *get_vma_pos(struct dump_info *di, unsigned long addr)
{
	struct core_vma *vma;

	for (vma = di->vma; vma; vma = vma->next) {
		/* check for address within vma */
		if (addr >= vma->start && addr < vma->mem_end)
			break;
	}

	return vma;
}

/*
 * Dumps a specific vma.
 * The balloon argument lowers the start and raises the end by
 * the amount "balloon".
 */
static int dump_vma(struct dump_info *di, unsigned long start, size_t len,
		    size_t balloon, const char *fmt, ...)
{
	unsigned long dump_start;
	unsigned long dump_end;
	struct core_vma *tmp;
	unsigned long end;
	char *desc = NULL;
	int err = 0;
	va_list ap;
	int ret;

	end = start + len;

	tmp = get_next_vma_range(di, start, end, di->vma);
	if (!tmp) {
		info("vma not found start=0x%lx! bad recept or internal bug!",
		     start);
		return EINVAL;
	}

	va_start(ap, fmt);
	ret = vasprintf(&desc, fmt, ap);
	va_end(ap);

	if (ret == -1)
		return ENOMEM;

	while (tmp) {
		dump_start = start;
		dump_end = end;

		if (balloon > 0) {
			/* the balloon argument lowers the start and
			 * raises the end by the amount "balloon" */
			dump_start -= balloon;
			dump_end += balloon;
		}

		/* only dump what is actually in VMA */
		if (dump_start < tmp->start)
			dump_start = tmp->start;
		if (dump_end > tmp->mem_end)
			dump_end = tmp->mem_end;

		/* make sure we have something to dump */
		if (dump_start < dump_end) {
			len = dump_end - dump_start;

			info("dump: %s: %zu bytes @ 0x%lx", desc ? desc : "",
			     len, dump_start);

			err = add_core_data(di, tmp->file_off + dump_start -
						tmp->start, len, di->mem_fd,
					    dump_start);
			if (err)
				break;
		}

		tmp = get_next_vma_range(di, start, end, tmp->next);
	}

	if (desc)
		free(desc);

	return err;
}

static int note_cb(struct dump_info *di, Elf *elf, GElf_Phdr *phdr)
{
	size_t offset = 0;
	Elf_Data *data;

	data = elf_getdata_rawchunk(elf, phdr->p_offset, phdr->p_filesz,
				    ELF_T_NHDR);
	if (!data) {
		info("elf_getdata_rawchunk failed: %s",
		     elf_errmsg(elf_errno()));
		return -1;
	}

	while (offset < data->d_size) {
		const struct elf_prstatus *status;
		size_t name_offset;
		size_t desc_offset;
		const char *desc;
		GElf_Nhdr nhdr;

		offset = gelf_getnote(data, offset, &nhdr, &name_offset,
				      &desc_offset);
		if (offset == 0) {
			info("gelf_getnote failed: %s",
			     elf_errmsg(elf_errno()));
			return -1;
		}

		desc = data->d_buf + desc_offset;

		if (nhdr.n_type != NT_PRSTATUS)
			continue;

		status = (const struct elf_prstatus *)desc;

		di->first_pid = status->pr_pid;

		/* success, we can stop */
		return 1;
	}

	/* we found nothing, keep looking */
	return 0;
}

/*
 * Dumps the current stack of all threads.
 */
static int dump_stacks(struct dump_info *di)
{
	unsigned long stack_addr;
	struct core_vma *tmp;
	size_t max_len;
	size_t len;
	int i;

	if (di->cfg->prog_config.stack.first_thread_only) {
		GElf_Phdr type;

		/* find and set the first task */
		memset(&type, 0, sizeof(type));
		type.p_type = PT_NOTE;
		do_elf_ph_parse(di, &type, note_cb);
	}

	if (di->first_pid)
		info("first thread: %i", di->first_pid);

	for (i = 0; i < di->ntsks; i++) {
		/* skip this task if we should only dump the
		 * first task and we know the first task */
		if (di->first_pid && (di->first_pid != di->tsks[i]))
			continue;

		/* grab the stack pointer */
		if (get_stack_pointer(di->tsks[i], &stack_addr) != 0) {
			info("unable to find thread #%d's (%d) stack pointer",
			     i + 1, di->tsks[i]);
			continue;
		}

		/* find the vma containing the stack */
		tmp = get_vma_pos(di, stack_addr);
		if (!tmp) {
			info("unable to find thread #%d's (%d) stack", i + 1,
			     di->tsks[i]);
			continue;
		}

		/* determine how much of the stack is actually used */
		len = tmp->file_end - stack_addr;

		/* truncate stack if above max threshold */
		max_len = di->cfg->prog_config.stack.max_stack_size;
		if (max_len && len > max_len) {
			info("stack[%d] is too large (%zu bytes), truncating "
			     "to %zu bytes", di->tsks[i], len, max_len);
			len = max_len;
		}

		/* dump the bottom part of stack in use */
		dump_vma(di, stack_addr, len, 0, "stack[%d]",
			 di->tsks[i]);
	}

	return 0;
}

static off64_t get_core_pos(struct dump_info *di, unsigned long addr)
{
	struct core_vma *vma;

	vma = get_vma_pos(di, addr);
	if (!vma)
		return (off64_t)-1;

	return (vma->file_off + addr - vma->start);
}

/*
 * Tests whether a map has been specified by the recept.
 */
static int map_is_interesting(struct dump_info *di, const char *name,
			      size_t len)
{
	unsigned int i;

	for (i = 0; i < di->cfg->prog_config.maps.nglobs; i++) {
		if (simple_match(di->cfg->prog_config.maps.name_globs[i],
				 name) == 0) {
			return 1;
		}
	}

	return 0;
}

/*
 * Iterates over all maps and dumps the selected ones.
 */
static int dump_maps(struct dump_info *di, int get_only)
{
#define MAPS_LINE_MAXSIZE 8192
	unsigned long start;
	unsigned long end;
	FILE *f = NULL;
	int err = -1;
	char *perms;
	char *lib;
	char *buf;
	char *p;
	int i;

	/* create a buffer large enough for maps line */
	buf = malloc(MAPS_LINE_MAXSIZE);
	if (!buf)
		goto out_err;

	/* open maps file */
	snprintf(buf, MAPS_LINE_MAXSIZE, "/proc/%d/maps", di->pid);
	f = fopen(buf, "r");
	if (!f)
		goto out_err;

	while (fgets(buf, MAPS_LINE_MAXSIZE, f)) {
		/* read memory range */
		if (sscanf(buf, "%lx-%lx ", &start, &end) != 2)
			continue;

		/* find 2nd item: man proc(5) */
		p = strchr(buf, ' ');
		if (!p)
			continue;

		/* capture permissions */
		perms = p + 1;

		/* only interested in readable maps */
		if (perms[0] != 'r')
			continue;

		if (get_only) {
			add_vma(di, start, end, end, start, 0);
			continue;
		}

		/* find 6th item: man proc(5) */
		p = perms;
		for (i = 1; i < 5; i++) {
			p = strchr(p, ' ');
			if (!p)
				break;
			p++;
		}

		if (!p)
			continue;

		/* 6th item has extra whitespace */
		while (*p == ' ')
			p++;

		/* capture library name */
		lib = p;

		/* strip newline */
		p = strchr(lib, '\n');
		if (p)
			*p = 0;

		if (!map_is_interesting(di, lib, end - start))
			continue;

		dump_vma(di, start, end - start, 0, "%s", lib);
	}

	err = 0;
out_err:
	if (f)
		fclose(f);
	if (buf)
		free(buf);

	return err;
#undef MAPS_LINE_MAXSIZE
}

static int read_remote(struct dump_info *di, unsigned long addr, void *dst,
		       ssize_t len)
{
	int ret;

	ret = pread64(di->mem_fd, dst, len, addr);
	if (ret != len) {
		info("read_remote failed: len=%d, addr=0x%lx, "
		     "dest=0x%x, errno=\"%s\"",
		     len, addr, dst, strerror(errno));
		return -1;
	}

	return 0;
}

static int alloc_remote_string(struct dump_info *di, unsigned long addr,
			       char **dst)
{
#define REMOTE_STRING_MAX 4096
	char *ptr;
	int ret;
	int i;

	*dst = NULL;

	if (addr == 0)
		return EINVAL;

	/* TODO: only max string length of 4095 accepted */

	ptr = malloc(REMOTE_STRING_MAX);
	if (!ptr)
		return ENOMEM;

	for (i = 1; i < REMOTE_STRING_MAX; i++) {
		ret = pread64(di->mem_fd, ptr, i, addr);
		if (ret != i) {
			ret = errno;
			info("read_remote failed: addr %#lx: %s", addr,
			     strerror(errno));
			free(ptr);
			if (ret == 0)
				ret = -1;
			return ret;
		}

		if (ptr[i - 1] == 0)
			break;
	}

	ptr[i - 1] = 0;
	*dst = ptr;

	return 0;
#undef REMOTE_STRING_MAX
}

static void *do_setup_data(struct dump_data_elem *elem, void *data)
{
	struct dump_info *di = data;
	void *data_ptr;

	data_ptr = malloc(elem->u.length);
	if (!data_ptr)
		return NULL;

	if (read_remote(di, (unsigned long)elem->data_ptr,
			data_ptr, elem->u.length) != 0) {
		free(data_ptr);
		return NULL;
	}

	return data_ptr;
}

static void do_cleanup_data(void *data_ptr)
{
	free(data_ptr);
}

static void free_dump_data_content(struct mcd_dump_data *dd)
{
	if (dd->ident) {
		free(dd->ident);
		dd->ident = NULL;
	}

	if (dd->fmt) {
		free(dd->fmt);
		dd->fmt = NULL;
	}

	if (dd->es) {
		free(dd->es);
		dd->es = NULL;
	}
}

static int alloc_remote_data_content(struct dump_info *di, unsigned long addr,
				     struct mcd_dump_data *dd)
{
	struct dump_data_elem *es;
	int ret;

	memset(dd, 0, sizeof(*dd));

	ret = read_remote(di, addr, dd, sizeof(*dd));
	if (ret != 0)
		return EFAULT;

	/* abort if we should ignore this dump */
	if (dd->dump_scope > di->cfg->prog_config.dump_scope)
		return EACCES;

	if (dd->ident) {
		ret = alloc_remote_string(di, (unsigned long)dd->ident,
					  &dd->ident);
		if (ret != 0)
			return EFAULT;

		/* abort if invalid ident */
		if (invalid_ident(dd->ident)) {
			/* clear fields so there is no free() attempt */
			dd->fmt = NULL;
			dd->es = NULL;
			free_dump_data_content(dd);
			return EINVAL;
		}
	}

	if (dd->fmt) {
		ret = alloc_remote_string(di, (unsigned long)dd->fmt,
					  &dd->fmt);
		if (ret != 0) {
			/* clear fields so there is no free() attempt */
			dd->fmt = NULL;
			dd->es = NULL;
			free_dump_data_content(dd);
			return EFAULT;
		}
	}

	if (dd->es_n == 0) {
		/* done, no registered variables */
		dd->es = NULL;
		return 0;
	}

	es = calloc(sizeof(*es), dd->es_n);
	if (!es) {
		/* clear fields so there is no free() attempt */
		dd->es = NULL;
		free_dump_data_content(dd);
		return ENOMEM;
	}

	ret = read_remote(di, (unsigned long)dd->es, es,
			  (sizeof(*es) * dd->es_n));
	dd->es = es;
	if (ret != 0) {
		free_dump_data_content(dd);
		return EFAULT;
	}

	return 0;
}

static int dump_data_content_core(struct dump_info *di,
				  struct mcd_dump_data *dd)
{
	struct dump_data_elem *es;
	unsigned long addr_ind;
	unsigned long addr;
	unsigned int i;
	size_t length;
	int ret;

	/* dump each element to core */
	for (i = 0; i < dd->es_n; i++) {
		es = &dd->es[i];

		/* resolve data pointer */
		if ((es->flags & MCD_DATA_PTR_INDIRECT)) {
			addr_ind = (unsigned long)es->data_ptr;
			ret = read_remote(di, (unsigned long)es->data_ptr,
					  &addr, sizeof(es->data_ptr));
			if (ret != 0)
				return ret;
		} else {
			addr_ind = 0;
			addr = (unsigned long)es->data_ptr;
		}

		/* resolve length pointer */
		if ((es->flags & MCD_LENGTH_INDIRECT)) {
			ret = read_remote(di, (unsigned long)es->u.length_ptr,
					  &length, sizeof(es->u.length_ptr));
			if (ret != 0)
				return ret;
		} else {
			length = es->u.length;
		}

		/* dump indirect data pointer to core */
		if (addr_ind != 0) {
			dump_vma(di, addr_ind, sizeof(es->data_ptr), 0,
				 "data pointer");
		}

		/* dump data to core */
		if (!(es->flags & MCD_DATA_NODUMP))
			dump_vma(di, addr, length, 0, "data");
	}

	return 0;
}

static int add_symbol_map_entry(struct dump_info *di, off64_t core_pos,
				unsigned long mem_pos, size_t size, char type,
				const char *ident)
{
	char *tmp_path;
	size_t len;
	FILE *f;
	int ret;

	/* do not create symbol map if core-related dumps are disabled */
	if (di->core_fd < 0)
		return 0;

	len = strlen(di->dst_dir) + strlen("/symbol.map") + 1;
	tmp_path = malloc(len);
	if (!tmp_path)
		return ENOMEM;

	snprintf(tmp_path, len, "%s/symbol.map", di->dst_dir);
	f = fopen(tmp_path, "a");
	ret = errno;
	free(tmp_path);
	if (!f)
		return ret;

	fprintf(f, "%" PRIx64 " %lx %zx %c %s\n",
		core_pos, mem_pos, size, type, ident);

	fclose(f);

	return 0;
}

static int dump_data_file_bin(struct dump_info *di, struct mcd_dump_data *dd,
			      FILE *file)
{
	/* binary file dumps should only have 1 element */
	struct dump_data_elem *es = &dd->es[0];
	unsigned long addr_ind;
	unsigned long addr;
	char type = 'D';
	off64_t core_pos;
	size_t length;
	char *buf;
	int ret;

	/* resolve data pointer */
	if ((es->flags & MCD_DATA_PTR_INDIRECT)) {
		addr_ind = (unsigned long)es->data_ptr;
		ret = read_remote(di, (unsigned long)es->data_ptr,
				  &addr, sizeof(es->data_ptr));
		if (ret != 0)
			return ret;
	} else {
		addr_ind = 0;
		addr = (unsigned long)es->data_ptr;
	}

	/* resolve length pointer */
	if ((es->flags & MCD_LENGTH_INDIRECT)) {
		ret = read_remote(di, (unsigned long)es->u.length_ptr,
				  &length, sizeof(es->u.length_ptr));
		if (ret != 0)
			return ret;
	} else {
		length = es->u.length;
	}

	/* allocate buffer for data */
	buf = malloc(length);
	if (!buf)
		return ENOMEM;

	/* read in data */
	ret = read_remote(di, addr, buf, length);
	if (ret != 0)
		goto out;

	/* dump indirect data pointer */
	if ((es->flags & MCD_DATA_PTR_INDIRECT)) {
		fwrite(&addr, sizeof(unsigned long), 1, file);

		core_pos = get_core_pos(di, addr_ind);
		if (core_pos != (off64_t)-1) {
			add_symbol_map_entry(di, core_pos, addr_ind,
					     sizeof(unsigned long), 'I',
					     dd->ident);
		}
	}

	/* dump data */
	if ((es->flags & MCD_DATA_NODUMP))
		type = 'N';
	else
		fwrite(buf, length, 1, file);

	core_pos = get_core_pos(di, addr);
	if (core_pos != (off64_t)-1) {
		add_symbol_map_entry(di, core_pos, addr, length,
				     type, dd->ident);
	}
out:
	free(buf);
	return ret;
}

static int dump_data_content_file(struct dump_info *di,
				  struct mcd_dump_data *dd)
{
	struct stat sb;
	char *tmp_path;
	FILE *file;
	int len;
	int ret;

	len = strlen(di->dst_dir) + strlen("/dumps/") + 32 +
	      strlen(dd->ident) + 1;
	tmp_path = malloc(len);
	if (!tmp_path)
		return ENOMEM;

	/* create "dumps" directory */
	snprintf(tmp_path, len, "%s/dumps", di->dst_dir);
	mkdir(tmp_path, 0700);

	/* create dumps pid sub-directory */
	snprintf(tmp_path, len, "%s/dumps/%i", di->dst_dir, di->pid);
	mkdir(tmp_path, 0700);

	/* open text file for output */
	snprintf(tmp_path, len, "%s/dumps/%i/%s", di->dst_dir, di->pid,
		 dd->ident);
	file = fopen(tmp_path, "a");
	ret = errno;
	if (!file)
		goto out;

	if (dd->type == MCD_BIN) {
		ret = dump_data_file_bin(di, dd, file);
	} else {
		struct remote_data_callbacks cb = {
			.setup_data = do_setup_data,
			.cleanup_data = do_cleanup_data,
			.cbdata = di,
		};
		ret = dump_data_file_text(dd, file, &cb);
	}

	fclose(file);

	/* delete file if it is empty */
	if (stat(tmp_path, &sb) == 0) {
		if (sb.st_size == 0)
			unlink(tmp_path);
	}
out:
	free(tmp_path);
	return ret;
}

static int dyn_dump(struct dump_info *di)
{
	struct mcd_dump_data *iter;
	unsigned long dd_addr;
	struct mcd_dump_data *dd;
	unsigned long addr;
	int version;
	int ret;

	/* get dump data version */
	ret = sym_address(di, "mcd_dump_data_version", &addr);
	if (ret) {
		info("libminicoredumper: no dump data version found");
		return ENOKEY;
	}

	/* read in pointer to head of dump data */
	ret = read_remote(di, addr, &version, sizeof(version));
	if (ret != 0)
		return EFAULT;

	if (version != DUMP_DATA_VERSION) {
		info("libminicoredumper: dump data version mismatch:"
		     " found %d, expected %d", version, DUMP_DATA_VERSION);
		return ENOKEY;
	}

	/* get address of pointer to head of dump data */
	ret = sym_address(di, "mcd_dump_data_head", &addr);
	if (ret) {
		info("libminicoredumper: no dump data found");
		return ENOKEY;
	}

	/* read in pointer to head of dump data */
	ret = read_remote(di, addr, &dd_addr, sizeof(unsigned long));
	if (ret != 0)
		return EFAULT;

	if (dd_addr == 0) {
		info("libminicoredumper: no registered variables");
		return 0;
	}

	info("libminicoredumper: found registered variables");

	dd = malloc(sizeof(*dd));
	if (!dd)
		return ENOMEM;

	for (iter = (struct mcd_dump_data *)dd_addr; iter; iter = dd->next) {
		/* read in dd and its content */
		ret = alloc_remote_data_content(di, (unsigned long)iter, dd);
		if (ret != 0) {
			/*
			 * EACCESS is returned if dd was read,
			 * but this data is out of scope.
			 */
			if (ret == EACCES)
				continue;
			goto out;
		}

		/* dump the registered data... */
		if (dd->ident) {
			/* ...to external file */
			ret = dump_data_content_file(di, dd);
		} else {
			/* ...to core */
			ret = dump_data_content_core(di, dd);
		}
		free_dump_data_content(dd);
		if (ret != 0)
			goto out;
	}
out:
	free(dd);
	return ret;
}

static void dump_fat_core(struct dump_info *di)
{
	struct core_vma *tmp;
	size_t len;
	char *buf;

	buf = malloc(PAGESZ);
	if (!buf)
		return;

	for (tmp = di->vma; tmp; tmp = tmp->next) {
		len = tmp->file_end - tmp->start;

		lseek64(di->mem_fd, tmp->start, SEEK_SET);
		lseek64(di->fatcore_fd, tmp->file_off, SEEK_SET);

		if (copy_data(di->mem_fd, di->fatcore_fd, -1, len, buf) < 0)
			break;
	}

	free(buf);
}

static int copy_link(const char *dest, const char *src)
{
	struct stat sb;
	char *linkname;
	int ret;

	if (lstat(src, &sb) != 0)
		return -1;

	/* stat/lstat is screwy for /proc/.../cwd, so
	 * fallback to stat if lstat provides no size */
	if (sb.st_size == 0) {
		if (stat(src, &sb) != 0)
			return -1;
	}

	/* set a sane value in case lstat/stat did not help */
	if (sb.st_size < 1 || sb.st_size > 4096)
		sb.st_size = 4096;

	linkname = malloc(sb.st_size + 1);
	if (!linkname)
		return -1;

	ret = readlink(src, linkname, sb.st_size + 1);
	if (ret < 2) {
		/* empty link? */
		free(linkname);
		return -1;
	}
	/* truncate when too long */
	if (ret > sb.st_size)
		ret = sb.st_size;
	/* readlink does not terminate the string */
	linkname[ret] = 0;

	ret = symlink(linkname, dest);

	free(linkname);

	return ret;
}

static void copy_proc_files(struct dump_info *di, int tasks, const char *name,
			    int link)
{
	struct dirent *de;
	size_t base_len;
	int do_fds = 0;
	size_t size;
	char *path;
	DIR *d;
	int i;

	base_len = strlen(di->dst_dir);

	/* assume maximum length expected */
	size = base_len + strlen("/proc/") + 32 + strlen("/task/") + 32 +
	       + strlen("/fd/") + strlen(name) + 32;
	path = malloc(size);
	if (!path)
		return;

	/* identify special case */
	if (strcmp(name, "fd") == 0)
		do_fds = 1;

	snprintf(path, size, "%s/proc", di->dst_dir);
	mkdir(path, 0700);
	snprintf(path, size, "%s/proc/%d", di->dst_dir, di->pid);
	mkdir(path, 0700);

	/* handle non-task file */
	if (!tasks) {
		snprintf(path, size, "%s/proc/%d/%s", di->dst_dir, di->pid,
			 name);
		if (link)
			copy_link(path, path + base_len);
		else
			copy_file(path, path + base_len);
		free(path);
		return;
	}

	snprintf(path, size, "%s/proc/%d/task", di->dst_dir, di->pid);
	mkdir(path, 0700);

	for (i = 0 ; i < di->ntsks; i++) {
		snprintf(path, size, "%s/proc/%d/task/%d", di->dst_dir,
			 di->pid, di->tsks[i]);
		mkdir(path, 0700);

		/* handle the normal task case */
		if (!do_fds) {
			snprintf(path, size, "%s/proc/%d/task/%d/%s",
				 di->dst_dir, di->pid, di->tsks[i], name);

			if (link)
				copy_link(path, path + base_len);
			else
				copy_file(path, path + base_len);
			continue;
		}

		/* special case: copy the symlinks in the fd directory */
		snprintf(path, size, "%s/proc/%d/task/%d/fd", di->dst_dir,
			 di->pid, di->tsks[i]);
		mkdir(path, 0700);

		d = opendir(path + base_len);
		if (!d)
			continue;

		while (1) {
			de = readdir(d);
			if (!de)
				break;

			/* ignore hidden files */
			if (de->d_name[0] == '.')
				continue;

			snprintf(path, size, "%s/proc/%d/task/%d/fd/%s",
				 di->dst_dir, di->pid, di->tsks[i],
				 de->d_name);

			copy_link(path, path + base_len);
		}

		closedir(d);
	}

	free(path);
}

static long __sys_get_robust_list(int pid, struct robust_list_head **head_ptr,
				  size_t *len_ptr)
{
	return syscall(SYS_get_robust_list, pid, head_ptr, len_ptr);
}

/*
 * Iterates over the robust mutex list, dumping them to the core.
 */
static int get_robust_mutex_list(struct dump_info *di)
{
	unsigned long l_head = 0;
	unsigned long l_start;
	unsigned long l_tmp;
	size_t len;
	long ret;

	ret = __sys_get_robust_list(di->pid,
				    (struct robust_list_head **)&l_head, &len);
	if (ret != 0 || len != sizeof(struct robust_list_head))
		return -1;

	/* no robust list */
	if (!l_head)
		return 0;

	dump_vma(di, l_head, sizeof(struct robust_list_head), 0,
		 "robust mutex head");

	if (read_remote(di, l_head + offsetof(struct robust_list_head, list),
			&l_start, sizeof(l_start)) != 0) {
		return 1;
	}

	l_tmp = l_start;
	do {
		dump_vma(di, l_tmp, sizeof(struct robust_list), 0,
			 "robust mutex");

		if (read_remote(di, l_tmp + offsetof(struct robust_list, next),
				&l_tmp, sizeof(l_tmp)) != 0) {
			return 1;
		}

	} while (l_tmp != l_start);

	return 0;
}

typedef struct list_head
{
	struct list_head *next;
	struct list_head *prev;
} list_t;

static void dump_pthread_list(const char *desc, struct dump_info *di,
			      unsigned long addr, unsigned int pthreadsz)
{
	list_t *head = (list_t *)addr;
	list_t item;

	while (addr) {
		/* "bubble" the address with the pthread size because
		 * (officially) we do not know where the list head is
		 * located within the struct pthread. */
		dump_vma(di, addr, 0, pthreadsz, desc);

		if (read_remote(di, addr, &item, sizeof(item)) != 0)
			break;
		if (!item.next)
			break;
		if (item.next == head)
			break;

		addr = (unsigned long)item.next;
	}
}

static void get_pthread_list_fallback(struct dump_info *di)
{
	unsigned int pthreadsz = 0;
	unsigned long addr;

	/* try to determine the size of "struct pthread" */
	if (sym_address(di, "_thread_db_sizeof_pthread", &addr) == 0)
		read_remote(di, addr, &pthreadsz, sizeof(pthreadsz));
	if (pthreadsz == 0) {
		pthreadsz = PAGESZ;
		info("guessing sizeof(struct pthread): %u bytes", pthreadsz);
	} else {
		info("sizeof(struct pthread): %u bytes", pthreadsz);
	}

	if (sym_address(di, "stack_used", &addr) == 0)
		dump_pthread_list("stack_used pthread", di, addr, pthreadsz);

	if (sym_address(di, "__stack_user", &addr) == 0)
		dump_pthread_list("__stack_user pthread", di, addr, pthreadsz);
}

typedef enum
{
	PS_OK,		/* Generic "call succeeded". */
	PS_ERR,		/* Generic error. */
	PS_BADPID,	/* Bad process handle. */
	PS_BADLID,	/* Bad LWP identifier. */
	PS_BADADDR,	/* Bad address. */
	PS_NOSYM,	/* Could not find given symbol. */
	PS_NOFREGS	/* FPU register set not available for given LWP. */
} ps_err_e;

struct ps_prochandle
{
	struct dump_info *di;
};

ps_err_e ps_pdread(struct ps_prochandle *ph, psaddr_t addr, void *buf,
		   size_t size)
{
	if (read_remote(ph->di, (unsigned long)addr, buf, size) != 0)
		return PS_ERR;

	/* whatever td_ta_thr_iter() reads, dump to core */
	dump_vma(ph->di, (unsigned long)addr, size, 0, "pthread data");

	return PS_OK;
}

ps_err_e ps_pdwrite(struct ps_prochandle *ph, psaddr_t addr, const void *buf,
		    size_t size)
{
	/* NOP */
	return PS_OK;
}

ps_err_e ps_lgetregs(struct ps_prochandle *ph, lwpid_t lwpid,
		     prgregset_t prgregset)
{
	/* NOP */
	return PS_OK;
}

ps_err_e ps_lsetregs(struct ps_prochandle *ph, lwpid_t lwpid,
		     const prgregset_t prgregset)
{
	/* NOP */
	return PS_OK;
}

ps_err_e ps_lgetfpregs(struct ps_prochandle *ph, lwpid_t lwpid,
		       prfpregset_t *prfpregset)
{
	/* NOP */
	return PS_OK;
}

ps_err_e ps_lsetfpregs(struct ps_prochandle *ph, lwpid_t lwpid,
		       const prfpregset_t *prfpregset)
{
	/* NOP */
	return PS_OK;
}

pid_t ps_getpid(struct ps_prochandle *ph)
{
	return ph->di->pid;
}

ps_err_e ps_pglobal_lookup(struct ps_prochandle *ph, const char *object_name,
			   const char *sym_name, psaddr_t *sym_addr)
{
	unsigned long addr;

	if (sym_address(ph->di, sym_name, &addr) != 0)
		return PS_NOSYM;

	*sym_addr = (psaddr_t)addr;

	return PS_OK;
}

static int find_pthreads_cb(const td_thrhandle_t *th, void *cb_data)
{
	/* Get thread info, in order to access (and dump) data that
	   gdb/libthread_db needs.  */
	td_thrinfo_t thinfo;
	td_thr_get_info (th, &thinfo);

	return TD_OK;
}

static void get_pthread_list(struct dump_info *di)
{
	struct ps_prochandle ph = { di };
	td_thragent_t *ta;
	td_err_e err;

	err = td_ta_new(&ph, &ta);
	if (err == TD_OK) {
		err = td_ta_thr_iter(ta, find_pthreads_cb, NULL,
				     TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
				     TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);

		td_ta_delete(ta);
	}

	if (err == TD_NOLIBTHREAD) {
		info("target does not appear to be multi-threaded");
	} else if (err != TD_OK) {
		info("WARNING: libthread_db not found, using fallback");
		get_pthread_list_fallback(di);
	}
}

static unsigned long get_atval(ElfW(auxv_t) *elf_auxv, ElfW(Addr) type)
{
	int i;

	for (i = 0; elf_auxv[i].a_type != AT_NULL; i++) {
		if (elf_auxv[i].a_type == type)
			return elf_auxv[i].a_un.a_val;
	}

	return 0;
}

/*
 * Get value from DT_DEBUG element from /proc/PID/auxv.
 * (This is the r_debug structure.)
 */
static int init_from_auxv(struct dump_info *di, ElfW(auxv_t) *auxv,
			  unsigned long *debug_ptr)
{
	ElfW(Addr) relocation;
	ElfW(Addr) phdr_addr;
	ElfW(Addr) dyn_addr;
	unsigned long addr;
	uint32_t val32;
	int found = 0;
	int max_ph;
	int i;

	max_ph = get_atval(auxv, AT_PHNUM);
	phdr_addr = get_atval(auxv, AT_PHDR);

	if (!phdr_addr)
		return 1;

	for (i = 0; i < max_ph; i++) {
		/* val32 = (ElfW(Phdr))phdr_addr[i].p_type */
		addr = phdr_addr + (sizeof(ElfW(Phdr)) * i) +
		       offsetof(ElfW(Phdr), p_type);
		read_remote(di, addr, &val32, sizeof(val32));

		if (val32 == PT_NULL) {
			break;

		} else if (val32 == PT_PHDR) {
			addr = phdr_addr + (sizeof(ElfW(Phdr)) * i) +
			       offsetof(ElfW(Phdr), p_vaddr);
			read_remote(di, addr, &relocation, sizeof(relocation));
			found |= 0x1;

			relocation = phdr_addr - relocation;

		} else if (val32 == PT_DYNAMIC) {
			/* dyn_addr = (ElfW(Phdr))phdr_addr[i].p_vaddr */
			addr = phdr_addr + (sizeof(ElfW(Phdr)) * i) +
			       offsetof(ElfW(Phdr), p_vaddr);
			read_remote(di, addr, &dyn_addr, sizeof(dyn_addr));
			found |= 0x2;
		}
	}

	/* dump auxv phdrs to core */
	if (di->cfg->prog_config.dump_auxv_so_list) {
		dump_vma(di, phdr_addr, sizeof(ElfW(Phdr)) * i, 0,
			 "auxv phdrs");
	}

	if (found != 0x3)
		return 3;

	if (!dyn_addr)
		return 4;

	/* Store symbol information in executable.
	 * This is necessary for sym_address() to work. */
	store_sym_data(di, di->exe, relocation);

	dyn_addr = dyn_addr + relocation;

	for (i = 0; ; i++) {
		/* val32 = (ElfW(Dyn))dyn_addr[i].d_tag */
		addr = dyn_addr + (sizeof(ElfW(Dyn)) * i)
		       + offsetof(ElfW(Dyn), d_tag);
		read_remote(di, addr, &val32, sizeof(val32));

		if (val32 == DT_NULL) {
			break;

		} else if (val32 == DT_DEBUG) {
			/* debug_ptr = (ElfW(Dyn))dyn_addr[i].d_un.d_ptr */
			addr = dyn_addr + (sizeof(ElfW(Dyn)) * i) +
			       offsetof(ElfW(Dyn), d_un.d_ptr);
			read_remote(di, addr, debug_ptr, sizeof(*debug_ptr));

			/* found it! */
			found |= 0x4;
		}
	}

	/* dump auxv dyns to core */
	if (di->cfg->prog_config.dump_auxv_so_list)
		dump_vma(di, dyn_addr, sizeof(ElfW(Dyn)) * i, 0, "auxv dyns");

	if (found != 0x7)
		return 5;

	return 0;
}

/* Get the shared libary list via /proc/pid/auxv */
static int get_so_list(struct dump_info *di)
{
	unsigned long ptr = 0;
	char *filename;
	void *buf;
	int ret;
	int fd;

	if (asprintf(&filename, "/proc/%d/auxv", di->pid) == -1)
		return -1;

	fd = open(filename, O_RDONLY);
	free(filename);
	if (fd < 0)
		return -1;

	buf = calloc(1, PAGESZ);
	if (!buf) {
		close(fd);
		return -1;
	}

	ret = read(fd, buf, PAGESZ);

	close(fd);

	if (ret < 0)
		return -1;

	/* get value from DT_DEBUG element from /proc/PID/auxv
	 * (this is the r_debug structure) */
	if (init_from_auxv(di, buf, &ptr) != 0)
		return -1;

	free(buf);

	if (!ptr)
		return 0;

	/* dump r_debug structure */
	if (di->cfg->prog_config.dump_auxv_so_list)
		dump_vma(di, ptr, sizeof(struct r_debug), 0, "auxv r_debug");

	/* get pointer to first link_map */
	read_remote(di, ptr + offsetof(struct r_debug, r_map), &ptr,
		    sizeof(ptr));

	while (ptr) {
		unsigned long addr = 0;
		char *l_name = NULL;

		/* dump link_map */
		if (di->cfg->prog_config.dump_auxv_so_list) {
			dump_vma(di, ptr, sizeof(struct link_map), 0,
				 "auxv link_map");
		}

		/* get pointer to link_map name */
		read_remote(di, ptr + offsetof(struct link_map, l_name),
			    &addr, sizeof(addr));

		if (alloc_remote_string(di, addr, &l_name) == 0) {
			/* dump link_map name */
			if (di->cfg->prog_config.dump_auxv_so_list) {
				dump_vma(di, addr, strlen(l_name) + 1, 0,
					 "auxv link_map name (%s)", l_name);
			}

			/* store so data since we are here */
			if (l_name[0] != 0) {
				/* get pointer to base address */
				read_remote(di,
					ptr + offsetof(struct link_map,
						       l_addr),
					&addr, sizeof(addr));

				store_sym_data(di, l_name, addr);
			}

			free(l_name);
		}

		/* get pointer to next link_map */
		read_remote(di, ptr + offsetof(struct link_map, l_next),
			    &ptr, sizeof(ptr));
	}

	return 0;
}

static void dump_sym_buffer(struct dump_info *di, unsigned long ptr,
			    size_t len, const char *symname)
{
	unsigned long addr;

	dump_vma(di, ptr, sizeof(void *), 0, "data pointer (%s)", symname);
	if (read_remote(di, ptr, &addr, sizeof(addr)) == 0)
		dump_vma(di, addr, len, 0, "data (%s)", symname);
}

static void get_interesting_buffers(struct dump_info *di)
{
	struct interesting_buffer *buf = di->cfg->prog_config.buffers;
	unsigned long addr;
	int ret;

	while (buf) {
		ret = sym_address(di, buf->symname, &addr);
		if (ret) {
			info("WARNING: unable to find recept symbol: %s",
			     buf->symname);
			buf = buf->next;
			continue;
		} else {
			info("found symbol: %s @ 0x%lx", buf->symname, addr);
		}

		if (buf->follow_ptr) {
			dump_sym_buffer(di, addr, buf->data_len, buf->symname);
		} else {
			dump_vma(di, addr, buf->data_len, 0, "data (%s)",
				 buf->symname);
		}

		buf = buf->next;
	}
}

/*
 * Copies various files from /proc/pid/.
 */
static void write_proc_info(struct dump_info *di)
{
	copy_proc_files(di, 0, "cmdline", 0);
	copy_proc_files(di, 0, "environ", 0);
	copy_proc_files(di, 1, "io", 0);
	copy_proc_files(di, 1, "maps", 0);
	copy_proc_files(di, 1, "smaps", 0);
	copy_proc_files(di, 1, "stack", 0);
	copy_proc_files(di, 1, "stat", 0);
	copy_proc_files(di, 1, "statm", 0);
	copy_proc_files(di, 1, "cwd", 1);
	copy_proc_files(di, 1, "fd", 1);
}

#ifdef SUPPORT_LIBELF_MODIFY
static int add_dumplist_section(struct dump_info *di)
{
	size_t core_size = di->core_file_size;
	off64_t dump_offset;

	if (add_dump_list(di->elf_fd, &core_size, di->core_file,
			  &dump_offset) != 0) {
		return -1;
	}

	di->core_file_size = core_size;

	add_core_data(di, dump_offset, core_size - dump_offset,
		      di->elf_fd, dump_offset);

	return 0;
}
#endif

static void do_dump(struct dump_info *di, int argc, char *argv[])
{
	int ret;

	ret = init_di(di, argc, argv);
	if (ret == 1) {
		info("unable to create new dump info instance");
		goto out;
	} else if (ret == 2) {
		info("no watch for comm=%s exe=%s", di->comm, di->exe);
		goto out;
	}

	if (init_log(di) != 0)
		info("failed to init debug log");

	if (di->core_fd >= 0) {
		/* dump up until first vma */
		if (init_src_core(di, STDIN_FILENO) != 0)
			fatal("unable to initialize core");

		/* log the vma info we found */
		log_vmas(di);
	} else {
		dump_maps(di, 1);
	}

	/* copy intersting /proc data (if configured) */
	if (di->cfg->prog_config.write_proc_info)
		write_proc_info(di);

	/* Get shared object list. This is necessary for sym_address() to work.
	 * This function will also dump the auxv data (if configured). */
	get_so_list(di);

	/* dump all stacks (if configured) */
	if (di->cfg->prog_config.stack.dump_stacks)
		dump_stacks(di);

	/* dump the pthread list (if configured) */
	if (di->cfg->prog_config.dump_pthread_list)
		get_pthread_list(di);

	/* dump the robust mutex list (if configured) */
	if (di->cfg->prog_config.dump_robust_mutex_list)
		get_robust_mutex_list(di);

	if (di->core_fd >= 0) {
		/* dump any maps configured for dumping */
		if (di->cfg->prog_config.maps.nglobs > 0)
			dump_maps(di, 0);

		/* dump any buffers configured for dumping */
		get_interesting_buffers(di);
	}

	/* dump registered application data */
	dyn_dump(di);

	if (di->core_fd >= 0) {
#ifdef SUPPORT_LIBELF_MODIFY
		/* add a new elf section containing the dump list */
		if (add_dumplist_section(di) != 0)
			info("WARNING: failed to add dump list");
#else
		info("WARNING: libelf too old to support dump list");
#endif

		/* dump data to compressed tar'd sparse core file */
		if (dump_compressed_tar(di) != 0) {
			/* dump data to compressed core file */
			if (dump_compressed_core(di) != 0) {
				/* dump data to sparse core file */
				dump_mini_core(di);
			}
		}

		/* dump a fat core (if configured) */
		if (di->cfg->prog_config.dump_fat_core)
			dump_fat_core(di);
	} else {
		info("dump path: %s", di->dst_dir);
	}
out:
	/* we are done, cleanup */
	cleanup_di(di);
}

static long ptrace_tree(enum __ptrace_request request, pid_t pid)
{
	char buf[64];
	struct dirent *de;
	DIR *d;

	snprintf(buf, sizeof(buf), "/proc/%d/task", pid);
	d = opendir(buf);
	if (!d)
		return -1;

	while (1) {
		de = readdir(d);
		if (!de)
			break;
		if (de->d_name[0] == '.')
			continue;
		ptrace(request, atoi(de->d_name), NULL, NULL);
	}

	closedir(d);

	return 0;
}

static int do_lock(pthread_mutex_t *m)
{
	int ret;

	ret = pthread_mutex_lock(m);
	if (ret != 0) {
		if (ret != EOWNERDEAD)
			return -1;

		pthread_mutex_consistent(m);
	}

	return 0;
}

static void alloc_registered_pids(pid_t core_pid, pid_t **pids, int *n)
{
	struct mcd_shm_item *si;
	struct mcd_shm_head *sh;
	size_t map_size;
	struct stat sb;
	int fd;
	int i;

	*pids = NULL;
	*n = 0;

	fd = shm_open(MCD_SHM_PATH, O_RDWR, S_IRUSR|S_IWUSR);
	if (fd < 0)
		return;

	if (fstat(fd, &sb) != 0)
		return;

	map_size = sb.st_size;
	if (map_size < sizeof(*sh))
		return;

	sh = mmap(NULL, map_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (sh == MAP_FAILED)
		return;

	if (do_lock(&sh->m) != 0)
		goto out;

	if (map_size < sizeof(*sh) + (sh->count * sizeof(*si)))
		goto out2;

	*pids = malloc(sizeof(pid_t) * sh->count);
	if (!*pids)
		goto out2;

	si = (struct mcd_shm_item *)(sh + 1);

	for (i = 0; i < sh->count; i++) {
		if (si->pid == core_pid) {
			/* force-unregister core task */
			si->pid = 0;
			si->data = 0;
			sh->count--;
			info("unregistered core task: %d\n", core_pid);
		}
		(*pids)[i] = si->pid;
		si++;
	}
	*n = sh->count;
out2:
	pthread_mutex_unlock(&sh->m);
out:
	munmap(sh, map_size);
}

static int do_all_dumps(struct dump_info *di, int argc, char *argv[])
{
	struct config *cfg;
	const char *recept;
	bool live_dumper;
	char *comm_base;
	pid_t core_pid;
	long timestamp;
	char *comm;
	char *exe;
	char *p;
	char *ext_argv[10] = {
		argv[0],
		argv[1],
		argv[2],
		argv[3],
		"0",
		argv[5],
		argv[6],
		"",
		argv[8],
		NULL
	};

	if (argc == 8) {
		cfg = init_config("/etc/minicoredumper/"
				  "minicoredumper.cfg.json");
	} else if (argc == 9) {
		info("using custom minicoredumper cfg: %s", argv[8]);
		cfg = init_config(argv[8]);
	} else {
		fatal("wrong arg count, check /proc/sys/kernel/core_pattern");
	}

	if (!cfg)
		fatal("unable to init config");

	check_config(cfg);

	core_pid = strtol(argv[1], &p, 10);
	if (*p != 0)
		return 1;

	timestamp = strtol(argv[5], &p, 10);
	if (*p != 0)
		return 1;

	comm = alloc_comm(argv[7], core_pid);
	if (!comm)
		return 1;

	if (core_pid == 0)
		exe = strdup("");
	else
		exe = alloc_exe(core_pid);
	if (!exe)
		return 1;

	comm_base = comm;
	while (1) {
		p = strchr(comm_base, '/');
		if (!p)
			break;
		comm_base = p + 1;
	}

	di->dst_dir = alloc_dst_dir(timestamp, cfg->base_dir,
				    comm_base, core_pid);
	if (!di->dst_dir)
		return 1;

	recept = get_prog_recept(cfg, comm, exe);
	if (!recept)
		return 1;

	if (init_prog_config(cfg, recept) != 0)
		return 1;

	live_dumper = cfg->prog_config.live_dumper;

	free_config(cfg);
	free(comm);
	free(exe);

	if (live_dumper) {
		char pidstr[16];
		pid_t *pids;
		int n;
		int i;

		alloc_registered_pids(core_pid, &pids, &n);

		/* pause all registered tasks */
		for (i = 0; i < n; i++) {
			if (pids[i] == 0)
				continue;
			if (pids[i] == core_pid)
				continue;
			if (ptrace_tree(PTRACE_SEIZE, pids[i]) != 0)
				pids[i] = 0;
			else
				ptrace_tree(PTRACE_INTERRUPT, pids[i]);
		}

		/* dump all registered tasks */
		for (i = 0; i < n; i++) {
			if (pids[i] == 0)
				continue;
			if (pids[i] == core_pid)
				continue;
			snprintf(pidstr, sizeof(pidstr), "%d", pids[i]);
			ext_argv[1] = &pidstr[0];
			do_dump(di, argc, ext_argv);
		}

		/* resume all registered tasks */
		for (i = 0; i < n; i++) {
			if (pids[i] == 0)
				continue;
			if (pids[i] == core_pid)
				continue;
			ptrace_tree(PTRACE_DETACH, pids[i]);
		}

		if (pids)
			free(pids);
	}

	if (core_pid != 0) {
		/* dump crashed task */
		do_dump(di, argc, argv);
	}

	free(di->dst_dir);

	return 0;
}

int main(int argc, char *argv[])
{
	struct dump_info di;

	memset(&di, 0, sizeof(di));

	/* set global di pointer, used only by info()/fatal() */
	global_di = &di;

	/* determine page size */
	PAGESZ = sysconf(_SC_PAGESIZE);

	/* create all files only owner-readable */
	umask(077);

	/* open syslog */
	openlog("minicoredumper", LOG_NDELAY, LOG_SYSLOG);

	/* prevent memory paging to swap */
	mlockall(MCL_CURRENT | MCL_FUTURE);

	if (argc == 8 || argc == 9) {
		info("argv: %s %s %s %s %s %s %s %s", argv[0], argv[1],
		     argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
	} else {
		fatal("wrong amount of command line parameters");
	}

	do_all_dumps(&di, argc, argv);

	closelog();
	munlockall();

	return 0;
}
