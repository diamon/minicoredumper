/*
 * Copyright (c) 2016 Ericsson AB
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
#include <dirent.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "common.h"

/* global data used for graceful shutdown on signal */
static int running = 1;
static int close_fd;
struct mcd_regdata close_data;
struct sockaddr_un close_addr;
struct msghdr close_msgh;
struct iovec close_iov;

static int get_msg(int fd, pid_t *pid, struct mcd_regdata *rd)
{
	struct mcd_regdata data;
	struct sockaddr_un addr;
	struct cmsghdr *cmhp;
	struct ucred *ucredp;
	struct msghdr msgh;
	struct iovec iov;
	ssize_t n;
	union {
		struct cmsghdr cmh;
		char control[CMSG_SPACE(sizeof(struct ucred))];
	} control_un;

	memset(&data, 0, sizeof(data));
	iov.iov_base = &data;
	iov.iov_len = sizeof(data);

	memset(&addr, 0, sizeof(addr));

	control_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
	control_un.cmh.cmsg_level = SOL_SOCKET;
	control_un.cmh.cmsg_type = SCM_CREDENTIALS;

	msgh.msg_control = control_un.control;
	msgh.msg_controllen = sizeof(control_un.control);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_name = (void *)&addr;
	msgh.msg_namelen = sizeof(addr);

	do {
		n = recvmsg(fd, &msgh, 0);
		if (n < 0 && errno == EINTR)
			continue;
		else if (n != sizeof(data))
			return -1;
		else
			break;
	} while (1);

	cmhp = CMSG_FIRSTHDR(&msgh);
	if (!cmhp || cmhp->cmsg_len != CMSG_LEN(sizeof(struct ucred)))
		return -1;
	if (cmhp->cmsg_level != SOL_SOCKET)
		return -1;
	if (cmhp->cmsg_type != SCM_CREDENTIALS)
		return -1;

	ucredp = (struct ucred *)CMSG_DATA(cmhp);

	*pid = ucredp->pid;
	memcpy(rd, &data, sizeof(*rd));

	switch (data.req) {
	case MCD_REGISTER:
	case MCD_UNREGISTER:
		/* only these requests require a response */
		break;
	default:
		goto out;
	}

	data.data = ~data.data;

	msgh.msg_control = NULL;
	msgh.msg_controllen = 0;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_name = (void *)&addr;
	msgh.msg_namelen = sizeof(addr);

	do {
		n = sendmsg(fd, &msgh, 0);
		if (n < 0 && errno == EINTR)
			continue;
		else if (n != sizeof(data))
			return -1;
		else
			break;
	} while (1);
out:
	return 0;
}

static int setup_close_socket(void)
{
	int ret;

	memset(&close_addr, 0, sizeof(close_addr));
	close_addr.sun_family = AF_UNIX;
	snprintf(close_addr.sun_path, sizeof(close_addr.sun_path), "x%s.%d",
		 MCD_SOCK_PATH, getpid());
	close_addr.sun_path[0] = 0;

	close_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (close_fd < 0)
		return -1;

	ret = bind(close_fd, (struct sockaddr *)&close_addr,
		   sizeof(close_addr));
	if (ret != 0)
		return -1;

	memset(&close_data, 0, sizeof(close_data));
	close_data.req = MCD_SHUTDOWN;

	close_iov.iov_base = &close_data;
	close_iov.iov_len = sizeof(close_data);

	memset(&close_addr, 0, sizeof(close_addr));
	close_addr.sun_family = AF_UNIX;
	snprintf(close_addr.sun_path, sizeof(close_addr.sun_path), "x%s",
		 MCD_SOCK_PATH);
	close_addr.sun_path[0] = 0;

	memset(&close_msgh, 0, sizeof(close_msgh));
	close_msgh.msg_iov = &close_iov;
	close_msgh.msg_iovlen = 1;
	close_msgh.msg_name = (void *)&close_addr;
	close_msgh.msg_namelen = sizeof(close_addr);

	return 0;
}

static int setup_socket(void)
{
	struct sockaddr_un addr;
	int err = -1;
	int optval;
	int ret;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "x%s", MCD_SOCK_PATH);
	addr.sun_path[0] = 0;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return err;

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0)
		goto out;

	optval = 1;
	ret = setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval));
	if (ret != 0)
		goto out;

	return fd;
out:
	close(fd);
	return err;
}

static int setup_shm(void)
{
	pthread_mutexattr_t attr;
	struct mcd_shm_head *sh;
	struct stat sb;
	int fd;

	fd = shm_open(MCD_SHM_PATH, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "error: failed to setup shared memory\n");
		return -1;
	}

	if (ftruncate(fd, sizeof(struct mcd_shm_head)) != 0) {
		close(fd);
		shm_unlink(MCD_SHM_PATH);
		return -1;
	}

	if (fstat(fd, &sb) != 0) {
		close(fd);
		shm_unlink(MCD_SHM_PATH);
		return -1;
	}

	sh = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (sh == MAP_FAILED) {
		close(fd);
		shm_unlink(MCD_SHM_PATH);
		return -1;
	}

	sh->head_size = sizeof(struct mcd_shm_head);
	sh->item_size = sizeof(struct mcd_shm_item);
	sh->count = 0;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);
	pthread_mutexattr_setrobust_np(&attr, PTHREAD_MUTEX_ROBUST_NP);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&sh->m, &attr);

	munmap(sh, sb.st_size);

	return fd;
}

static void *do_mmap(int fd, size_t map_size)
{
	struct mcd_shm_head *sh;

	/*
	 * If the head and item structures should ever grow, these
	 * size checks could be modified to support reading the
	 * smaller sizes of previous versions.
	 */

	if (map_size < sizeof(struct mcd_shm_head))
		return NULL;

	sh = mmap(NULL, map_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (sh == MAP_FAILED)
		return NULL;

	if (sh->head_size != sizeof(struct mcd_shm_head))
		goto out_err;

	if (sh->item_size != sizeof(struct mcd_shm_item))
		goto out_err;

	if (map_size < sh->head_size + (sh->count * sh->item_size))
		goto out_err;

	return sh;
out_err:
	munmap(sh, map_size);
	return NULL;
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

static void add_client(int fd, pid_t pid, uint32_t data)
{
	struct mcd_shm_item *empty_si = NULL;
	struct mcd_shm_head *sh_new;
	struct mcd_shm_head *sh;
	struct mcd_shm_item *si;
	size_t map_size_new;
	size_t map_size;
	struct stat sb;
	int i;

	if (fstat(fd, &sb) != 0)
		return;
	map_size = sb.st_size;

	sh = do_mmap(fd, map_size);
	if (!sh)
		return;

	si = ((void *)sh) + sh->head_size;

	if (do_lock(&sh->m) != 0)
		goto out;

	for (i = 0; i < sh->count; i++) {
		if (si->pid == pid) {
			/* found existing entry */

			if (si->data != data)
				si->data = data;
			pthread_mutex_unlock(&sh->m);
			goto out;

		} else if (si->pid == 0) {
			empty_si = si;
		}

		si = ((void *)si) + sh->item_size;
	}

	/* check if there is extra space already allocated */
	if (!empty_si &&
	    map_size >= sh->head_size + ((sh->count + 1) * sh->item_size)) {
		empty_si = si;
	}

	if (empty_si) {
		/* add to empty slot */

		empty_si->pid = pid;
		empty_si->data = data;
		sh->count++;
		pthread_mutex_unlock(&sh->m);
		goto out;
	}

	pthread_mutex_unlock(&sh->m);

	/* expand shm to add new slot */

	if (ftruncate(fd, map_size + sh->item_size) != 0)
		goto out;

	if (fstat(fd, &sb) != 0)
		goto out;
	map_size_new = sb.st_size;

	sh_new = mremap(sh, map_size, map_size_new, MREMAP_MAYMOVE);
	if (sh_new == MAP_FAILED)
		goto out;
	sh = sh_new;
	map_size = map_size_new;

	si = ((void *)sh) + sh->head_size + (sh->count * sh->item_size);

	if (do_lock(&sh->m) != 0)
		goto out;
	si->pid = pid;
	si->data = data;
	sh->count++;
	pthread_mutex_unlock(&sh->m);
out:
	munmap(sh, map_size);
}

static void remove_client(int fd, pid_t pid, uint32_t data)
{
	struct mcd_shm_head *sh;
	struct mcd_shm_item *si;
	size_t map_size;
	struct stat sb;
	int i;

	if (fstat(fd, &sb) != 0)
		return;
	map_size = sb.st_size;

	sh = do_mmap(fd, map_size);
	if (!sh)
		return;

	si = ((void *)sh) + sh->head_size;

	if (do_lock(&sh->m) != 0)
		goto out;

	for (i = 0; i < sh->count; i++) {
		if (si->pid == pid) {
			/* found entry */

			si->pid = 0;
			si->data = 0;
			sh->count--;
			pthread_mutex_unlock(&sh->m);

			goto out;
		}

		si = ((void *)si) + sh->item_size;
	}

	pthread_mutex_unlock(&sh->m);
out:
	munmap(sh, map_size);
}

static void do_stop(int sig)
{
	running = 0;
	sendmsg(close_fd, &close_msgh, 0);
}

int main(void)
{
	struct mcd_regdata rd;
	int sock_fd;
	int shm_fd;
	pid_t pid;
	int ret;

	sock_fd = setup_socket();
	if (sock_fd < 0)
		return 1;

	if (setup_close_socket() != 0) {
		close(sock_fd);
		return 1;
	}

	shm_fd = setup_shm();
	if (shm_fd < 0) {
		close(sock_fd);
		close(close_fd);
		return 1;
	}

	/* hook signals for graceful shutdowns */
	signal(SIGHUP, do_stop);
	signal(SIGINT, do_stop);
	signal(SIGTERM, do_stop);

	while (running) {
		ret = get_msg(sock_fd, &pid, &rd);

		if (ret != 0 || pid == 0)
			continue;

		switch (rd.req) {
		case MCD_REGISTER:
			add_client(shm_fd, pid, rd.data);
			break;
		case MCD_UNREGISTER:
			remove_client(shm_fd, pid, rd.data);
			break;
		case MCD_SHUTDOWN:
			/* if this is valid, running is now 0 */
			break;
		}
	}

	close(sock_fd);
	close(close_fd);
	close(shm_fd);
	shm_unlink(MCD_SHM_PATH);

	return 0;
}
