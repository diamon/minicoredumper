/*
 * Copyright (C) 2012-2016 Linutronix GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <printf.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "dump_data_private.h"
#include "common.h"
#include "minicoredumper.h"

/* public symbols used by minicoredumper */
struct mcd_dump_data *mcd_dump_data_head;
int mcd_dump_data_version = DUMP_DATA_VERSION;

static pthread_mutex_t dump_mutex = PTHREAD_MUTEX_INITIALIZER;
static int registered;

static int mcd_request(int req)
{
	uint32_t dval = 0x55555555;
	struct sockaddr_un addr;
	struct mcd_regdata data;
	struct msghdr msgh;
	struct iovec iov;
	int err = -1;
	ssize_t n;
	int ret;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "x%s.%d",
		 MCD_SOCK_PATH, getpid());
	addr.sun_path[0] = 0;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return err;

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0)
		goto out;

	memset(&data, 0, sizeof(data));
	data.req = req;
	data.data = dval;

	iov.iov_base = &data;
	iov.iov_len = sizeof(data);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "x%s", MCD_SOCK_PATH);
	addr.sun_path[0] = 0;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_name = (void *)&addr;
	msgh.msg_namelen = sizeof(addr);

	do {
		n = sendmsg(fd, &msgh, 0);
		if (n < 0 && errno == EINTR)
			continue;
		else if (n != sizeof(data))
			goto out;
		else
			break;
	} while (1);

	do {
		n = recvmsg(fd, &msgh, 0);
		if (n < 0 && errno == EINTR)
			continue;
		else if (n != sizeof(data))
			goto out;
		else
			break;
	} while (1);

	if (~data.data != dval)
		goto out;

	err = 0;
out:
	close(fd);
	return err;
}

static void handle_register(void)
{
	if (registered)
		return;

	if (mcd_request(MCD_REGISTER) != 0)
		return;

	registered = 1;
}

static void handle_unregister(void)
{
	if (!registered)
		return;

	if (mcd_request(MCD_UNREGISTER) != 0)
		return;

	registered = 0;
}

static void free_dump_data(struct mcd_dump_data *dd)
{
	if (dd->ident)
		free(dd->ident);
	if (dd->es)
		free(dd->es);
	if (dd->fmt)
		free(dd->fmt);
	free(dd);
}

static int append_dump_data(struct mcd_dump_data *dump_data)
{
	struct mcd_dump_data *iter;
	int err = -1;

	dump_data->next = NULL;

	pthread_mutex_lock(&dump_mutex);

	if (!mcd_dump_data_head) {
		/* first item in list */
		mcd_dump_data_head = dump_data;
		err = 0;
		goto out;
	}

	/* find last item (while checking for ident dups) */
	for (iter = mcd_dump_data_head; iter->next; iter = iter->next) {
		/* text dumps are allowed to have duplicate idents */
		if (dump_data->type == MCD_TEXT && iter->type == MCD_TEXT)
			continue;

		/* NULL idents are allowed to be duplicates */
		if (!dump_data->ident || !iter->ident)
			continue;

		/* compare idents */
		if (strcmp(dump_data->ident, iter->ident) != 0)
			continue;

		/* illegal duplicate found! */
		goto out;
	}

	/* add to end of list */
	iter->next = dump_data;
	err = 0;

out:
	if (err == 0)
		handle_register();

	pthread_mutex_unlock(&dump_mutex);

	return err;
}

static size_t get_type_length(int type, void *data)
{
	switch (type) {
	case PA_INT:
		return sizeof(int);
	case PA_CHAR:
		return sizeof(char);
	case PA_STRING:
		return (strlen((char *)data) + 1);
	case PA_POINTER:
		return sizeof(void *);
	case PA_FLOAT:
		return sizeof(float);
	case PA_DOUBLE:
		return sizeof(double);
	case (PA_INT | PA_FLAG_SHORT):
		return sizeof(short);
	case (PA_INT | PA_FLAG_LONG):
		return sizeof(long);
	case (PA_INT | PA_FLAG_LONG_LONG):
		return sizeof(long long);
	case (PA_DOUBLE | PA_FLAG_LONG_DOUBLE):
		return sizeof(long double);
	default:
		break;
	}

	return 0;
}

int mcd_vdump_data_register_text(const char *ident, unsigned long dump_scope,
				 mcd_dump_data_t *save_ptr,
				 const char *fmt, va_list ap)
{
	struct dump_data_elem *es = NULL;
	struct mcd_dump_data *dd = NULL;
	int *argtypes = NULL;
	int err = ENOMEM;
	int maxcnt;
	void *ptr;
	int n = 0;
	int i;

	if (!ident || !fmt) {
		err = EINVAL;
		goto out_err;
	}

	if (invalid_ident(ident)) {
		err = EINVAL;
		goto out_err;
	}

	/* max count is if fmt has _only_ directives in it */
	maxcnt = strlen(fmt);

	if (maxcnt > 0) {
		argtypes = (int *)calloc(maxcnt, sizeof(int));
		if (!argtypes)
			goto out_err;

		n = parse_printf_format(fmt, maxcnt, argtypes);
	}

	dd = calloc(1, sizeof(*dd));
	if (!dd)
		goto out_err;

	if (n > 0) {
		es = calloc(n, sizeof(*es));
		if (!es)
			goto out_err;
	}

	for (i = 0; i < n; i++) {
		ptr = va_arg(ap, void *);
		es[i].flags = MCD_DATA_PTR_DIRECT | MCD_LENGTH_DIRECT;
		es[i].data_ptr = ptr;
		es[i].fmt_type = argtypes[i];
		es[i].u.length = get_type_length(argtypes[i], ptr);
	}

	dd->type = MCD_TEXT;
	dd->dump_scope = dump_scope;
	dd->es = es;
	dd->fmt = strdup(fmt);
	dd->es_n = n;
	dd->ident = strdup(ident);

	/* make sure strdup() succeeded */
	if (!dd->ident || !dd->fmt)
		goto out_err;

	if (append_dump_data(dd) != 0) {
		err = EEXIST;
		goto out_err;
	}

	if (save_ptr)
		*save_ptr = dd;

	free(argtypes);

	return 0;
out_err:
	if (argtypes)
		free(argtypes);

	if (dd)
		free_dump_data(dd);

	if (save_ptr)
		*save_ptr = NULL;

	return err;
}

int mcd_dump_data_register_text(const char *ident, unsigned long dump_scope,
				mcd_dump_data_t *save_ptr,
				const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = mcd_vdump_data_register_text(ident, dump_scope, save_ptr,
					   fmt, ap);
	va_end(ap);

	return err;
}

int mcd_dump_data_register_bin(const char *ident, unsigned long dump_scope,
			       mcd_dump_data_t *save_ptr, void *data_ptr,
			       size_t data_size,
			       enum mcd_dump_data_flags ptr_flags)
{
	struct dump_data_elem *es = NULL;
	struct mcd_dump_data *dd = NULL;
	int err = ENOMEM;

	if (!data_ptr || data_size == 0) {
		err = EINVAL;
		goto out_err;
	}

	if (invalid_ident(ident)) {
		err = EINVAL;
		goto out_err;
	}

	dd = calloc(1, sizeof(*dd));
	if (!dd)
		goto out_err;

	es = calloc(1, sizeof(*es));
	if (!es)
		goto out_err;

	es->data_ptr = data_ptr;
	es->flags = ptr_flags;
	if ((ptr_flags & MCD_LENGTH_INDIRECT) == MCD_LENGTH_INDIRECT)
		es->u.length_ptr = (size_t *)data_size;
	else
		es->u.length = data_size;

	dd->type = MCD_BIN;
	dd->dump_scope = dump_scope;
	dd->es = es;
	dd->es_n = 1;
	/* ident is optional for binary dumps */
	if (ident) {
		dd->ident = strdup(ident);
		if (!dd->ident)
			goto out_err;
	}

	if (append_dump_data(dd) != 0) {
		err = EEXIST;
		goto out_err;
	}

	if (save_ptr)
		*save_ptr = dd;

	return 0;
out_err:
	if (dd)
		free_dump_data(dd);

	if (save_ptr)
		*save_ptr = NULL;

	return err;
}

int mcd_dump_data_unregister(mcd_dump_data_t dd)
{
	struct mcd_dump_data *prev = NULL;
	struct mcd_dump_data *iter;
	int err = 0;

	pthread_mutex_lock(&dump_mutex);

	for (iter = mcd_dump_data_head; iter; iter = iter->next) {
		if (iter != dd) {
			prev = iter;
			continue;
		}

		if (!prev)
			mcd_dump_data_head = iter->next;
		else
			prev->next = iter->next;

		break;
	}

	if (iter)
		free_dump_data(iter);
	else
		err = ENOKEY;

	if (!mcd_dump_data_head)
		handle_unregister();

	pthread_mutex_unlock(&dump_mutex);

	return err;
}
