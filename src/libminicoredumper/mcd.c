/*
 * Copyright (C) 2012-2016 Ericsson AB
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
#include <sys/inotify.h>

#include "dump_data_private.h"
#include "common.h"
#include "minicoredumper.h"

static pthread_mutex_t dump_mutex = PTHREAD_MUTEX_INITIALIZER;

struct mcd_dump_data *mcd_dump_data_head;
int mcd_dump_data_version = DUMP_DATA_VERSION;

static void dump_proc(char *path, int pid)
{
	char *tmp_path;
	size_t size;

	size = strlen(path) + 64;

	tmp_path = malloc(size);
	if (!tmp_path)
		return;

	snprintf(tmp_path, size, "%s/proc/%i", path, pid);

	if (mkdir(tmp_path, 0700) == -1)
		goto out;

	snprintf(tmp_path, size, "%s/proc/%i/cmdline", path, pid);
	copy_file(tmp_path, "/proc/self/cmdline");

	snprintf(tmp_path, size, "%s/proc/%i/environ", path, pid);
	copy_file(tmp_path, "/proc/self/environ");
out:
	free(tmp_path);
}

int dump_data_walk(char *path, unsigned long dump_scope)
{
	struct mcd_dump_data *iter;
	char *tmp_path;
	size_t length;
	char *fname;
	int err = 0;
	void *data;
	FILE *ft;
	int len;
	int pid;

	pid = getpid();

	dump_proc(path, pid);

	if (asprintf(&tmp_path, "%s/dumps/%i", path, pid) == -1)
		return errno;

	if (mkdir(tmp_path, 0700) == -1) {
		free(tmp_path);
		return errno;
	}

	pthread_mutex_lock(&dump_mutex);

	for (iter = mcd_dump_data_head; iter; iter = iter->next) {

		/* ignore core-only data */
		if (!iter->ident)
			continue;

		/* ignore data flagged for not dumping */
		if ((iter->es->flags & MCD_DATA_NODUMP))
			continue;

		/* ignore data if beyond scope */
		if (iter->dump_scope > dump_scope)
			continue;

		/* verify ident */
		if (invalid_ident(iter->ident))
			continue;

		len = strlen(tmp_path) + strlen("/") + strlen(iter->ident) + 1;

		/* allocate, open, and free filename */
		fname = malloc(len);
		if (!fname) {
			err = -1;
			continue;
		}
		snprintf(fname, len, "%s/%s", tmp_path, iter->ident);
		ft = fopen(fname, "a");
		free(fname);

		if (!ft) {
			err = -1;
			continue;
		}

		fchmod(fileno(ft), S_IRUSR|S_IWUSR);

		/* handle binary dump */
		if (iter->type == MCD_BIN) {
			if ((iter->es->flags & MCD_DATA_PTR_INDIRECT)) {
				fwrite(iter->es->data_ptr, 1,
				       sizeof(unsigned long), ft);

				data = *(void **)iter->es->data_ptr;
			} else {
				data = iter->es->data_ptr;
			}

			if ((iter->es->flags & MCD_LENGTH_INDIRECT))
				length = *(iter->es->u.length_ptr);
			else
				length = iter->es->u.length;

			/* write out data */
			fwrite(data, 1, length, ft);

			fclose(ft);

			continue;
		}

		/* handle text dump */
		dump_data_file_text(iter, ft, NULL);

		fclose(ft);
	}

	pthread_mutex_unlock(&dump_mutex);

	free(tmp_path);

	return err;
}

/* monitor thread */
static pthread_t monitor_thread_id;

#ifdef USE_DBUS
extern void *start_dbus_gloop(void *);
extern void stop_dbus_gloop(void);

int mcd_dump_data_dbus_start(void)
{
	pthread_create(&monitor_thread_id, NULL, &start_dbus_gloop, NULL);

	return 0;
}

void mcd_dump_data_dbus_stop(void)
{
	stop_dbus_gloop();
	pthread_join(monitor_thread_id, NULL);
}
#else
static int monitor_thread_pipe[2] = { -1, -1 };
static const char *monitor_fname;
static int monitor_fd = -1;

static void do_dump(const char *trigger_file)
{
	size_t buf_size = PATH_MAX + 10;
	unsigned long dump_scope;
	char *buf;
	FILE *f;
	char *p;

	buf = malloc(buf_size);
	if (!buf)
		return;

	f = fopen(monitor_fname, "r");
	if (!f)
		goto out;

	if (!fgets(buf, buf_size, f))
		goto out;
	if (strncmp(buf, "version=", strlen("version=")) != 0)
		goto out;
	if (atoi(buf + strlen("version=")) != DUMP_DATA_VERSION)
		goto out;
	if (!fgets(buf, buf_size, f))
		goto out;
	if (strncmp(buf, "scope=", strlen("scope=")) != 0)
		goto out;
	dump_scope = strtoul(buf + strlen("scope="), NULL, 10);
	if (!fgets(buf, buf_size, f))
		goto out;
	if (strncmp(buf, "path=", strlen("path=")) != 0)
		goto out;

	/* strip newline */
	p = strchr(buf, '\n');
	if (p)
		*p = 0;

	dump_data_walk(buf + strlen("path="), dump_scope);
out:
	if (f)
		fclose(f);
	free(buf);
}

static void *monitor_thread(void *arg)
{
	size_t ib_size = sizeof(struct inotify_event) + NAME_MAX + 1;
	const char *trigger_file = arg;
	struct inotify_event *iev;
	struct pollfd fds[2];
	char *ib;

	ib = malloc(ib_size);
	if (!ib)
		return NULL;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = monitor_thread_pipe[0];
	fds[0].events = POLLIN;
	fds[1].fd = monitor_fd;
	fds[1].events = POLLIN;

	while (1) {
		fds[0].revents = 0;
		fds[1].revents = 0;

		if (poll(fds, 2, -1) <= 0) {
			if (errno != -EINTR)
				break;
		}

		/* inotify event */
		if (fds[1].revents == POLLIN) {
			memset(ib, 0, ib_size);
			if (read(monitor_fd, ib, ib_size) >
			    sizeof(struct inotify_event)) {
				iev = (struct inotify_event *)ib;

				if ((iev->mask & IN_CLOSE_WRITE) &&
				    strcmp(iev->name, trigger_file) == 0) {
					/* dump trigger */
					do_dump(trigger_file);
				}
			}
		}

		/* pipe event */
		if (fds[0].revents == POLLIN) {
			char c;
			if (read(monitor_thread_pipe[0], &c, 1) == 1) {
				if (c == 'q') {
					/* quit request */
					break;
				}
			}
		}
	}

	free(ib);

	return NULL;
}

/* setup inotify method */
int mcd_dump_data_dbus_start(void)
{
	char *monitor_dname;
	char *basename;

	if (monitor_fd >= 0)
		return -1;

	monitor_fname = getenv(DUMP_DATA_MONITOR_ENV);
	if (!monitor_fname || monitor_fname[0] != '/')
		return -1;

	monitor_dname = strdup(monitor_fname);
	if (!monitor_dname)
		return -1;

	basename = strrchr(monitor_dname, '/');
	*basename = 0;
	basename++;

	monitor_fd = inotify_init();
	if (monitor_fd < 0)
		goto err_out1;

	if (inotify_add_watch(monitor_fd, monitor_dname, IN_CLOSE_WRITE) < 0)
		goto err_out2;

	if (pipe(monitor_thread_pipe) != 0)
		goto err_out2;

	if (pthread_create(&monitor_thread_id, NULL,
			   &monitor_thread, basename) != 0) {
		goto err_out3;
	}

	return 0;

err_out3:
	close(monitor_thread_pipe[0]);
	monitor_thread_pipe[0] = -1;
	close(monitor_thread_pipe[1]);
	monitor_thread_pipe[1] = -1;
err_out2:
	close(monitor_fd);
	monitor_fd = -1;
err_out1:
	free(monitor_dname);

	return -1;
}

void mcd_dump_data_dbus_stop(void)
{
	if (monitor_fd < 0)
		return;

	while (write(monitor_thread_pipe[1], "q", 1) != 1) {
		/* only loop if interrupted by signal */
		if (errno != EINTR)
			break;
	}
	pthread_join(monitor_thread_id, NULL);

	close(monitor_thread_pipe[0]);
	monitor_thread_pipe[0] = -1;
	close(monitor_thread_pipe[1]);
	monitor_thread_pipe[1] = -1;

	close(monitor_fd);
	monitor_fd = -1;
}
#endif /* USE_DBUS */

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
			       enum mcd_dump_data_flags ptr_flags,
			       size_t data_size)
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

	pthread_mutex_unlock(&dump_mutex);

	return err;
}
