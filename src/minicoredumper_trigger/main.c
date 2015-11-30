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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "dump_data_private.h"

#ifdef USE_DBUS
#include <glib.h>
#include <dbus/dbus-glib.h>

/* Pull the common symbolic defines. */
#include "common.h"

/* Pull in the client stubs that were generated with
   dbus-binding-tool */
#include "dbus_mcd.h"

/* Pull in compatibility layer functions. */
#include "compat_mcd.h"

/* Define the time out in ms */
#define TIME_OUT 5000

static GMainLoop *mainloop;

/**
 * Print out an error message and optionally quit (if fatal is TRUE)
 */
static void handleError(const char *msg, const char *reason, gboolean fatal)
{
	g_printerr("handleError: ERROR: %s (%s)\n", msg, reason);
	if (fatal)
		exit(EXIT_FAILURE);
}

/**
 * Is just waiting from the daemon that all dumps have been done.
 * if not, time out will exit the minicoredumper application.
 */
static void valueChangedSignalHandler(DBusGProxy *proxy, const char *valueName,
				      gpointer userData)
{
	if (!strcmp(valueName, SIGNAL_DUMP_MCD_DONE)) {
		printf("All registered minicoredumper apps have dumped!\n");
		g_main_loop_quit(mainloop);
	}
}

static gboolean timerCallback(DBusGProxy *remoteobj)
{
	printf("Not all registered minicoredumper apps were able to dump - Timeout!\n");
	g_main_loop_quit(mainloop);
	return FALSE;
}

static void do_trigger(const char *dump_path, int dump_scope)
{
	DBusGProxy *remoteValue;
	DBusGConnection *bus;
	GError *error = NULL;

	g_type_init_compat();

	mainloop = g_main_loop_new(NULL, FALSE);

	if (!mainloop) {
		handleError("Failed to create the mainloop", "Unknown (OOM?)",
			    TRUE);
	}

	bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error)
		printf("D-bus error %s\n", error->message);

	remoteValue = dbus_g_proxy_new_for_name(bus,
				VALUE_SERVICE_NAME, /* name */
				VALUE_SERVICE_OBJECT_PATH, /* obj path */
				VALUE_SERVICE_INTERFACE /* interface */ );

	if (!remoteValue) {
		handleError("Couldn't create the proxy object",
			    "Unknown(dbus_g_proxy_new_for_name)", TRUE);
	}

	{
		unsigned int i;
		const gchar *signalNames[] = { SIGNAL_DUMP_MCD_DONE };

		for (i = 0; i < sizeof(signalNames) / sizeof(signalNames[0]);
		     i++) {
			dbus_g_proxy_add_signal(remoteValue, signalNames[i],
						G_TYPE_STRING, G_TYPE_INVALID);
		}
	}

	dbus_g_proxy_connect_signal(remoteValue, SIGNAL_DUMP_MCD_DONE,
				    G_CALLBACK (valueChangedSignalHandler),
				    NULL, NULL);

	printf("Timeout for registered applications %dms\n", TIME_OUT);
	g_timeout_add(TIME_OUT, (GSourceFunc)timerCallback, remoteValue);

	printf("Signal crash state to DUMP to registered applications\n");
	org_ericsson_mcd_setcrashstate(remoteValue, 0, STATE_MCD_USER_DUMP,
				       dump_scope, dump_path, &error);
	if (error) {
		handleError("Failed to set crash state", error->message,
			    FALSE);
		printf("Failed to set crash state, Message: %s\n",
		       error->message);
	}

	g_main_loop_run(mainloop);
}
#else
static void do_trigger(const char *dump_path, int dump_scope)
{
	const char *monitor_fname;
	char *tmp_path;
	FILE *f;
	int fd;

	monitor_fname = getenv(DUMP_DATA_MONITOR_ENV);
	if (!monitor_fname || monitor_fname[0] != '/') {
		fprintf(stderr,
			"error: %s not defined, not triggering live dump\n",
			DUMP_DATA_MONITOR_ENV);
		return;
	}

	if (asprintf(&tmp_path, "%s/monitor.XXXXXX", dump_path) == -1) {
		fprintf(stderr, "error: failed to allocate temp string\n");
		return;
	}

	fd = mkstemp(tmp_path);
	if (fd < 0) {
		fprintf(stderr, "error: failed to create temp file\n");
		goto out;
	}

	f = fdopen(fd, "w");
	if (!f) {
		fprintf(stderr, "error: failed to reopen temp file\n");
		close(fd);
		goto out;
	}

	fprintf(f, "version=%d\n", DUMP_DATA_VERSION);
	fprintf(f, "scope=%d\n", dump_scope);
	fprintf(f, "path=%s\n", dump_path);

	fclose(f);

	chmod(tmp_path, 0644);

	if (rename(tmp_path, monitor_fname) != 0) {
		fprintf(stderr, "error: failed to rename %s to %s\n", tmp_path,
		     monitor_fname);
		unlink(tmp_path);
		goto out;
	}

	f = fopen(monitor_fname, "a");
	if (!f) {
		fprintf(stderr, "error: failed to append to %s\n",
			 monitor_fname);
		goto out;
	}

	/* inotify trigger */
	fclose(f);

	printf("Trigger success!\n");
out:
	free(tmp_path);
}
#endif

static int usage(const char *argv0, const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	fprintf(stderr, "usage: %s <absolute-dump-path> <dump-scope>\n",
		argv0);
	return 1;
}

/**
 *  Thread with dbus init and registers a Timeout at the end
 */
int main(int argc, char *argv[])
{
	char *tmp_path;

	if (argc != 3)
		return usage(argv[0], "wrong number of arguments");

	if (argv[1][0] != '/')
		return usage(argv[0], "dump path not absolute");

	printf("Triggering minicoredumper live dumper...\n");

	mkdir(argv[1], 01777);
	chmod(argv[1], 01777);

	if (asprintf(&tmp_path, "%s/proc", argv[1]) != -1) {
		mkdir(tmp_path, 01777);
		chmod(tmp_path, 01777);
		free(tmp_path);
	}

	do_trigger(argv[1], atoi(argv[2]));

	return 0;
}
