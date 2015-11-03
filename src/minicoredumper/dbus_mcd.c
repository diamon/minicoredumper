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

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <stddef.h>

/* Pull the common symbolic defines. */
#include "common.h"

/* Pull in the client stubs that were generated with
   dbus-binding-tool */
#include "prog_config.h"
#include "corestripper.h"
#include "dbus_mcd.h"

/* Pull in compatibility layer functions. */
#include "compat_mcd.h"

/* Define the time out in ms */
#define TIME_OUT 500

typedef struct {
	int state;
	int pid;
	int dump_scope;
	char *path;
	char *app_name;
} stateObject;

stateObject localstate;

void info(const char *fmt, ...);

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
		info("Corestripper all dbus registered apps have dumped!");
		g_main_loop_quit(mainloop);
	}
}

static gboolean timerCallback(DBusGProxy *remoteobj)
{
	info("Corestripper not all applications were able to dump - Timeout!");
	g_main_loop_quit(mainloop);
	return FALSE;
}

static void setup_public_subdir(const char *base, const char *subdir)
{
	size_t size;
	char *name;

	size = strlen(base) + 1 + strlen(subdir) + 1;

	name = malloc(size);
	if (!name)
		return;

	snprintf(name, size, "%s/%s", base, subdir);

	mkdir(name, 01777);
	chmod(name, 01777);

	free(name);
}

/**
 *  Thread with dbus init and registers a Timeout at the end
 */
int start_dbus_gloop(void *_di)
{
	struct dump_info *di = (struct dump_info *)_di;
	DBusGConnection *bus;
	DBusGProxy *remoteValue;
	GError *error = NULL;

	info("Corestripper live dumper ... ");

	chmod(di->dst_dir, 01777);

	setup_public_subdir(di->dst_dir, "proc");

	localstate.state = STATE_MCD_CRASHED;
	localstate.path = di->dst_dir;
	localstate.app_name = di->comm;
	localstate.pid = di->pid;
	localstate.dump_scope = di->cfg->prog_config.dump_scope;

	info("dump path  : %s", localstate.path);
	info("app name   : %s", localstate.app_name);
	info("pid        : %i", localstate.pid);
	info("dump scope : %i", localstate.dump_scope);

	g_type_init_compat();

	mainloop = g_main_loop_new(NULL, FALSE);

	if (!mainloop) {
		handleError("Failed to create the mainloop", "Unknown (OOM?)",
			    TRUE);
	}

	bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error)
		info("D-bus error %s ", error->message);

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

	dbus_g_proxy_connect_signal(remoteValue, SIGNAL_DUMP_APP_DONE,
				    G_CALLBACK(valueChangedSignalHandler),
				    NULL, NULL);

	info("Timeout for registered applications %dms", TIME_OUT);
	g_timeout_add(TIME_OUT, (GSourceFunc)timerCallback, remoteValue);

	info("Signal crash state to DUMP to registered applications");
	org_ericsson_mcd_setcrashstate(remoteValue, localstate.pid,
				       STATE_MCD_CRASHED,
				       localstate.dump_scope, localstate.path,
				       &error);
	if (error) {
		handleError("Failed to set crash state", error->message,
			    FALSE);
		info("Failed to set crash state, Message: %s",error->message);
	}

	g_main_loop_run(mainloop);

	return 0;
}
