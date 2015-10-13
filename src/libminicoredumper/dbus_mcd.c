/*
 * Copyright (C) 2012-2015 Ericsson AB
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

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#include <dbus/dbus-glib.h>

#include "common.h"
#include "dbus_mcd.h"
#include "compat_mcd.h"

extern int dump_data_walk(char *path, int dump_scope);

struct localinfo {
	char uuid[37];
	int pid;
};

static struct localinfo ai;

/**
 *   Print out an error message and optionally quit (if fatal is TRUE)
 */
static void handle_error(const char *msg, const char *reason, gboolean fatal)
{
	g_printerr("APP: ERROR: %s (%s)\n", msg, reason);
	if (fatal)
		exit(EXIT_FAILURE);
}

/**
 *   Main signal handler
 */
static void app_signal_hangler(DBusGProxy * proxy, const char *signalName,
			       gpointer userData)
{
	gchar *dump_path = NULL;
	GError *error = NULL;
	gint dump_scope;
	gint v = 0;

	/* ignored */
	(void)userData;

	g_print("APP: Received signal (%s)\n", signalName);

	/* XXX: why is this done? "v" is never used */
	org_ericsson_mcd_getcrashstate(proxy, &v, &error);
	g_clear_error(&error);

	if (!strcmp(signalName, SIGNAL_DUMP)) {
		org_ericsson_mcd_getdumpinfo(proxy, &dump_path, &dump_scope,
					    &error);

		if (error) {
			handle_error("Can't get dump path", error->message,
				     FALSE);
			g_clear_error(&error);
		} else {
			g_print("APP: Gonna walk hook list with dump path "
				"(%s)\n", dump_path);

			dump_data_walk(dump_path, dump_scope);

			org_ericsson_mcd_setdumpstate(proxy, ai.uuid, &error);
			g_clear_error(&error);
		}

		if (dump_path)
			g_free(dump_path);
	}
}

/**
 * atexit function: register from dbus daemon
 */
void end()
{
}

static GMainLoop *mainloop;

/**
 *  Main function for dbus handling
 */
void *start_dbus_gloop(void *arg)
{
	DBusGConnection *conn;
	GError *error = NULL;
	DBusGProxy *proxy;
	uuid_t uuid;
	size_t s;

	const gchar *signalNames[] = {
		SIGNAL_DUMP,
		SIGNAL_REGISTER
	};

	/* unused */
	(void)arg;

	g_type_init_compat();

	uuid_generate_time_safe(uuid);

	uuid_unparse_lower(uuid, ai.uuid);
	ai.pid = getpid();

	g_print("APP: PID: %d\n", ai.pid);

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		handle_error("Failed to create the mainloop", "Unknown (OOM?)",
			     TRUE);
	}

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error)
		handle_error("Couldn't connect to the Session bus",
			     error->message, TRUE);
	g_clear_error(&error);

	proxy = dbus_g_proxy_new_for_name(conn, VALUE_SERVICE_NAME,
					  VALUE_SERVICE_OBJECT_PATH,
					  VALUE_SERVICE_INTERFACE);
	if (!proxy)
		handle_error("Couldn't create the proxy object",
			     "Unknown(dbus_g_proxy_new_for_name)", TRUE);

	for (s = 0; s < sizeof(signalNames) / sizeof(signalNames[0]); s++) {
		dbus_g_proxy_add_signal(proxy, signalNames[s], G_TYPE_STRING,
					G_TYPE_INVALID);
	}

	dbus_g_proxy_connect_signal(proxy, SIGNAL_DUMP,
				    G_CALLBACK(app_signal_hangler), NULL, NULL);

	dbus_g_proxy_connect_signal(proxy, SIGNAL_REGISTER,
				    G_CALLBACK(app_signal_hangler), NULL, NULL);

	org_ericsson_mcd_register(proxy, ai.uuid, ai.pid, &error);
	if (error)
		handle_error("Failed to Register", error->message, FALSE);
	else
		g_print("APP: Application registered with %s \n", ai.uuid);
	g_clear_error(&error);

	atexit(end);

	g_main_loop_run(mainloop);

	org_ericsson_mcd_unregister(proxy, ai.uuid, ai.pid, &error);
	if (error)
		handle_error("Failed to Unregister", error->message, FALSE);
	else
		g_print("APP: Application unregistered with %s \n", ai.uuid);

	return NULL;
}

void stop_dbus_gloop(void)
{
	g_main_loop_quit(mainloop);
}
