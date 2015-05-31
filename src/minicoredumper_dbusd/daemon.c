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
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"

#define APPNAME "minicoredumper_dbusd"

typedef enum {
	E_SIGNAL_REGISTER,
	E_SIGNAL_DUMP,
	E_SIGNAL_DUMP_APP_DONE,
	E_SIGNAL_DUMP_MCD_DONE,
	E_SIGNAL_COUNT
} ValueSignalNumber;

typedef enum {
	E_STATE_D_RUN,
	E_STATE_D_CRASH,
	E_STATE_D_DUMP,
	E_STATE_D_DUMP_DONE
} States;


typedef struct {
	int pid;
	char *uuid;
} appInfo;

typedef struct {
	gchar *dump_path;
	GObject parent;
} CrashObject;

typedef struct {
	GObjectClass parent;
	States state;
	gint dump_scope;
	gchar *dump_path;
	gint apps_dump_state;
	gint dump_state;
	gint mcd_state;
	GSList *registered_apps;
	GSList *dump_apps;
	guint signals[E_SIGNAL_COUNT];
} CrashObjectClass;

GType value_object_get_type(void);

#define VALUE_TYPE_OBJECT (value_object_get_type())

#define VALUE_IS_OBJECT(object) \
	(G_TYPE_CHECK_INSTANCE_TYPE ((object), \
	 VALUE_TYPE_OBJECT))
#define VALUE_IS_OBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
	 VALUE_TYPE_OBJECT))

#define VALUE_OBJECT(object) \
	(G_TYPE_CHECK_INSTANCE_CAST ((object), \
	 VALUE_TYPE_OBJECT, CrashObject))

#define VALUE_OBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST ((klass), \
	 VALUE_TYPE_OBJECT, CrashObjectClass))

#define VALUE_OBJECT_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS ((obj), \
	 VALUE_TYPE_OBJECT, CrashObjectClass))

G_DEFINE_TYPE(CrashObject, value_object, G_TYPE_OBJECT)



gboolean value_object_getcrashstate(CrashObject *obj, gint *mcd_state,
				GError **error);
gboolean value_object_setcrashstate(CrashObject *obj, gint pid, gint state,
				    gint dump_scope, gchar *dump_path,
				    GError **error);

gboolean value_object_getdumpstate(CrashObject *obj, gint *dump_state,
				   GError **error);
gboolean value_object_setdumpstate(CrashObject *obj, gchar *app_uuid,
				   GError **error);

gboolean value_object_getdumpinfo(CrashObject *obj, gchar **dump_path,
				  gint *dump_scope, GError **error);

gboolean value_object_register(CrashObject *obj, gchar *app_uuid,
			       gint pid, GError **error);
gboolean value_object_unregister(CrashObject *obj, gchar *app_uuid,
				 gint pid, GError **error);

#include "dbus_mcd.h"

#ifdef NO_DAEMON
#define dbg(fmtstr, args...) \
	(g_print(APPNAME ":%s: " fmtstr "\n", __func__, ##args))
#else
#define dbg(dummy...)
#endif

/**
 * Per object initializer
 */
static void value_object_init(CrashObject *obj)
{
	dbg("Called value_object_init");
	g_assert(obj != NULL);
}

/**
 * Per class initializer
 */
static void value_object_class_init(CrashObjectClass *klass)
{
	const gchar *signalNames[E_SIGNAL_COUNT] = {
		SIGNAL_REGISTER,
		SIGNAL_DUMP,
		SIGNAL_DUMP_APP_DONE,
		SIGNAL_DUMP_MCD_DONE
	};
	int i;

	g_assert(klass != NULL);


	for (i = 0; i < E_SIGNAL_COUNT; i++) {
		guint signalId;

		signalId = g_signal_new(signalNames[i],
					G_OBJECT_CLASS_TYPE(klass),
					G_SIGNAL_RUN_LAST,
					0, NULL, NULL,
					g_cclosure_marshal_VOID__STRING,
					G_TYPE_NONE, 1, G_TYPE_STRING);
		klass->signals[i] = signalId;
	}

	klass->state = STATE_D_RUN;
	klass->dump_scope = 0;
	klass->dump_path = "not init";
	klass->mcd_state = STATE_MCD_NOTDEF;
	klass->apps_dump_state = STATE_APPS_IDLE;
	klass->mcd_state = STATE_MCD_NOTDEF;

	dbus_g_object_type_install_info(VALUE_TYPE_OBJECT,
					&dbus_glib_value_object_object_info);

}

/**
 * Utility helper to emit a signal given with internal enumeration and
 * the passed string as the signal data.
 */
static void value_object_emitSignal(CrashObject *obj,
				    ValueSignalNumber num,
				    const gchar *message)
{
	CrashObjectClass *klass = VALUE_OBJECT_GET_CLASS(obj);

	g_assert((num < E_SIGNAL_COUNT) && (num == 0 || num > 0));
	dbg("Emitting signal id %d, with message '%s'", num, message);
	g_signal_emit(obj, klass->signals[num], 0, message);
}

gint cmp_uuid(gconstpointer item1, gconstpointer item2)
{
	return g_ascii_strcasecmp(((appInfo *)item1)->uuid, item2);
}

gint cmp_pid(gconstpointer item1, gconstpointer item2)
{
	dbg("cmp_pid: %ld %d ", (long)item2, ((appInfo *)item1)->pid);
	if (((appInfo *)item1)->pid == (long)item2)
		return 0;
	return 1;
}

/**
 *  function called by register applications to set
 *  their dumpstate to done !
 */
gboolean value_object_setdumpstate(CrashObject *obj, gchar *app_uuid,
				   GError **error)
{
	CrashObjectClass *klass;

	(void)error;

	dbg("Setdumpstate called by app with uuid=%s", app_uuid);
	g_assert(obj != NULL);

	klass = VALUE_OBJECT_GET_CLASS(obj);
	if (klass->mcd_state == STATE_MCD_CRASHED) {
		gint len;
		GSList *tlist;

		tlist = g_slist_find_custom(klass->dump_apps,
					    app_uuid,
					    (GCompareFunc)cmp_uuid);
		if (tlist != NULL) {
			dbg("Removed app_uuid: %s from dump list", app_uuid);
			klass->dump_apps = g_slist_remove(klass->dump_apps,
							  tlist);
		}

		/* check if all apps have dumped ! */
		len = g_slist_length(klass->dump_apps);
		if (len == 0) {
			value_object_emitSignal(obj, E_SIGNAL_DUMP_MCD_DONE,
						"dump_mcd_done");
			klass->state = STATE_D_RUN;
			klass->mcd_state = STATE_MCD_DUMP_DONE;
			dbg("All applications have dumped their hooks!");
		}
	}

	return TRUE;
}


/**
 *  function to unregister application at the dump daemon
 */
gboolean value_object_unregister(CrashObject *obj, gchar *app_uuid,
				 gint pid, GError **error)
{
	CrashObjectClass *klass;

	(void)pid;
	(void)error;

	dbg("Called unregister app_uud = %s", app_uuid);
	g_assert(obj != NULL);

	klass = VALUE_OBJECT_GET_CLASS(obj);
	if (klass->state == STATE_D_RUN) {
		GSList *tlist;

		tlist = g_slist_find_custom(klass->registered_apps, app_uuid,
					    (GCompareFunc)cmp_uuid);
		if (tlist == NULL) {
			dbg("Unregister app_uuid: %s", app_uuid);
			klass->registered_apps =
				g_slist_remove(klass->registered_apps, tlist);
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * Function that gets called when someone tries to register over the
 * D-Bus.
 */
gboolean value_object_register(CrashObject *obj, gchar *app_uuid,
			       gint pid, GError **error)
{
	CrashObjectClass *klass;
	appInfo *appElem;

	(void)error;

	dbg("Called register app_uuid = %s", app_uuid);
	g_assert(obj != NULL);

    	appElem = (appInfo *)malloc(sizeof(appInfo));
	appElem->pid = pid;
	if (asprintf(&appElem->uuid, "%s", app_uuid) == -1) {
		dbg("can't get mem!");
	}

	klass = VALUE_OBJECT_GET_CLASS(obj);
	if (klass->state == STATE_D_RUN) {
		if (g_slist_find_custom(klass->registered_apps, app_uuid,
					(GCompareFunc)cmp_uuid) == NULL) {
			dbg("Register app_uuid: %s", app_uuid);
			klass->registered_apps =
				g_slist_prepend(klass->registered_apps,
						appElem);
		}
	}

	return TRUE;
}

/*
 *
 * timer callback function, after dump signal to applications
 * a Timeout will be set state of daemon to RUN
 */
static gboolean timerCallback(DBusGProxy *obj)
{
	CrashObjectClass *klass = VALUE_OBJECT_GET_CLASS(obj);

	if (klass->state == STATE_D_DUMP) {
		g_printerr(APPNAME ": dump application time out, "
			   "daemon state will be set to STATE_D_RUN\n");
		CrashObjectClass *klass = VALUE_OBJECT_GET_CLASS(obj);
		klass->state = STATE_D_RUN;
		klass->mcd_state = STATE_MCD_DUMP_DONE;
	}

	return TRUE;
}



/**
 * minicoredumper sets crash state in the daemon to crashed
 */
gboolean value_object_setcrashstate(CrashObject *obj, gint pid, gint mcd_state,
				    gint dump_scope, gchar *dump_path,
				    GError **error)
{
	CrashObjectClass *klass;

	(void)error;

	dbg("Called from minicoredumper with crash scope %d, state %d, "
	    "path %s", dump_scope, mcd_state, dump_path);

	g_assert(obj != NULL);

	klass = VALUE_OBJECT_GET_CLASS(obj);
	if ((klass->state == STATE_D_RUN) &&
	    (mcd_state == STATE_MCD_CRASHED ||
	     mcd_state == STATE_MCD_DUMP_DONE)) {
		GSList *tlist;

		dbg("Emit Signal dump data =%d, state %d", dump_scope,
		    mcd_state);

		/* Get crashed application from registered and delete it */
		tlist = g_slist_find_custom(klass->registered_apps,
					    (gconstpointer)(long)pid,
					    (GCompareFunc)cmp_pid);
		if (tlist != NULL) {
			dbg("Remove crashed app with pid: %i removed from "
			    "application list", pid);
			klass->registered_apps =
				g_slist_remove(klass->registered_apps, tlist);
		}

		klass->dump_apps = g_slist_copy(klass->registered_apps);
		klass->dump_path = g_strdup(dump_path);
		klass->apps_dump_state = STATE_APPS_DUMP;
		klass->state = STATE_D_DUMP;
		klass->dump_scope = dump_scope;
		klass->mcd_state = STATE_MCD_CRASHED;
		value_object_emitSignal(obj, E_SIGNAL_DUMP, "dump"); /* XXX */
		g_timeout_add(1000, (GSourceFunc)timerCallback, obj);
	}

	return TRUE;
}


/**
 * Function that gets executed on "getdumpinfo".
 */
gboolean value_object_getdumpinfo(CrashObject *obj, gchar **dump_path,
				  gint *dump_scope, GError **error)
{
	CrashObjectClass *klass;

	(void)error;

	klass = VALUE_OBJECT_GET_CLASS(obj);
	dbg("Called getdumpinfo %p", &klass->dump_path);

	g_assert(obj != NULL);
	g_assert(dump_path != NULL);

	*dump_path = g_strdup(klass->dump_path);
	*dump_scope = klass->dump_scope;

	return TRUE;
}


/**
 * getcrashstate function
 */
gboolean value_object_getcrashstate(CrashObject *obj, gint *mcd_state,
				    GError **error)
{
	CrashObjectClass *klass;

	(void)error;

	g_assert(obj != NULL);
	g_assert(mcd_state != NULL);

	klass = VALUE_OBJECT_GET_CLASS(obj);
	*mcd_state = klass->mcd_state;

	return TRUE;
}

/**
 * Not used
 */
gboolean value_object_getdumpstate(CrashObject *obj, gint *dump_state,
				   GError **error)
{
	(void)error;

	g_assert(obj != NULL);
	g_assert(dump_state != NULL);

/*
	*valueOut = obj->dump_state;
*/
	return TRUE;
}

/**
 * Print out an error message and optionally quit (if fatal is TRUE)
 */
static void handleError(const char *msg, const char *reason, gboolean fatal)
{
	g_printerr(APPNAME ": ERROR: %s (%s)\n", msg, reason);
	if (fatal)
		exit(EXIT_FAILURE);
}

/**
 * the minicoredumper_dbusd code
 */
int main(void)
{
	DBusGConnection *bus = NULL;
	DBusGProxy *busProxy = NULL;
	CrashObject *valueObj = NULL;
	GMainLoop *mainloop = NULL;
	guint result;
	GError *error = NULL;

	g_type_init();

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		handleError("Couldn't create GMainLoop", "Unknown(OOM?)",
			    TRUE);
	}

	g_print(APPNAME ": main Connecting to the Session D-Bus.\n");
	bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error) {
		handleError("Couldn't connect to session bus", error->message,
			    TRUE);
	}

	g_print(APPNAME ": main Registering the well-known name (%s)\n",
		VALUE_SERVICE_NAME);

	busProxy = dbus_g_proxy_new_for_name(bus, DBUS_SERVICE_DBUS,
					     DBUS_PATH_DBUS,
					     DBUS_INTERFACE_DBUS);
	if (!busProxy) {
		handleError("Failed to get a proxy for D-Bus",
			    "Unknown(dbus_g_proxy_new_for_name)", TRUE);
	}

	if (!dbus_g_proxy_call(busProxy, "RequestName", &error, G_TYPE_STRING,
			       VALUE_SERVICE_NAME, G_TYPE_UINT, 0,
			       G_TYPE_INVALID, G_TYPE_UINT, &result,
			       G_TYPE_INVALID)) {
		handleError("D-Bus.RequestName RPC failed", error->message,
			    TRUE);
	}
	g_print(APPNAME ": main RequestName returned %d.\n",
		result);
	if (result != 1) {
		handleError("Failed to get the primary well-known name.",
			    "RequestName result != 1", TRUE);
	}

	g_print(APPNAME ": main Creating one Value object.\n");
	valueObj = g_object_new(VALUE_TYPE_OBJECT, NULL);
	if (valueObj == NULL) {
		handleError("Failed to create one Value instance.",
			    "Unknown(OOM?)", TRUE);
	}

	g_print(APPNAME ": main Registering it on the D-Bus.\n");
	dbus_g_connection_register_g_object(bus, VALUE_SERVICE_OBJECT_PATH,
					    G_OBJECT(valueObj));

	g_print(APPNAME ": main Ready to serve requests (daemonizing).\n");

#ifndef NO_DAEMON
	if (daemon(0, 0) != 0)
		g_error(APPNAME ": Failed to daemonize.\n");
#else
	g_print(APPNAME ": Not daemonizing "
		"(built with NO_DAEMON-build define)\n");
#endif

	g_main_loop_run(mainloop);
	return EXIT_FAILURE;
}
