##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

bin_PROGRAMS = minicoredumper_trigger

dist_man_MANS = minicoredumper_trigger.1


dbus_mcd.h: $(top_srcdir)/src/dbus/interface.xml
	dbus-binding-tool --prefix=value_object --mode=glib-client $< > $@

main.c: dbus_mcd.h

minicoredumper_trigger_SOURCES = main.c

if USE_DBUS
dbus_CFLAGS += -DUSE_DBUS -I$(top_srcdir)/src/dbus
endif

minicoredumper_trigger_LDADD = @dbus_LIBS@
minicoredumper_trigger_CFLAGS = -g -Wall -std=c99 -D_GNU_SOURCE $(MCD_WERROR) \
			-D_LARGEFILE64_SOURCE $(dbus_CFLAGS) \
			-I$(top_srcdir)/lib \
			-I$(top_srcdir)/src/api \
			-I$(top_srcdir)/src/compat \
			-I$(top_srcdir)/src/libminicoredumper
