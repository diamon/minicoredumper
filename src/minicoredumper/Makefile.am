##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

bin_PROGRAMS = minicoredumper

dist_man_MANS = minicoredumper.cfg.json.5 minicoredumper.recept.json.5 \
		minicoredumper.1


dbus_mcd.h: $(top_srcdir)/src/dbus/interface.xml
	dbus-binding-tool --prefix=value_object --mode=glib-client $< > $@

dbus_mcd.c: dbus_mcd.h

minicoredumper_SOURCES = corestripper.c corestripper.h \
			 prog_config.c prog_config.h

if USE_DBUS
minicoredumper_SOURCES += dbus_mcd.c
dbus_CFLAGS += -DUSE_DBUS -I$(top_srcdir)/src/dbus
endif

minicoredumper_LDADD = $(top_builddir)/lib/libjson.a -lelf -lthread_db \
		       @dbus_LIBS@
minicoredumper_CFLAGS = -g -Wall -std=c99 -D_GNU_SOURCE $(MCD_WERROR) \
			-D_LARGEFILE64_SOURCE $(dbus_CFLAGS) \
			-I$(top_srcdir)/lib \
			-I$(top_srcdir)/src/api \
			-I$(top_srcdir)/src/libminicoredumper
