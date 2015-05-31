##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

bin_PROGRAMS = minicoredumper_dbusd

dist_man_MANS = minicoredumper_dbusd.1

dbus_mcd.h: $(top_srcdir)/src/dbus/interface.xml
	dbus-binding-tool --prefix=value_object --mode=glib-server $< > $@

daemon.c: dbus_mcd.h

minicoredumper_dbusd_SOURCES = daemon.c

dbus_CFLAGS += -I$(top_srcdir)/src/dbus

minicoredumper_dbusd_LDADD = @dbus_LIBS@
minicoredumper_dbusd_CFLAGS = -g -Wall -std=c99 -D_GNU_SOURCE $(MCD_WERROR) \
			      $(dbus_CFLAGS)
