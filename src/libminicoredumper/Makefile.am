##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = minicoredumper.pc

dist_man_MANS = libminicoredumper.7

EXTRA_DIST = minicoredumper.pc.in minicoredumper-uninstalled.pc.in

lib_LTLIBRARIES = libminicoredumper.la

libminicoredumper_la_SOURCES = mcd.c dump_data_private.h
libminicoredumper_la_CPPFLAGS = $(MCD_CPPFLAGS) \
				-I$(top_srcdir)/src/api \
				-I$(top_srcdir)/src/common \
				-DG_LOG_DOMAIN=\"minicoredumper\"
libminicoredumper_la_CFLAGS = $(MCD_CFLAGS)
libminicoredumper_la_LIBADD = ../common/libmcdident.la

include_HEADERS = $(top_srcdir)/src/api/minicoredumper.h

# 1) If the library source code has changed at all since the last update, then
#    increment revision ("c:r:a" becomes "c:r+1:a").
# 2) If any interfaces have been added, removed, or changed since the last
#    update, increment current, and set revision to 0.
# 3) If any interfaces have been added since the last public release,
#    then increment age.
# 4) If any interfaces have been removed or changed since the last public
#    release, then set age to 0.
libminicoredumper_la_LDFLAGS = -version-info 2:0:0
