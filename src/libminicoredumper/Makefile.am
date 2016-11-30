##
## Copyright (c) 2015-2016 Ericsson AB
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
## 1. Redistributions of source code must retain the above copyright notice,
##    this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright notice,
##    this list of conditions and the following disclaimer in the documentation
##    and/or other materials provided with the distribution.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
## AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
## LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
## CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
## SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
## INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
## CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
## ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
## POSSIBILITY OF SUCH DAMAGE.
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
libminicoredumper_la_LDFLAGS = -Wl,--exclude-libs,ALL
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
libminicoredumper_la_LDFLAGS += -version-info 2:0:0
