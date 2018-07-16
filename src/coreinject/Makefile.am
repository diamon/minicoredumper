##
## Copyright (c) 2015-2018 Linutronix GmbH. All rights reserved.
##
## SPDX-License-Identifier: BSD-2-Clause
##

bin_PROGRAMS = coreinject

man_MANS = coreinject.1
EXTRA_DIST = $(man_MANS)

coreinject_SOURCES = main.c
coreinject_CPPFLAGS = $(MCD_CPPFLAGS) \
		      -I$(top_srcdir)/src/common \
		      $(libelf_CFLAGS)
coreinject_LDADD = ../common/libmcdelf.a $(libelf_LIBS)
