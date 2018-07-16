##
## Copyright (c) 2015-2018 Linutronix GmbH. All rights reserved.
##
## SPDX-License-Identifier: BSD-2-Clause
##

sbin_PROGRAMS = minicoredumper

man_MANS = minicoredumper.cfg.json.5 minicoredumper.recept.json.5 \
	   minicoredumper.1
EXTRA_DIST = $(man_MANS)

minicoredumper_SOURCES = corestripper.c corestripper.h \
			 prog_config.c prog_config.h
minicoredumper_CPPFLAGS = $(MCD_CPPFLAGS) \
			  -I$(top_srcdir)/lib \
			  -I$(top_srcdir)/src/api \
			  -I$(top_srcdir)/src/common \
			  -I$(top_srcdir)/src/libminicoredumper \
			  -DMCD_CONF_PATH=\"$(MCD_CONF_PATH)\" \
			  $(libelf_CFLAGS) $(libjsonc_CFLAGS)
minicoredumper_CFLAGS = $(MCD_CFLAGS)
minicoredumper_LDADD = ../common/libmcdelf.a \
		       ../common/libmcdident.a \
		       $(libelf_LIBS) $(libjsonc_LIBS) \
		       -lthread_db -lpthread -lrt
