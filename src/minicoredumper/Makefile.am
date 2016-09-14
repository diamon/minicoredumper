##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

sbin_PROGRAMS = minicoredumper

dist_man_MANS = minicoredumper.cfg.json.5 minicoredumper.recept.json.5 \
		minicoredumper.1

minicoredumper_SOURCES = corestripper.c corestripper.h \
			 prog_config.c prog_config.h
minicoredumper_CPPFLAGS = $(MCD_CPPFLAGS) \
			  -I$(top_srcdir)/lib \
			  -I$(top_srcdir)/src/api \
			  -I$(top_srcdir)/src/common \
			  -I$(top_srcdir)/src/libminicoredumper \
			  $(libelf_CFLAGS)
minicoredumper_CFLAGS = $(MCD_CFLAGS)
minicoredumper_LDADD = ../../lib/libjson.a \
		       ../common/libmcdelf.a \
		       ../common/libmcdident.a \
		       -lthread_db -lpthread -lrt \
		       $(libelf_LIBS)
