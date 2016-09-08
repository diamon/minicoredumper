##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

bin_PROGRAMS = minicoredumper

dist_man_MANS = minicoredumper.cfg.json.5 minicoredumper.recept.json.5 \
		minicoredumper.1

minicoredumper_SOURCES = corestripper.c corestripper.h \
			 prog_config.c prog_config.h \
			 ../common/common.c ../common/elf_dumplist.c

minicoredumper_LDADD = $(top_builddir)/lib/libjson.a \
		       -lthread_db -lrt -lpthread \
		       $(libelf_LIBS)
minicoredumper_CFLAGS = -g -Wall -std=c99 -D_GNU_SOURCE $(MCD_WERROR) \
			-D_LARGEFILE64_SOURCE \
			-I$(top_srcdir)/lib \
			-I$(top_srcdir)/src/api \
			-I$(top_srcdir)/src/common \
			-I$(top_srcdir)/src/libminicoredumper \
			$(libelf_CFLAGS)
