##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

bin_PROGRAMS = minicoredumper_demo

minicoredumper_demo_SOURCES = main.c
minicoredumper_demo_CFLAGS = -g -Wall -std=c99 -D_GNU_SOURCE $(MCD_WERROR) \
			     -I$(top_srcdir)/src/api
minicoredumper_demo_LDADD = $(top_builddir)/src/libminicoredumper/libminicoredumper.la
