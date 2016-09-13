##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

bin_PROGRAMS = minicoredumper_demo

minicoredumper_demo_SOURCES = main.c
minicoredumper_demo_CPPFLAGS = $(MCD_CPPFLAGS) \
			       -I$(top_srcdir)/src/api
minicoredumper_demo_CFLAGS = $(MCD_CFLAGS)
minicoredumper_demo_LDADD = ../libminicoredumper/libminicoredumper.la
