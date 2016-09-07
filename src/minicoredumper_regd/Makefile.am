##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

bin_PROGRAMS = minicoredumper_regd

dist_man_MANS = minicoredumper_regd.1

minicoredumper_regd_SOURCES = daemon.c

minicoredumper_regd_LDFLAGS = -lpthread -lrt
minicoredumper_regd_CFLAGS = -g -Wall -std=c99 -D_GNU_SOURCE $(MCD_WERROR) \
			     -I$(top_srcdir)/src/common
