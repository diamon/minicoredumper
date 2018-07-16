##
## Copyright (c) 2016-2018 Linutronix GmbH. All rights reserved.
##
## SPDX-License-Identifier: BSD-2-Clause
##

sbin_PROGRAMS = minicoredumper_regd

man_MANS = minicoredumper_regd.1
EXTRA_DIST = $(man_MANS)

minicoredumper_regd_SOURCES = daemon.c
minicoredumper_regd_CPPFLAGS = $(MCD_CPPFLAGS) \
			       -I$(top_srcdir)/src/common
minicoredumper_regd_CFLAGS = $(MCD_CFLAGS)
minicoredumper_regd_LDFLAGS = -lpthread -lrt
