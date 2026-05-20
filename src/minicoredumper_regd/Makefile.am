##
## Copyright (c) 2016-2026 Linutronix GmbH. All rights reserved.
##
## SPDX-License-Identifier: BSD-2-Clause
##

sbin_PROGRAMS = minicoredumper_regd

man_MANS = minicoredumper_regd.8
EXTRA_DIST = $(man_MANS)

minicoredumper_regd_SOURCES = daemon.c
minicoredumper_regd_CPPFLAGS = $(MCD_CPPFLAGS) \
			       -I$(top_srcdir)/src/common
minicoredumper_regd_LDFLAGS = -lpthread -lrt
